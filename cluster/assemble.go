package cluster

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	as "github.com/snapcore/snapd/cluster/assemblestate"
)

type AssembleOpts struct {
	DiscoveryPeriod time.Duration
	Secret          string
	ErrorHandler    func(error)
	ListenIP        net.IP
	ListenPort      int
	Logger          *slog.Logger
	RDTOverride     string
}

type Discoverer = func(context.Context) ([]UntrustedPeer, error)

func Assemble(ctx context.Context, discover Discoverer, opts AssembleOpts) error {
	if opts.DiscoveryPeriod == 0 {
		opts.DiscoveryPeriod = time.Second * 3
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	if opts.ErrorHandler == nil {
		opts.ErrorHandler = func(err error) {
			logger.Error(err.Error())
		}
	}

	// TODO: eventually, this will be lazy-initialized from the state we pass in
	rdt, err := as.NewRDT()
	if err != nil {
		return err
	}

	if opts.RDTOverride != "" {
		rdt = as.RDT(opts.RDTOverride)
	}

	logger = logger.With("local-rdt", rdt)

	cert, err := createCert(opts.ListenIP)
	if err != nil {
		return err
	}

	view, err := as.NewView(opts.Secret, rdt, opts.ListenIP, opts.ListenPort, cert)
	if err != nil {
		return err
	}

	assembler, err := newAssembler(view, *logger, opts.ErrorHandler)
	if err != nil {
		return err
	}
	defer assembler.stop()

	// not required right now due to the function's current control flow, but we
	// want to make sure that the context we use is cancelled when leaving this
	// function.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	discoveries, stop := discoveryNotifier(ctx, discover, opts.DiscoveryPeriod, opts.ErrorHandler)
	defer stop()

	verified := make(map[string]bool)
	for {
		var untrusted []UntrustedPeer
		// TODO: handle another source of discoveries
		select {
		case untrusted = <-discoveries:
		case <-ctx.Done():
			return nil
		}

		for _, up := range untrusted {
			addr := peerAddress(up.IP, up.Port)
			if verified[addr] || (up.IP.Equal(opts.ListenIP) && up.Port == opts.ListenPort) {
				continue
			}

			logger.Debug("discovered peer", "peer-address", addr)

			rdt, err := assembler.verify(ctx, up)
			if err != nil {
				opts.ErrorHandler(fmt.Errorf("verifying discovered peer: %w", err))
				continue
			}

			verified[addr] = true
			logger.Debug("established trust with peer", "peer-address", addr, "peer-rdt", rdt)
		}
	}
}

type assembler struct {
	view   *as.ClusterView
	server *http.Server

	lock  sync.Mutex
	peers map[as.RDT]*peer

	wg     sync.WaitGroup
	errors func(error)
	logger slog.Logger
}

func newAssembler(view *as.ClusterView, logger slog.Logger, errs func(error)) (*assembler, error) {
	a := assembler{
		errors: errs,
		peers:  make(map[as.RDT]*peer),
		view:   view,
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.Handle("/assemble/auth", http.HandlerFunc(a.handleAuth))
	mux.Handle("/assemble/routes", a.trustedHandler(a.handleRoutes))
	mux.Handle("/assemble/unknown", a.trustedHandler(a.handleUnknown))
	mux.Handle("/assemble/devices", a.trustedHandler(a.handleDevices))

	a.server = &http.Server{
		Handler: mux,
	}

	// this will be closed by assembler.stop
	ln, err := net.Listen("tcp", view.Address())
	if err != nil {
		return nil, err
	}

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()

		listener := tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{view.Cert()},
			ClientAuth:   tls.RequireAnyClientCert,
		})
		_ = a.server.Serve(listener)
	}()

	return &a, nil

}

func (a *assembler) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	if r.TLS == nil {
		w.WriteHeader(400)
		return
	}

	if len(r.TLS.PeerCertificates) != 1 {
		w.WriteHeader(400)
		return
	}

	// set a max size so an untrusted peer can't send some massive JSON
	const maxAuthSize = 1024 * 4
	var auth as.Auth
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAuthSize)).Decode(&auth); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := a.view.CheckAuth(auth, r.TLS.PeerCertificates[0].Raw); err != nil {
		w.WriteHeader(403)
		return
	}

	if err := json.NewEncoder(w).Encode(a.view.Auth()); err != nil {
		w.WriteHeader(500)
		return
	}

	a.logger.Debug("got valid auth message", "peer-rdt", auth.RDT)

	// TODO: technically we could authenticate the peer here as well, and start
	// receiving data for them. however, it is annoying as we cannot fully
	// constuct the peer's identity, since we don't have their port available.
	// we maybe could introspect the ip of the sender, but not the port.
	//
	// adding the address in assemble-auth could make this better, maybe?
	//
	// for now, we will drop any messages from this peer until we've
	// "discovered" them
}

func (a *assembler) trustedHandler(h func(http.ResponseWriter, *http.Request, as.RDT)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			w.WriteHeader(400)
			return
		}

		if len(r.TLS.PeerCertificates) != 1 {
			w.WriteHeader(400)
			return
		}

		rdt, err := a.view.Trusted(r.TLS.PeerCertificates[0].Raw)
		if err != nil {
			a.logger.Debug("dropping message from untrusted peer")
			w.WriteHeader(403)
			return
		}

		h(w, r, rdt)
	}
}

func (a *assembler) handleRoutes(w http.ResponseWriter, r *http.Request, peerRDT as.RDT) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	var routes as.Routes
	if err := json.NewDecoder(r.Body).Decode(&routes); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := a.view.RecordPeerRoutes(peerRDT, routes); err != nil {
		w.WriteHeader(400)
		return
	}

	a.logger.Debug("got routes update", "peer-rdt", peerRDT)

	a.lock.Lock()
	defer a.lock.Unlock()

	// wake up this peer's thread so that it'll request information for any
	// devices we don't recognize
	a.peers[peerRDT].unidentified <- struct{}{}

	for rdt, peer := range a.peers {
		// any new routes from this peer don't need to be sent back to that
		// peer, since they already have them. don't even bother waking that
		// thread up
		if rdt == peerRDT {
			continue
		}

		// let all the other peer threads know that there is new data that they
		// might need to publish
		peer.routes <- struct{}{}
	}
}

func (a *assembler) handleUnknown(w http.ResponseWriter, r *http.Request, peerRDT as.RDT) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	var unknown as.UnknownDevices
	if err := json.NewDecoder(r.Body).Decode(&unknown); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := a.view.RecordPeerDeviceQueries(peerRDT, unknown); err != nil {
		w.WriteHeader(400)
		return
	}

	a.logger.Debug("got query for device information", "peer-rdt", peerRDT)

	a.lock.Lock()
	defer a.lock.Unlock()

	a.peers[peerRDT].devices <- struct{}{}
}

func (a *assembler) handleDevices(w http.ResponseWriter, r *http.Request, peerRDT as.RDT) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	var devices as.Devices
	if err := json.NewDecoder(r.Body).Decode(&devices); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := a.view.RecordIdentities(devices); err != nil {
		w.WriteHeader(400)
		return
	}

	a.logger.Debug("got unknown device information", "peer-rdt", peerRDT)

	a.lock.Lock()
	defer a.lock.Unlock()

	// new information about devices could enable us to publish more routes to
	// our peers
	for _, p := range a.peers {
		p.routes <- struct{}{}
	}
}

func (a *assembler) stop() {
	a.lock.Lock()
	defer a.lock.Unlock()

	for _, p := range a.peers {
		p.stop()
	}

	_ = a.server.Shutdown(context.Background())

	a.wg.Wait()
}

func (a *assembler) verify(ctx context.Context, up UntrustedPeer) (as.RDT, error) {
	cert := a.view.Cert()
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
			},
		},
		Timeout: time.Second * 10,
	}

	res, err := sendWithResponse(ctx, &client, peerAddress(up.IP, up.Port), "auth", a.view.Auth())
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.TLS == nil {
		return "", errors.New("cannot establish trust over unencrypted connection")
	}

	if len(res.TLS.PeerCertificates) != 1 {
		return "", fmt.Errorf("exactly one peer certificate expected, got %d", len(res.TLS.PeerCertificates))
	}

	// set a max size so an untrusted peer can't send some massive JSON
	const maxAuthSize = 1024 * 4
	var auth as.Auth
	if err := json.NewDecoder(io.LimitReader(res.Body, maxAuthSize)).Decode(&auth); err != nil {
		return "", err
	}

	pv, err := a.view.Authenticate(auth, res.TLS.PeerCertificates[0].Raw, up.IP, up.Port)
	if err != nil {
		return "", err
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	rdt := pv.RDT()
	a.peers[rdt] = newPeer(ctx, pv, cert, a.logger, a.errors)

	return rdt, nil
}

type peer struct {
	routes       chan struct{}
	unidentified chan struct{}
	devices      chan struct{}
	wg           sync.WaitGroup
	errors       func(error)
}

// consumer orchestrates a loop that is either driver my an event source (the
// given channel), or by a periodic retry.
//
// The given "work" function is called when either the channel is read from, or
// when the work should be retried. If the "work" function returns true, then a
// retry will be scheduled.

// Retries are scheduled with an exponential back off. Incoming events are not
// currently throttled, and might take precedence over an already scheduled
// retry.
func publisher(ctx context.Context, events <-chan struct{}, work func() bool) {
	retry := false
	backoff := time.Millisecond * 500
	for {
		if retry {
			retry = false
			select {
			case _, ok := <-events:
				if !ok {
					return
				}
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
		} else {
			select {
			case _, ok := <-events:
				if !ok {
					return
				}
			case <-ctx.Done():
				return
			}
		}

		if work() {
			backoff = min(backoff*2, time.Second*30)
			retry = true
			continue
		}
		backoff = time.Millisecond * 500
	}
}

func newPeer(ctx context.Context, pv *as.PeerView, cert tls.Certificate, logger slog.Logger, errs func(error)) *peer {
	p := &peer{
		routes:       make(chan struct{}, 1024),
		unidentified: make(chan struct{}, 1024),
		devices:      make(chan struct{}, 1024),
		errors:       errs,
	}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(certs [][]byte, chains [][]*x509.Certificate) error {
					if len(certs) != 1 {
						return fmt.Errorf("exactly one peer certificate expected, got %d", len(certs))
					}

					if sha512.Sum512(certs[0]) != pv.FP() {
						return errors.New("refusing to communicate with unexpected peer certificate")
					}
					return nil
				},
				Certificates: []tls.Certificate{cert},
			},
		},
		// TODO: timeout
	}

	// below we spawn a few goroutines that handle publishing data to this peer.
	// each goroutine here blocks on a channel, and the HTTP handlers wake up
	// the goroutines by writing to those channels. data isn't passed around in
	// the channels themselves, since we need to make sure that everything that
	// we know about the cluster is stored in persistent state.
	//
	// we could consider using just one channel and goroutine here. the channel
	// would have to carry a message that indicates which type of data we should
	// publish. the current implementation uses multiple goroutines to keep the
	// retry loops independent, but we might not want that.

	// this goroutine handles publishing routes to this peer that the local node
	// doesn't think this peer knows about.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		previous := as.Routes{}
		publisher(ctx, p.routes, func() (retry bool) {
			unknown, err := pv.UnknownRoutes()
			if err != nil {
				p.errors(err)
				return false
			}

			if routesEqual(previous, unknown) || routesEqual(unknown, as.Routes{}) {
				return false
			}

			if err := send(ctx, &client, pv.Address(), "routes", unknown); err != nil {
				if errors.Is(err, context.Canceled) {
					return false
				}

				p.errors(err)
				return true
			}

			logger.Debug("sent routes update", "peer-rdt", pv.RDT(), "routes", unknown)
			previous = unknown

			if err := pv.AckRoutes(unknown); err != nil {
				p.errors(err)
				return false
			}
			return false
		})
	}()
	p.routes <- struct{}{}

	// this goroutine handles requesting device information from this peer that
	// the local node doesn't yet have.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		publisher(ctx, p.unidentified, func() (retry bool) {
			unknown := pv.UnidentifiedDevices()
			if len(unknown.Devices) == 0 {
				return false
			}

			if err := send(ctx, &client, pv.Address(), "unknown", unknown); err != nil {
				if errors.Is(err, context.Canceled) {
					return false
				}

				p.errors(err)
				return true
			}
			return false
		})
	}()
	p.unidentified <- struct{}{}

	// this goroutine handles publishing device information that this peer has
	// requested
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		publisher(ctx, p.devices, func() (retry bool) {
			devices, err := pv.UnknownDevices()
			if err != nil {
				p.errors(err)
				return false
			}

			if len(devices.Devices) == 0 {
				return false
			}

			if err := send(ctx, &client, pv.Address(), "devices", devices); err != nil {
				if errors.Is(err, context.Canceled) {
					return false
				}

				p.errors(err)
				return true
			}

			pv.AckDevices(devices)
			return false
		})
	}()
	p.devices <- struct{}{}

	return p
}

func (p *peer) stop() {
	close(p.routes)
	close(p.unidentified)
	close(p.devices)
	p.wg.Wait()
}

func peerAddress(ip net.IP, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

func send(ctx context.Context, client *http.Client, addr string, kind string, data any) error {
	res, err := sendWithResponse(ctx, client, addr, kind, data)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("expected status code 200, got %d", res.StatusCode)
	}

	return nil
}

func sendWithResponse(ctx context.Context, client *http.Client, addr string, kind string, data any) (*http.Response, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://%s/assemble/%s", addr, kind)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	return client.Do(req)
}

func createCert(ip net.IP) (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}

	// TODO: rotation, renewal? don't worry about it? for now make it last until
	// the next century, when i'll be gone
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost-ed25519"},
		NotBefore:    now,
		NotAfter:     now.AddDate(100, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{ip},
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func routesEqual(l, r as.Routes) bool {
	return slices.Equal(l.Addresses, r.Addresses) &&
		slices.Equal(l.Devices, r.Devices) &&
		slices.Equal(l.Routes, r.Routes)
}

func discoveryNotifier(ctx context.Context, discover Discoverer, period time.Duration, errs func(error)) (<-chan []UntrustedPeer, func()) {
	outputs := make(chan []UntrustedPeer)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(outputs)

		ticker := time.NewTicker(period)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			// fail early even if the ticker won the select
			if ctx.Err() != nil {
				return
			}

			peers, err := discover(ctx)
			if err != nil {
				errs(err)
				continue
			}

			if len(peers) == 0 {
				continue
			}

			select {
			case outputs <- peers:
			case <-ctx.Done():
				return
			}
		}
	}()
	return outputs, wg.Wait
}
