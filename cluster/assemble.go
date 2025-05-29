package cluster

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"golang.org/x/time/rate"
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

func Assemble(ctx context.Context, discover Discoverer, opts AssembleOpts) (as.Routes, error) {
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
		return as.Routes{}, err
	}

	if opts.RDTOverride != "" {
		rdt = as.RDT(opts.RDTOverride)
	}

	logger = logger.With("local-rdt", rdt)

	cert, err := createCert(opts.ListenIP)
	if err != nil {
		return as.Routes{}, err
	}

	view, err := as.NewClusterView(opts.Secret, rdt, opts.ListenIP, opts.ListenPort, cert)
	if err != nil {
		return as.Routes{}, err
	}

	assembler, err := newAssembler(view, *logger, opts.ErrorHandler)
	if err != nil {
		return as.Routes{}, err
	}
	defer assembler.stop()

	// not required right now due to the function's current control flow, but we
	// want to make sure that the context we use is cancelled when leaving this
	// function.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	discoveries, stop := discoveryNotifier(ctx, discover, opts.DiscoveryPeriod, opts.ErrorHandler)
	defer stop()

	defer logger.Info("assemble stopped")

	joined := make(map[string]bool)
	var lock sync.Mutex
outer:
	for {
		var untrusted []UntrustedPeer

		// TODO: handle another source of discoveries
		select {
		case untrusted = <-discoveries:
		case <-ctx.Done():
			break outer
		}

		if ctx.Err() != nil {
			break outer
		}

		var wg sync.WaitGroup
		for _, up := range untrusted {
			addr := peerAddress(up.IP, up.Port)
			if _, ok := joined[addr]; ok {
				continue
			}

			if up.IP.Equal(opts.ListenIP) && up.Port == opts.ListenPort {
				continue
			}

			wg.Add(1)
			go func() {
				defer wg.Done()

				logger.Info("discovered peer", "peer-address", addr)

				if err := assembler.verify(ctx, up); err != nil {
					opts.ErrorHandler(fmt.Errorf("verifying discovered peer: %w", err))
					return
				}

				lock.Lock()
				defer lock.Unlock()

				joined[addr] = true
			}()
		}
		wg.Wait()
	}

	return assembler.stop(), nil
}

type assembler struct {
	view    *as.ClusterView
	server  *http.Server
	limiter *rate.Limiter

	stopped bool
	lock    sync.Mutex
	peers   map[as.RDT]*peer

	wg     sync.WaitGroup
	errors func(error)
	logger slog.Logger
}

func newAssembler(view *as.ClusterView, logger slog.Logger, errs func(error)) (*assembler, error) {
	// TODO: handle a concept of an expected size
	a := assembler{
		errors: errs,
		peers:  make(map[as.RDT]*peer),
		view:   view,
		logger: logger,

		// start off with a conservative 20 outbound messages per-second. this
		// will be recalulated once peers join the cluster.
		limiter: rate.NewLimiter(rate.Limit(20), 1),
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

	// we don't yet know the return address here. we maybe could get the return
	// IP, but the port isn't known. we can auth this peer, and we'll start
	// queuing up data for them. but we won't publish any data for this until
	// the local node has "discovered" them
	const addr = ""
	if _, err := a.view.Authenticate(auth, r.TLS.PeerCertificates[0].Raw, ""); err != nil {
		w.WriteHeader(403)
		return
	}

	if err := json.NewEncoder(w).Encode(a.view.Auth()); err != nil {
		w.WriteHeader(500)
		return
	}

	a.logger.Debug("got valid auth message", "peer-rdt", auth.RDT)
}

func (a *assembler) trustedHandler(h func(http.ResponseWriter, *http.Request, *as.PeerView)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			w.WriteHeader(400)
			return
		}

		if len(r.TLS.PeerCertificates) != 1 {
			w.WriteHeader(400)
			return
		}

		pv, err := a.view.Trusted(r.TLS.PeerCertificates[0].Raw)
		if err != nil {
			a.logger.Debug("dropping message from untrusted peer")
			w.WriteHeader(403)
			return
		}

		h(w, r, pv)
	}
}

func (a *assembler) handleRoutes(w http.ResponseWriter, r *http.Request, pv *as.PeerView) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	var routes as.Routes
	if err := json.NewDecoder(r.Body).Decode(&routes); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := pv.RecordRoutes(routes); err != nil {
		w.WriteHeader(400)
		return
	}

	a.logger.Debug("got routes update", "peer-rdt", pv.RDT(), "routes-count", len(routes.Routes)/3)

	a.lock.Lock()
	defer a.lock.Unlock()

	// wake up this peer's thread so that it'll request information for any
	// devices we don't recognize
	if p, ok := a.peers[pv.RDT()]; ok {
		notify(p.unidentified)
	}

	for rdt, peer := range a.peers {
		// any new routes from this peer don't need to be sent back to that
		// peer, since they already have them. don't even bother waking that
		// thread up
		if rdt == pv.RDT() {
			continue
		}

		// let all the other peer threads know that there is new data that they
		// might need to publish
		notify(peer.routes)
	}
}

func (a *assembler) handleUnknown(w http.ResponseWriter, r *http.Request, pv *as.PeerView) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	var unknown as.UnknownDevices
	if err := json.NewDecoder(r.Body).Decode(&unknown); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := pv.RecordDeviceQueries(unknown); err != nil {
		w.WriteHeader(400)
		return
	}

	a.logger.Debug("got query for device information", "peer-rdt", pv.RDT())

	a.lock.Lock()
	defer a.lock.Unlock()

	if p, ok := a.peers[pv.RDT()]; ok {
		notify(p.devices)
	}
}

func (a *assembler) handleDevices(w http.ResponseWriter, r *http.Request, pv *as.PeerView) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	var devices as.Devices
	if err := json.NewDecoder(r.Body).Decode(&devices); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := pv.RecordIdentities(devices); err != nil {
		w.WriteHeader(400)
		return
	}

	a.logger.Debug("got unknown device information", "peer-rdt", pv.RDT())

	a.lock.Lock()
	defer a.lock.Unlock()

	// new information about devices could enable us to publish more routes to
	// our peers
	for _, p := range a.peers {
		notify(p.routes)
	}
}

func (a *assembler) stop() as.Routes {
	if !a.stopped {
		a.stopped = true

		_ = a.server.Shutdown(context.Background())
		a.wg.Wait()

		a.lock.Lock()
		defer a.lock.Unlock()
		for _, p := range a.peers {
			p.stop()
		}
	}

	return a.view.Export()
}

func (a *assembler) verify(ctx context.Context, up UntrustedPeer) error {
	cert := a.view.Cert()
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
			},
		},
		Timeout: time.Minute,
	}

	addr := peerAddress(up.IP, up.Port)
	res, err := sendWithResponse(ctx, &client, a.limiter, addr, "auth", a.view.Auth())
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.TLS == nil {
		return errors.New("cannot establish trust over unencrypted connection")
	}

	if len(res.TLS.PeerCertificates) != 1 {
		return fmt.Errorf("exactly one peer certificate expected, got %d", len(res.TLS.PeerCertificates))
	}

	// set a max size so an untrusted peer can't send some massive JSON
	const maxAuthSize = 1024 * 4
	var auth as.Auth
	if err := json.NewDecoder(io.LimitReader(res.Body, maxAuthSize)).Decode(&auth); err != nil {
		return err
	}

	pv, err := a.view.Authenticate(auth, res.TLS.PeerCertificates[0].Raw, addr)
	if err != nil {
		return err
	}

	if err := a.join(ctx, pv); err != nil {
		return err
	}

	return nil
}

type peer struct {
	routes       chan struct{}
	unidentified chan struct{}
	devices      chan struct{}
	wg           sync.WaitGroup
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

		if ctx.Err() != nil {
			return
		}

		if work() {
			backoff = min(backoff*2, time.Second*30)
			retry = true
			continue
		}
		backoff = time.Millisecond * 500
	}
}

func notify(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (a *assembler) join(ctx context.Context, pv *as.PeerView) error {
	a.lock.Lock()
	defer a.lock.Unlock()

	p := &peer{
		routes:       make(chan struct{}, 1),
		unidentified: make(chan struct{}, 1),
		devices:      make(chan struct{}, 1),
	}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(certs [][]byte, chains [][]*x509.Certificate) error {
					if len(certs) != 1 {
						return fmt.Errorf("exactly one peer certificate expected, got %d", len(certs))
					}

					if !bytes.Equal(certs[0], pv.Cert()) {
						return errors.New("refusing to communicate with unexpected peer certificate")
					}

					return nil
				},
				Certificates: []tls.Certificate{a.view.Cert()},
			},
		},
		Timeout: time.Minute,
	}

	addr, ok := pv.Address()
	if !ok {
		return fmt.Errorf("cannot communicate with peer %q without an address", pv.RDT())
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
		publisher(ctx, p.routes, func() (retry bool) {
			routes, err := pv.UnknownRoutes()
			if err != nil {
				a.errors(err)
				return false
			}

			if len(routes.Routes) == 0 && len(routes.Devices) == 0 && len(routes.Addresses) == 0 {
				return false
			}

			if err := send(ctx, &client, a.limiter, addr, "routes", routes); err != nil {
				if errors.Is(err, context.Canceled) {
					return false
				}

				a.errors(err)
				return true
			}

			a.logger.Debug("sent routes update", "peer-rdt", pv.RDT(), "routes-count", len(routes.Routes)/3)

			if err := pv.AckRoutes(routes); err != nil {
				a.errors(err)
				return false
			}
			return false
		})
	}()
	notify(p.routes)

	// this goroutine handles requesting device information from this peer that
	// the local node doesn't yet have.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		publisher(ctx, p.unidentified, func() (retry bool) {
			identifiable := pv.IdentifiableDevices()
			if len(identifiable.Devices) == 0 {
				return false
			}

			if err := send(ctx, &client, a.limiter, addr, "unknown", identifiable); err != nil {
				if errors.Is(err, context.Canceled) {
					return false
				}

				a.errors(err)
				return true
			}
			return false
		})
	}()
	notify(p.unidentified)

	// this goroutine handles publishing device information that this peer has
	// requested
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		publisher(ctx, p.devices, func() (retry bool) {
			devices, err := pv.UnknownDevices()
			if err != nil {
				a.errors(err)
				return false
			}

			if len(devices.Devices) == 0 {
				return false
			}

			if err := send(ctx, &client, a.limiter, addr, "devices", devices); err != nil {
				if errors.Is(err, context.Canceled) {
					return false
				}

				a.errors(err)
				return true
			}

			pv.AckDevices(devices)
			return false
		})
	}()
	notify(p.devices)

	rdt := pv.RDT()
	a.peers[rdt] = p

	// update our rate limiter to consider the number of peers in the cluster.
	// this is an attempt to coordinate throttling with our peers. we allow
	// everyone to send at least at least 1 message per second, but we try to
	// keep the cluster limited to 500 messages per second.
	rate := max(rate.Limit(1), rate.Limit(500/len(a.peers)))
	a.limiter.SetLimit(rate)

	a.logger.Info(
		"initiating outbound comms with peer",
		"peer-address", addr,
		"peer-rdt", rdt,
		"rate-limit", a.limiter.Limit(),
	)

	return nil
}

func (p *peer) stop() {
	p.wg.Wait()
}

func peerAddress(ip net.IP, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

func send(ctx context.Context, client *http.Client, limiter *rate.Limiter, addr string, kind string, data any) error {
	res, err := sendWithResponse(ctx, client, limiter, addr, kind, data)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("response to '%s' message contains status code %d", kind, res.StatusCode)
	}

	return nil
}

func sendWithResponse(ctx context.Context, client *http.Client, limiter *rate.Limiter, addr string, kind string, data any) (*http.Response, error) {
	if err := limiter.Wait(ctx); err != nil {
		return nil, err
	}

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
		first := true
		for {
			if !first {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}

				// fail early even if the ticker won the select
				if ctx.Err() != nil {
					return
				}
			}
			first = false

			peers, err := discover(ctx)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}

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
