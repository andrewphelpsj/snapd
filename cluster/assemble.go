package cluster

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
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
	"log"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	as "github.com/snapcore/snapd/cluster/assemblestate"
)

type AssembleOpts struct {
	DiscoveryPeriod time.Duration
	Secret          string
	TLSCert         string
	ErrorHandler    func(error)
	ListenIP        net.IP
	ListenPort      int
}

type Discoverer = func(context.Context) ([]UntrustedPeer, error)

func Assemble(ctx context.Context, discover Discoverer, opts AssembleOpts) error {
	if opts.ErrorHandler == nil {
		opts.ErrorHandler = func(err error) {
			log.Printf("cluster assemble error: %v\n", err)
		}
	}

	if opts.DiscoveryPeriod == 0 {
		opts.DiscoveryPeriod = time.Second * 3
	}

	// TODO: eventually, this will be lazy-initialized from the state we pass in
	rdt, err := as.NewRDT()
	if err != nil {
		return err
	}

	assembler, err := newAssembler(opts.Secret, rdt, opts.ListenIP, opts.ListenPort)
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
outer:
	for {
		var untrusted []UntrustedPeer
		// TODO: handle another source of discoveries
		select {
		case untrusted = <-discoveries:
		case <-ctx.Done():
			break outer
		}

		for _, up := range untrusted {
			addr := peerAddress(up.IP, up.Port)
			if verified[addr] {
				continue
			}

			if err := assembler.verify(ctx, up); err != nil {
				opts.ErrorHandler(err)
			} else {
				verified[addr] = true
			}
		}
	}

	return nil
}

type assembler struct {
	state  *as.ClusterView
	server *http.Server

	lock  sync.Mutex
	peers map[as.FP]*peer

	wg     sync.WaitGroup
	errors func(error)
}

func newAssembler(secret string, rdt as.RDT, ip net.IP, port int) (*assembler, error) {
	cert, err := createCert(ip)
	if err != nil {
		return nil, err
	}

	fp := calculateFP(cert.Certificate[0])

	state := as.New(secret, rdt, ip, port, fp)

	addr := peerAddress(ip, port)
	a := assembler{
		errors: func(err error) {
			log.Printf("cluster assemble error: %v\n", err)
		},
		peers: make(map[as.FP]*peer),
		state: state,
	}

	mux := http.NewServeMux()
	mux.Handle("/assemble/auth", http.HandlerFunc(a.handleAuth))
	mux.Handle("/assemble/routes", a.trustedHandler(a.handleRoutes))
	mux.Handle("/assemble/unknown", a.trustedHandler(a.handleUnknown))
	mux.Handle("/assemble/devices", a.trustedHandler(a.handleDevices))

	a.server = &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}

	// this will be closed by assembler.stop
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()

		listener := tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
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

	peerFP, err := calculatePeerFP(r.TLS)
	if err != nil {
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

	expectedHMAC := calculateHMAC(auth.RDT, peerFP, a.state.Secret())
	if !hmac.Equal(expectedHMAC, auth.HMAC) {
		w.WriteHeader(403)
		return
	}

	if err := json.NewEncoder(w).Encode(as.Auth{
		HMAC: a.state.HMAC(),
		RDT:  a.state.RDT(),
	}); err != nil {
		w.WriteHeader(500)
		return
	}

	a.state.Trust(peerFP)
}

func (a *assembler) trustedHandler(h func(http.ResponseWriter, *http.Request, as.FP)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			w.WriteHeader(400)
			return
		}

		peerFP, err := calculatePeerFP(r.TLS)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		if !a.state.Trusted(peerFP) {
			w.WriteHeader(403)
			return
		}

		h(w, r, peerFP)
	}
}

func (a *assembler) handleRoutes(w http.ResponseWriter, r *http.Request, peerFP as.FP) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	var routes as.Routes
	if err := json.NewDecoder(r.Body).Decode(&routes); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := a.state.RecordPeerRoutes(peerFP, routes); err != nil {
		w.WriteHeader(400)
		return
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	// wake up this peer's thread so that it'll request information for any
	// unknown devices. note that this peer thread might not have started,
	// depending on the order of operations.
	if p, ok := a.peers[peerFP]; ok {
		p.query <- struct{}{}
	}

	for fp, peer := range a.peers {
		// any new routes from this peer don't need to be sent back to that
		// peer, since they already have them. don't even bother waking that
		// thread up
		if fp == peerFP {
			continue
		}

		// let all the other peer threads know that there is new data that they
		// might need to publish
		peer.routes <- struct{}{}
	}
}

func (a *assembler) handleUnknown(w http.ResponseWriter, r *http.Request, peerFP as.FP) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	var unknown as.UnknownDevices
	if err := json.NewDecoder(r.Body).Decode(&unknown); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := a.state.RecordPeerDeviceQueries(peerFP, unknown); err != nil {
		w.WriteHeader(400)
		return
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	if p, ok := a.peers[peerFP]; ok {
		p.query <- struct{}{}
	}
}

func (a *assembler) handleDevices(w http.ResponseWriter, r *http.Request, peerFP as.FP) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	var devices as.Devices
	if err := json.NewDecoder(r.Body).Decode(&devices); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := a.state.RecordIdentities(devices); err != nil {
		w.WriteHeader(400)
		return
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	for fp, p := range a.peers {
		// any new devices from this peer don't need to be sent back to that
		// peer, since they already have them. don't even bother waking that
		// thread up
		if fp == peerFP {
			continue
		}

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

func (a *assembler) verify(ctx context.Context, up UntrustedPeer) error {
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       a.server.TLSConfig.Certificates,
			},
		},
		Timeout: time.Second * 10,
	}

	res, err := sendWithResponse(ctx, &client, peerAddress(up.IP, up.Port), "auth", as.Auth{
		HMAC: a.state.HMAC(),
		RDT:  a.state.RDT(),
	})
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.TLS == nil {
		return errors.New("cannot establish trust over unencrypted connection")
	}

	peerFP, err := calculatePeerFP(res.TLS)
	if err != nil {
		return err
	}

	// set a max size so an untrusted peer can't send some massive JSON
	const maxAuthSize = 1024 * 4
	var auth as.Auth
	if err := json.NewDecoder(io.LimitReader(res.Body, maxAuthSize)).Decode(&auth); err != nil {
		return err
	}

	expectedHMAC := calculateHMAC(auth.RDT, peerFP, a.state.Secret())
	if !hmac.Equal(expectedHMAC, auth.HMAC) {
		return errors.New("received invalid HMAC from peer")
	}

	a.state.Trust(peerFP)

	pv, err := a.state.PeerView(peerFP, auth.RDT, up.IP, up.Port)
	if err != nil {
		return err
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	a.peers[peerFP] = newPeer(ctx, pv, a.server.TLSConfig.Certificates[0], a.errors)

	return nil
}

type peer struct {
	routes chan struct{}
	query  chan struct{}
	inform chan struct{}
	wg     sync.WaitGroup
	errors func(error)
}

func newPeer(ctx context.Context, pv *as.PeerView, cert tls.Certificate, errs func(error)) *peer {
	p := &peer{
		routes: make(chan struct{}, 1024),
		query:  make(chan struct{}, 1024),
		inform: make(chan struct{}, 1024),
		errors: errs,
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
		Timeout: time.Second * 10,
	}

	// TODO: either deduplicate the code here, or make it so that all incoming
	// messages are multiplexed into one goroutine. this might be hard, since we
	// probably want to retry failed POSTs.

	// one thread will be responsible for sending assemble-routes
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		backoff := time.Millisecond * 500
		retry := false
		for {
			if retry {
				select {
				case _, ok := <-p.routes:
					if !ok {
						return
					}
				case <-time.After(backoff):
					retry = false
					backoff = min(backoff*2, time.Second*30)
				}
			} else {
				_, ok := <-p.routes
				if !ok {
					return
				}
			}

			unknown, err := pv.UnknownRoutes()
			if err != nil {
				p.errors(err)
				continue
			}

			if err := send(ctx, &client, pv.Address(), "routes", unknown); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}

				retry = true
				p.errors(err)
				continue
			}
			backoff = time.Millisecond * 500

			if err := pv.AckRoutes(unknown); err != nil {
				p.errors(err)
				continue
			}
		}
	}()
	p.routes <- struct{}{}

	// another thread will be responsible for sending assemble-unknown-devices
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		for {
			// even if we haven't gotten any new data, should we run this loop
			// periodically?
			select {
			case _, ok := <-p.query:
				if !ok {
					return
				}
			case <-time.After(time.Second * 30):
			}

			unknown := pv.UnidentifiedDevices()
			if len(unknown.Devices) == 0 {
				continue
			}

			if err := send(ctx, &client, pv.Address(), "unknown", unknown); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}

				p.errors(err)
				continue
			}
		}
	}()
	p.query <- struct{}{}

	// finally, another thread will be responsible for sending assemble-devices
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		backoff := time.Millisecond * 500
		retry := false
		for {
			if retry {
				select {
				case _, ok := <-p.inform:
					if !ok {
						return
					}
				case <-time.After(backoff):
					retry = false
					backoff = min(backoff*2, time.Second*30)
				}
			} else {
				_, ok := <-p.inform
				if !ok {
					return
				}
			}

			ad, err := pv.UnknownDevices()
			if err != nil {
				p.errors(err)
				continue
			}

			if len(ad.Devices) == 0 {
				retry = false
				continue
			}

			if err := send(ctx, &client, pv.Address(), "devices", ad); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}

				retry = true
				p.errors(err)
				continue
			}
			backoff = time.Millisecond * 500

			pv.AckDevices(ad)
		}
	}()
	p.inform <- struct{}{}

	return p
}

func (p *peer) stop() {
	close(p.routes)
	close(p.query)
	close(p.inform)
	p.wg.Wait()
}

func peerAddress(ip net.IP, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

func calculateFP(cert []byte) as.FP {
	return sha512.Sum512(cert)
}

func calculatePeerFP(conn *tls.ConnectionState) (as.FP, error) {
	if len(conn.PeerCertificates) != 1 {
		return as.FP{}, fmt.Errorf("exactly one peer certificate expected, got %d", len(conn.PeerCertificates))
	}

	return calculateFP(conn.PeerCertificates[0].Raw), nil
}

func calculateHMAC(rdt as.RDT, fp as.FP, secret string) []byte {
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write(fp[:])
	mac.Write([]byte(rdt))
	return mac.Sum(nil)
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
