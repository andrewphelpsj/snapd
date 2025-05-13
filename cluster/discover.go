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
	"maps"
	"math/big"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"slices"

	"github.com/snapcore/snapd/cluster/mdns"
)

const ServiceType = "_snapd._tcp"

type AdvertiseOpts struct {
	Instance  string
	Port      int
	IPs       []net.IP
	Domain    string
	Hostname  string
	Interface *net.Interface
}

func Advertise(opts AdvertiseOpts) (stop func() error, err error) {
	service, err := mdns.NewMDNSService(
		opts.Instance, ServiceType, opts.Domain, opts.Hostname, opts.Port, opts.IPs, nil,
	)
	if err != nil {
		return nil, err
	}

	server, err := mdns.NewServer(&mdns.Config{
		Zone:  service,
		Iface: opts.Interface,
	})
	if err != nil {
		return nil, err
	}

	return server.Shutdown, nil
}

type DiscoverOpts struct {
	Domain    string
	Interface *net.Interface
}

type UntrustedPeer struct {
	IP   net.IP
	Port int
}

func Discover(ctx context.Context, opts DiscoverOpts) ([]UntrustedPeer, error) {
	// reasonably large buffer, since the mdns library will drop entries if we
	// cannot process them fast enough
	//
	// TODO: we could patch that if we fork this library
	ch := make(chan *mdns.ServiceEntry, 1024)

	params := mdns.DefaultParams(ServiceType)
	params.Interface = opts.Interface
	params.Entries = ch
	params.Domain = opts.Domain
	params.Logger = log.New(io.Discard, "", 0)

	var peers []UntrustedPeer
	done := make(chan struct{})
	go func() {
		defer close(done)
		for entry := range ch {
			peers = append(peers, UntrustedPeer{
				IP:   entry.AddrV4,
				Port: entry.Port,
			})
		}
	}()

	if err := mdns.QueryContext(ctx, params); err != nil {
		close(ch)
		<-done
		return nil, err
	}

	close(ch)
	<-done

	return peers, nil
}

type Discoverer = func(context.Context) ([]UntrustedPeer, error)

type AssembleOpts struct {
	DiscoveryPeriod time.Duration
	Secret          string
	TLSCert         string
	ErrorHandler    func(error)
	ListenIP        net.IP
	ListenPort      int
}

type assembler struct {
	client http.Client
	server *http.Server
	secret string
	rdt    string
	hmac   []byte
	port   int
	ip     net.IP

	lock sync.Mutex

	// trusted is a mapping of verifed peer RDTs to a [TrustedPeer] that describes that
	// peer. This will be used to verify incoming messages from trusted.
	trusted map[[64]byte]string

	// unverified keeps track of routes that we know about for which we haven't
	// seen an assemble-devices message for all devices involved.
	unverified routes

	// verified keeps track of routes that we can include in our assemble-routes
	// messages. Note that when sending an assemble-routes message, we will
	// always include the route on which we're sending the message (our RDT to
	// the peer's RDT, via the peer's address). This is an exception, since we
	// might not have gotten a assemble-devices message that corresponds to that
	// peer. Additionally, we will include our address as well.
	verified routes

	peers []chan<- routes
	wg    sync.WaitGroup

	errors func(error)
}

type routes struct {
	devices   map[string]*device
	addresses map[string]struct{}
}

func newRoutes() routes {
	return routes{
		devices:   make(map[string]*device),
		addresses: make(map[string]struct{}),
	}
}

type device struct {
	rdt         string
	connections map[string]*device
}

func (r *routes) add(from, to, via string) error {
	if _, ok := r.devices[from]; !ok {
		r.devices[from] = &device{
			rdt:         from,
			connections: make(map[string]*device),
		}
	}

	if _, ok := r.devices[to]; !ok {
		r.devices[to] = &device{
			rdt:         to,
			connections: make(map[string]*device),
		}
	}

	if peer, ok := r.devices[from].connections[via]; ok && peer != r.devices[to] {
		return errors.New("cannot overwrite already existing route with new destination")
	}

	r.devices[from].connections[via] = r.devices[to]
	r.addresses[via] = struct{}{}

	return nil
}

func (r *routes) merge(ar AssembleRoutes) error {
	if len(ar.Routes)%3 != 0 {
		return errors.New("length of routes list in assemble-routes must be a multiple of three")
	}

	// TODO: some sort of pending system here for routes???
	for i := 0; i+2 < len(ar.Routes); i += 3 {
		if ar.Routes[i] < 0 || ar.Routes[i+1] < 0 || ar.Routes[i+2] < 0 {
			return errors.New("invalid index in assemble-routes")
		}

		if ar.Routes[i] > len(ar.Devices) || ar.Routes[i+1] > len(ar.Devices) || ar.Routes[i+2] > len(ar.Addresses) {
			return errors.New("invalid index in assemble-routes")
		}

		if err := r.add(
			ar.Devices[ar.Routes[i]],
			ar.Devices[ar.Routes[i+1]],
			ar.Addresses[ar.Routes[i+2]],
		); err != nil {
			return err
		}
	}

	return nil
}

func (r *routes) equals(other routes) bool {
	if !maps.Equal(r.addresses, other.addresses) {
		return false
	}

	if len(r.devices) != len(other.devices) {
		return false
	}

	for rdt, d := range r.devices {
		otherDevice, ok := other.devices[rdt]
		if !ok {
			return false
		}

		if len(d.connections) != len(otherDevice.connections) {
			return false
		}

		for via, to := range d.connections {
			otherPeer, ok := otherDevice.connections[via]
			if !ok {
				return false
			}

			if otherPeer.rdt != to.rdt {
				return false
			}
		}
	}

	return true
}

func (r *routes) clone() routes {
	cloned := routes{
		addresses: maps.Clone(r.addresses),
		devices:   make(map[string]*device, len(r.devices)),
	}

	for _, d := range r.devices {
		cloned.devices[d.rdt] = &device{
			rdt:         d.rdt,
			connections: make(map[string]*device, len(d.connections)),
		}
	}

	for _, from := range r.devices {
		for via, to := range from.connections {
			cloned.devices[from.rdt].connections[via] = cloned.devices[to.rdt]
		}
	}

	return cloned
}

func (r *routes) export() AssembleRoutes {
	devices := slices.Sorted(maps.Keys(r.devices))
	addresses := slices.Sorted(maps.Keys(r.addresses))

	var routes []int
	for _, from := range devices {
		from := r.devices[from]
		connections := slices.Sorted(maps.Keys(from.connections))
		for _, via := range connections {
			to := from.connections[via]
			routes = append(routes, []int{
				sort.SearchStrings(devices, from.rdt),
				sort.SearchStrings(devices, to.rdt),
				sort.SearchStrings(addresses, via),
			}...)
		}
	}

	return AssembleRoutes{
		Devices:   devices,
		Addresses: addresses,
		Routes:    routes,
	}
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
	// the next century.
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

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv.Seed()})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func newAssembler(secret string, rdt string, ip net.IP, port int) (*assembler, error) {
	cert, err := createCert(ip)
	if err != nil {
		return nil, err
	}

	addr := peerAddress(ip, port)
	a := assembler{
		// TODO: consider creating clients for each peer that can only be used
		// to communicate wit that peer
		client: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
						return nil
					},
				},
			},
			Timeout: time.Second * 10,
		},
		ip:         ip,
		port:       port,
		rdt:        rdt,
		hmac:       calculateHMAC(rdt, [64]byte{}, secret),
		secret:     secret,
		unverified: newRoutes(),
		verified:   newRoutes(),
		errors: func(err error) {
			log.Printf("cluster assemble error: %v\n", err)
		},
		trusted: make(map[[64]byte]string),
	}

	a.server = &http.Server{
		Addr:      addr,
		Handler:   http.HandlerFunc(a.handle),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}

	// this will be closed by assembler.stop
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	go func() {
		defer a.wg.Done()

		listener := tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
		a.server.Serve(listener)
	}()

	return &a, nil

}

func (a *assembler) handle(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		w.WriteHeader(400)
		return
	}

	peerFP, err := calculateFP(r.TLS)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	// if this peer isn't trusted, we only accept assemble-auth
	if _, ok := a.trusted[peerFP]; !ok {
		a.handleAuth(w, r, peerFP)
		return
	}

	type message struct {
		Kind string `json:"kind"`
		json.RawMessage
	}

	var msg message
	if err := json.NewDecoder(r.Body); err != nil {
		w.WriteHeader(400)
		return
	}

	switch msg.Kind {
	case "assemble-routes":
		var ar AssembleRoutes
		if err := json.Unmarshal(msg.RawMessage, &ar); err != nil {
			w.WriteHeader(400)
			return
		}

		// TODO: consider the routes here and put them in their places

		// TODO: respond with an assemble-unknown-devices message? this is maybe
		// a little weird but makes the implementation simpler, since we don't
		// have to talk to another thread that will send it. this would create
		// this relationship:
		//   * POST assemble-auth <- assemble-auth (sent by disco thread, can
		//     maybe short-circuited if we see that we've already gotten one?)
		//   * POST assemble-routes <- assemble-unknown-devices (sent by per-peer thread)
		//   * POST assemble-devices <- OK (who sends this?)
		//
		// an alternative is to multiplex different types of messages over the
		// "peers" channel?
	default:
		w.WriteHeader(501)
		return
	}
}

func (a *assembler) handleAuth(w http.ResponseWriter, r *http.Request, peerFP [64]byte) {
	// set a max size so a malicious peer can't send some insane JSON
	const maxAuthSize = 1024 * 4
	var aa AssembleAuth
	if err := json.NewDecoder(io.LimitReader(r.Body, maxAuthSize)).Decode(&aa); err != nil {
		w.WriteHeader(400)
		return
	}

	expectedHMAC := calculateHMAC(aa.RDT, peerFP, a.secret)
	if !hmac.Equal(expectedHMAC, aa.HMAC) {
		w.WriteHeader(403)
		return
	}

	if err := json.NewEncoder(w).Encode(AssembleAuth{
		HMAC: a.hmac,
		RDT:  a.rdt,
	}); err != nil {
		w.WriteHeader(500)
		return
	}

	a.trusted[peerFP] = aa.RDT
}

func (a *assembler) stop() {
	a.lock.Lock()
	defer a.lock.Unlock()

	for _, ch := range a.peers {
		close(ch)
	}

	a.server.Shutdown(context.Background())

	a.wg.Wait()
}

func (a *assembler) verify(ctx context.Context, up UntrustedPeer) error {
	// TODO: we're doing double work here, consider first checking if we have
	// already gotten an assemble-auth from this peer, and using the trust that
	// we've already established with this peer
	res, err := send(ctx, &a.client, up.IP, up.Port, "assemble-auth", AssembleAuth{
		HMAC: a.hmac,
		RDT:  a.rdt,
	})
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.TLS == nil {
		return errors.New("cannot establish trust over unencrypted connection")
	}

	peerFP, err := calculateFP(res.TLS)
	if err != nil {
		return err
	}

	// set a max size so a malicious peer can't send some insane JSON
	const maxAuthSize = 1024 * 4
	var auth AssembleAuth
	if err := json.NewDecoder(io.LimitReader(res.Body, maxAuthSize)).Decode(&auth); err != nil {
		return err
	}

	expectedHMAC := calculateHMAC(auth.RDT, peerFP, a.secret)
	if !hmac.Equal(expectedHMAC, auth.HMAC) {
		return errors.New("received invalid HMAC from peer")
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	// TODO: check that these don't already exist and handle conflicts?
	a.trusted[peerFP] = auth.RDT

	updates := make(chan routes, 1024)
	a.wg.Add(1)

	peer := struct {
		RDT  string
		IP   net.IP
		Port int
	}{
		RDT:  auth.RDT,
		IP:   up.IP,
		Port: up.Port,
	}

	go func() {
		defer a.wg.Done()

		previous := newRoutes()
		var pending *routes
		backoff := time.Second

		for {
			var routes routes
			if pending != nil {
				select {
				case r, ok := <-updates:
					if !ok {
						return
					}
					routes = r
				case <-time.After(backoff):
					routes = *pending
				}
				pending = nil
			} else {
				r, ok := <-updates
				if !ok {
					return
				}
				routes = r
			}

			if err := routes.add(a.rdt, peer.RDT, peerAddress(peer.IP, peer.Port)); err != nil {
				a.errors(err)
				continue
			}

			routes.addresses[peerAddress(a.ip, a.port)] = struct{}{}

			// if we're just sending the same thing again, don't bother
			if routes.equals(previous) {
				continue
			}

			message := routes.export()
			if err := sendCheckOK(ctx, &a.client, peer.IP, peer.Port, "assemble-routes", message); err != nil {
				pending = &routes
				backoff = min(backoff*2, time.Minute)

				a.errors(err)
				continue
			}

			previous = routes
			backoff = time.Second
		}
	}()

	a.peers = append(a.peers, updates)

	// the first update to the first peer will be entirely empty, but the thread
	// interfacing with the peer is responsible for adding the route from this
	// node to destination peer. we won't officially add the route until we see
	// an assemble-devices message from the peer
	updates <- a.verified.clone()

	// once this happens, we will notify all peers that we have new info? what
	// is that new info. for each peer, generate a assemble-routes message.
	// check if the assemble-routes message is different than the last one we
	// sucessfully sent to that peer. if it is different, then we should send it
	// again. remember that each peer gets a custom assemble-routes message that

	// we can make all of the routes from us on our own, via this verified
	// mapping above (we know our advertised ip, so we can make the full tuple)
	//
	// all the other routes we need to combine info from the other peers. we
	// will consider what all the peers have sent us, and filter out routes for
	// devices we haven't seen an assemble-known-devices message about. of
	// course we can include the peer itself when sending an assemble-routes to
	// that peer, since they know about themselves

	// NOTE: when you get an assemble-routes message from the other side, you
	// verify the route in the other direction

	// NOTE: consider if the below should be true
	// NOTE: when you are considering which peers to publish an update to,
	// remember to include the route that they should know from them to us

	// NOTE: should we batch updates? or at least limit to n per-second. or do
	// we update each peer on an interval? to keep us working consistently
	// rather than in bursts

	// NOTE: do we always send everything we know? we must do a backoff per-
	// client

	return nil
}

func peerAddress(ip net.IP, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

func calculateFP(conn *tls.ConnectionState) ([64]byte, error) {
	if len(conn.PeerCertificates) != 1 {
		return [64]byte{}, fmt.Errorf("exactly one peer certificate expected, got %d", len(conn.PeerCertificates))
	}

	return sha512.Sum512(conn.PeerCertificates[0].Raw), nil
}

func calculateHMAC(rdt string, fp [64]byte, secret string) []byte {
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write(fp[:])
	mac.Write([]byte(rdt))
	return mac.Sum(nil)
}

func sendCheckOK(ctx context.Context, client *http.Client, ip net.IP, port int, kind string, data any) error {
	res, err := send(ctx, client, ip, port, kind, data)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("expected status code 200, got %d", res.StatusCode)
	}

	return nil
}

func send(ctx context.Context, client *http.Client, ip net.IP, port int, kind string, data any) (*http.Response, error) {
	type message struct {
		Kind string `json:"kind"`
		any
	}

	payload, err := json.Marshal(message{
		Kind: kind,
		any:  data,
	})
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://%s:%d/v1/assemble", ip, port)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	return client.Do(req)
}

type AssembleAuth struct {
	HMAC []byte `json:"hmac"`
	RDT  string `json:"rdt"`
}

type AssembleRoutes struct {
	Devices   []string
	Addresses []string
	Routes    []int
}

func Assemble(ctx context.Context, discover Discoverer, opts AssembleOpts) error {
	if opts.ErrorHandler == nil {
		opts.ErrorHandler = func(err error) {
			log.Printf("cluster assemble error: %v\n", err)
		}
	}

	if opts.DiscoveryPeriod == 0 {
		opts.DiscoveryPeriod = time.Second * 3
	}

	discoveries, errs := peerNotifier(ctx, discover, opts.DiscoveryPeriod)
	wait := sink(errs, opts.ErrorHandler)
	defer wait()

	gossip := make(chan []UntrustedPeer)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	assembler, err := newAssembler(opts.Secret, "TODO", opts.ListenIP, opts.ListenPort)
	if err != nil {
		return err
	}
	defer assembler.stop()

outer:
	for {
		var untrusted []UntrustedPeer
		select {
		case untrusted = <-discoveries:
		case untrusted = <-gossip:
		case <-ctx.Done():
			break outer
		}

		// TODO: rather than filtering based on if we've seen it before, we
		// should filter based on if we've actually spawned a thread for this
		// peer. this will help us handle retries.
		for _, up := range untrusted {
			if err := assembler.verify(ctx, up); err != nil {
				opts.ErrorHandler(err)
			}
		}
	}

	return nil
}

func sink[T any](ch <-chan T, fn func(T)) func() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for t := range ch {
			fn(t)
		}
	}()

	return func() {
		<-done
	}
}

func peerNotifier(ctx context.Context, discover Discoverer, period time.Duration) (<-chan []UntrustedPeer, <-chan error) {
	seen := make(map[string]bool)
	filtered := func(ctx context.Context) ([]UntrustedPeer, error) {
		peers, err := discover(ctx)
		if err != nil {
			return nil, err
		}

		var copied []UntrustedPeer
		for _, p := range peers {
			addr := peerAddress(p.IP, p.Port)
			if seen[addr] {
				continue
			}

			seen[addr] = true
			copied = append(copied, p)
		}

		return copied, nil
	}

	outputs := make(chan []UntrustedPeer)
	errs := make(chan error)
	go func() {
		defer close(outputs)
		defer close(errs)

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

			peers, err := filtered(ctx)
			if err != nil {
				errs <- err
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

	return outputs, errs
}
