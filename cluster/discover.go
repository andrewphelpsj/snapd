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

	"github.com/google/uuid"
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

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for entry := range ch {
			peers = append(peers, UntrustedPeer{
				IP:   entry.AddrV4,
				Port: entry.Port,
			})
		}
	}()

	if err := mdns.QueryContext(ctx, params); err != nil {
		close(ch)
		wg.Wait()
		return nil, err
	}

	close(ch)
	wg.Wait()

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
	state *AssembleState

	client http.Client
	hmac   []byte
	server *http.Server

	lock  sync.Mutex
	peers map[FP]*peer
	wg    sync.WaitGroup

	errors func(error)
}

type graph struct {
	// devices is a mapping of device RDTs to devices.
	devices map[string]*device

	// addresses is a set of addresses involved in the cluster. This might
	// include addresses that are not an edge in the graph.
	addresses map[string]struct{}
}

type device struct {
	// rdt is the RDT of this device.
	rdt string

	// connections describes all routes that originate from this device. It is a
	// mapping of addresses to other devices.
	connections map[string]*device
}

func newGraph() *graph {
	return &graph{
		devices:   make(map[string]*device),
		addresses: make(map[string]struct{}),
	}
}

func (r *graph) add(from, to, via string) error {
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

func (r *graph) known(from, to, via string) bool {
	if _, ok := r.devices[from]; !ok {
		return false
	}

	if _, ok := r.devices[to]; !ok {
		return false
	}

	if _, ok := r.addresses[via]; !ok {
		return false
	}

	return r.devices[from].connections[via] == r.devices[to]
}

func (r *graph) merge(ar AssembleRoutes) error {
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

func (r *graph) Equals(other *graph) bool {
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

func (r *graph) clone() *graph {
	cloned := graph{
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

	return &cloned
}

func (r *graph) export() AssembleRoutes {
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

	// TODO: eventually we'll need to be able to resume the assemble process
	state := &AssembleState{
		secret:    secret,
		rdt:       rdt,
		ip:        ip,
		port:      port,
		published: make(map[FP]*graph),
		routes:    make(map[FP]*graph),
		verified:  newGraph(),
		identities: map[string]DeviceIdentity{
			rdt: {
				RDT: rdt,
			},
		},
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
		errors: func(err error) {
			log.Printf("cluster assemble error: %v\n", err)
		},
		state: state,
	}

	mux := http.NewServeMux()
	mux.Handle("/assemble/auth", http.HandlerFunc(a.handleAuth))
	mux.Handle("/assemble/routes", a.trustedHandler(a.handleRoutes))
	mux.Handle("/assemble/unknown", a.trustedHandler(a.handleUnknown))

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
	if r.TLS == nil {
		w.WriteHeader(400)
		return
	}

	peerFP, err := calculateFP(r.TLS)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	// set a max size so an untrusted peer can't send some massive JSON
	const maxAuthSize = 1024 * 4
	var aa AssembleAuth
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAuthSize)).Decode(&aa); err != nil {
		w.WriteHeader(400)
		return
	}

	expectedHMAC := calculateHMAC(aa.RDT, peerFP, a.state.Secret())
	if !hmac.Equal(expectedHMAC, aa.HMAC) {
		w.WriteHeader(403)
		return
	}

	if err := json.NewEncoder(w).Encode(AssembleAuth{
		HMAC: a.hmac,
		RDT:  a.state.RDT(),
	}); err != nil {
		w.WriteHeader(500)
		return
	}

	a.state.Trust(peerFP)
}

func (a *assembler) trustedHandler(h func(http.ResponseWriter, *http.Request, FP)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			w.WriteHeader(400)
			return
		}

		peerFP, err := calculateFP(r.TLS)
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

func (a *assembler) handleRoutes(w http.ResponseWriter, r *http.Request, peerFP FP) {
	var ar AssembleRoutes
	if err := json.NewDecoder(r.Body).Decode(&ar); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := a.state.UpdatePeerView(peerFP, ar); err != nil {
		w.WriteHeader(400)
		return
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	for fp, peer := range a.peers {
		// any new routes from this peer
		if fp == peerFP {
			continue
		}
	}

	// TODO:
	// * put routes that we know about all the devices involved into our verified
	//   routes that we will use to send peers
	// * put routes that we don't know about all the devices involved into our
	//   unverified routes
	// * store all addresses somewhere
	// * notify peer threads that they should publish updates due to a change
	//   from this peer
}

func (a *assembler) handleUnknown(w http.ResponseWriter, r *http.Request, peerFP FP) {
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

type AssembleState struct {
	secret string
	rdt    string
	ip     net.IP
	port   int

	// published keeps track of what we've sent to each peer. This must be kept
	// in the state so that we can resume updates in the case that our node
	// restarts.
	published map[FP]*graph

	// routes keeps track of the routes each peer has sent to us.
	routes map[FP]*graph

	// verified keeps track of the routes for which we know all devices involved
	// in the route.
	verified *graph

	identities map[string]DeviceIdentity

	lock sync.Mutex
}

type AssembleDevices struct {
	Devices []DeviceIdentity `json:"devices"`
}

type DeviceIdentity struct {
	RDT         string   `json:"rdt"`
	FP          FP       `json:"fp"`
	Serial      string   `json:"serial"`
	SerialProof [64]byte `json:"serial-proof"`
}

type FP = [64]byte

// TODO: is it going to be safe to store this in state? maybe when rejoining, we
// need the admin to provide the secret again?
func (as *AssembleState) Secret() string {
	return as.secret
}

func (as *AssembleState) RDT() string {
	return as.rdt
}

func (as *AssembleState) LocalAddress() string {
	return peerAddress(as.ip, as.port)
}

func (as *AssembleState) Published(fp FP, ar AssembleRoutes) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	if _, ok := as.published[fp]; !ok {
		as.published[fp] = newGraph()
	}

	return as.published[fp].merge(ar)
}

func (as *AssembleState) Unpublished(fp FP) (*graph, error) {
	as.lock.Lock()
	defer as.lock.Unlock()

	if _, ok := as.published[fp]; !ok {
		as.published[fp] = newGraph()
	}

	published := as.published[fp]
	unpublished := newGraph()

	for _, d := range as.verified.devices {
		for via, peer := range d.connections {
			if published.known(d.rdt, peer.rdt, via) {
				continue
			}

			if err := unpublished.add(d.rdt, peer.rdt, via); err != nil {
				return nil, err
			}
		}
	}

	for addr := range as.verified.addresses {
		if _, ok := published.addresses[addr]; ok {
			continue
		}

		unpublished.addresses[addr] = struct{}{}
	}

	return unpublished, nil
}

func (as *AssembleState) Trusted(fp FP) bool {
	as.lock.Lock()
	defer as.lock.Unlock()

	if _, ok := as.routes[fp]; ok {
		return true
	}
	return false
}

func (as *AssembleState) Trust(fp FP) {
	as.lock.Lock()
	defer as.lock.Unlock()

	if _, ok := as.routes[fp]; !ok {
		as.routes[fp] = newGraph()
	}
}

func (as *AssembleState) UpdatePeerView(fp FP, ar AssembleRoutes) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	g, ok := as.routes[fp]
	if !ok {
		return errors.New("cannot update unknown peer's view of cluster")
	}

	if err := g.merge(ar); err != nil {
		return err
	}

	return as.reverify()
}

// reverify updates our internal view of what routes we can publish to other
// peers. This should be called whenever we see a new set of routes from another
// peer and when we see a new set of device identities.
func (as *AssembleState) reverify() error {
	for _, g := range as.routes {
		for _, d := range g.devices {
			if _, ok := as.identities[d.rdt]; !ok {
				continue
			}

			for via, peer := range d.connections {
				if _, ok := as.identities[peer.rdt]; !ok {
					continue
				}

				if err := as.verified.add(d.rdt, peer.rdt, via); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (as *AssembleState) UpdateIdentities(ad AssembleDevices) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	var dirty bool
	for _, d := range ad.Devices {
		if known, ok := as.identities[d.RDT]; ok {
			if d != known {
				return fmt.Errorf("inconsistent knownledge of device with RDT %q", d.RDT)
			}
			continue
		}

		as.identities[d.RDT] = d
		dirty = true
	}

	// if we don't see any new peers, then we don't need to recalculate what we
	// can publish to other peers
	if dirty {
		return as.reverify()
	}
	return nil
}

func (a *assembler) verify(ctx context.Context, up UntrustedPeer) error {
	// TODO: we're doing double work here, consider first checking if we have
	// already gotten an assemble-auth from this peer, and using the trust that
	// we've already established with this peer
	res, err := sendWithResponse(ctx, &a.client, up.IP, up.Port, "auth", AssembleAuth{
		HMAC: a.hmac,
		RDT:  a.state.RDT(),
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

	// set a max size so an untrusted peer can't send some massive JSON
	const maxAuthSize = 1024 * 4
	var auth AssembleAuth
	if err := json.NewDecoder(io.LimitReader(res.Body, maxAuthSize)).Decode(&auth); err != nil {
		return err
	}

	expectedHMAC := calculateHMAC(auth.RDT, peerFP, a.state.Secret())
	if !hmac.Equal(expectedHMAC, auth.HMAC) {
		return errors.New("received invalid HMAC from peer")
	}

	a.state.Trust(peerFP)

	a.lock.Lock()
	defer a.lock.Unlock()

	a.peers[peerFP] = newPeer(a.state, peerFP, auth.RDT, up.IP, up.Port)

	return nil
}

type peer struct {
	state   *AssembleState
	publish chan struct{}
	wg      sync.WaitGroup
	errors  func(error)
}

func newPeer(state *AssembleState, fp FP, rdt string, ip net.IP, port int) *peer {
	p := &peer{
		state:   state,
		publish: make(chan struct{}, 1024),
	}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(certs [][]byte, chains [][]*x509.Certificate) error {
					if len(certs) != 1 {
						return fmt.Errorf("exactly one peer certificate expected, got %d", len(certs))
					}

					if sha512.Sum512(certs[0]) != fp {
						return errors.New("refusing to communicate with unexpected peer certificate")
					}
					return nil
				},
			},
			// TODO: configure the client to use this device's TLS certs
		},
		Timeout: time.Second * 10,
	}

	// one thread will be responsible for sending assemble-routes
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		backoff := time.Millisecond * 500
		retry := false
		for {
			if retry {
				select {
				case _, ok := <-p.publish:
					if !ok {
						return
					}
				case <-time.After(backoff):
					retry = false
					backoff = min(backoff*2, time.Second*30)
				}
			} else {
				_, ok := <-p.publish
				if !ok {
					return
				}
			}

			unpublished, err := state.Unpublished(fp)
			if err != nil {
				p.errors(err)
				continue
			}

			// manually add the route from this peer to the receiving peer as a
			// special case. this is a special case, since we might not have
			// seen an assemble-devices message that includes the receiving peer
			if err := unpublished.add(state.RDT(), rdt, peerAddress(ip, port)); err != nil {
				p.errors(err)
				continue
			}

			// similarly, make sure that the route back to this node is always
			// present, even if it might not be involved in any of the routes we
			// are sending
			unpublished.addresses[state.LocalAddress()] = struct{}{}

			msg := unpublished.export()
			if err := send(context.Background(), &client, ip, port, "routes", unpublished.export()); err != nil {
				retry = true
				p.errors(err)
				continue
			}

			// a successful update resets the retry backoff
			backoff = time.Millisecond * 500

			if err := state.Published(fp, msg); err != nil {
				p.errors(err)
			}
		}
	}()

	p.publish <- struct{}{}

	// one thread will be responsible for sending assemble-unknown-devices.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
	}()

	// NOTE: whenever someone sends me an assemble-routes, i need to keep a copy
	// of exactly that. that is the only way i can know about who knows about
	// who, and who i should ask about unknown devices

	return p
}

func (p *peer) stop() {
	close(p.publish)
	p.wg.Wait()
}

func peerAddress(ip net.IP, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

func newRDT() (string, error) {
	uid, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return uid.String(), nil
}

func calculateFP(conn *tls.ConnectionState) (FP, error) {
	if len(conn.PeerCertificates) != 1 {
		return FP{}, fmt.Errorf("exactly one peer certificate expected, got %d", len(conn.PeerCertificates))
	}

	return sha512.Sum512(conn.PeerCertificates[0].Raw), nil
}

func calculateHMAC(rdt string, fp FP, secret string) []byte {
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write(fp[:])
	mac.Write([]byte(rdt))
	return mac.Sum(nil)
}

func send(ctx context.Context, client *http.Client, ip net.IP, port int, kind string, data any) error {
	res, err := sendWithResponse(ctx, client, ip, port, kind, data)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("expected status code 200, got %d", res.StatusCode)
	}

	return nil
}

func sendWithResponse(ctx context.Context, client *http.Client, ip net.IP, port int, kind string, data any) (*http.Response, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://%s:%d/v1/assemble/%s", ip, port, kind)
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
	Devices   []string `json:"devices"`
	Addresses []string `json:"addresses"`
	Routes    []int    `json:"routes"`
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

	discoveries := peerNotifier(ctx, discover, opts.DiscoveryPeriod, opts.ErrorHandler)

	gossip := make(chan []UntrustedPeer)

	// TODO: eventually, this will be lazy-initialized into the state we pass in
	rdt, err := newRDT()
	if err != nil {
		return err
	}

	assembler, err := newAssembler(opts.Secret, rdt, opts.ListenIP, opts.ListenPort)
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

func peerNotifier(ctx context.Context, discover Discoverer, period time.Duration, errors func(error)) <-chan []UntrustedPeer {
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
	go func() {
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

			peers, err := filtered(ctx)
			if err != nil {
				errors(err)
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

	return outputs
}
