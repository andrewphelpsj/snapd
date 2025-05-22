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
	"slices"
	"sort"
	"sync"
	"time"

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
	state  *AssembleState
	server *http.Server
	lock   sync.Mutex
	peers  map[FP]*peer
	wg     sync.WaitGroup
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

func (r *graph) connect(from, to, via string) error {
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

func (r *graph) add(ar AssembleRoutes) error {
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

		if err := r.connect(
			ar.Devices[ar.Routes[i]],
			ar.Devices[ar.Routes[i+1]],
			ar.Addresses[ar.Routes[i+2]],
		); err != nil {
			return err
		}
	}

	return nil
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

	fp := calculateFP(cert.Certificate[0])

	// TODO: eventually, we'll need to be able to resume the assemble process
	state := &AssembleState{
		secret:   secret,
		rdt:      rdt,
		ip:       ip,
		port:     port,
		views:    make(map[FP]*graph),
		verified: newGraph(),
		identities: map[string]DeviceIdentity{
			rdt: {
				RDT: rdt,
				FP:  fp,
			},
		},
		queries: make(map[FP]map[string]struct{}),
		hmac:    calculateHMAC(rdt, fp, secret),
	}

	addr := peerAddress(ip, port)
	a := assembler{
		errors: func(err error) {
			log.Printf("cluster assemble error: %v\n", err)
		},
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
		w.WriteHeader(400)
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
		HMAC: a.state.HMAC(),
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

func (a *assembler) handleRoutes(w http.ResponseWriter, r *http.Request, peerFP FP) {
	if r.Method != "POST" {
		w.WriteHeader(400)
		return
	}

	var ar AssembleRoutes
	if err := json.NewDecoder(r.Body).Decode(&ar); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := a.state.RecordPeerRoutes(peerFP, ar); err != nil {
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
		peer.publish <- struct{}{}
	}
}

func (a *assembler) handleUnknown(w http.ResponseWriter, r *http.Request, peerFP FP) {
	if r.Method != "POST" {
		w.WriteHeader(400)
		return
	}

	var au AssembleUnknownDevices
	if err := json.NewDecoder(r.Body).Decode(&au); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := a.state.RecordPeerDeviceQueries(peerFP, au.Devices); err != nil {
		w.WriteHeader(400)
		return
	}

	if p, ok := a.peers[peerFP]; ok {
		p.query <- struct{}{}
	}
}

func (a *assembler) handleDevices(w http.ResponseWriter, r *http.Request, peerFP FP) {
	if r.Method != "POST" {
		w.WriteHeader(400)
		return
	}

	var ad AssembleDevices
	if err := json.NewDecoder(r.Body).Decode(&ad); err != nil {
		w.WriteHeader(400)
		return
	}

	if err := a.state.RecordIdentities(ad); err != nil {
		w.WriteHeader(400)
		return
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	for fp, p := range a.peers {
		if fp == peerFP {
			continue
		}

		p.publish <- struct{}{}
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

type AssembleState struct {
	secret string
	rdt    string
	hmac   []byte
	ip     net.IP
	port   int

	// fields below this are mutated from multiple threads, and must be accessed
	// with the lock held.
	lock sync.Mutex

	// views keeps track of what the local node believes each peer knows of the
	// cluster. This information is a combination of routes that we have
	// successfully sent each peer and the routes that each peer has sent us.
	//
	// We use this information to help us keep track of what new information
	// needs to be published to each peer, and it is also used to determine
	// which peer should be queried for identifying device information.
	views map[FP]*graph

	// queries keeps track of device queries that we've gotten from each peer.
	queries map[FP]map[string]struct{}

	// verified keeps track of the routes for which we have identifying
	// information for both devices involved in the route. The routes here can
	// be safely published to other peers.
	verified *graph

	// identities keeps track of device identities that we've received from
	// other trusted peers.
	identities map[string]DeviceIdentity
}

// PeerView returns a [PeerView], which can be used to fetch and record
// information about what this local node believes the given peer knows about
// the cluster.
func (as *AssembleState) PeerView(fp FP, rdt string, ip net.IP, port int) (*PeerView, error) {
	if _, ok := as.views[fp]; !ok {
		return nil, errors.New("peer is not trusted")
	}

	return &PeerView{
		as:   as,
		fp:   fp,
		rdt:  rdt,
		ip:   ip,
		port: port,
	}, nil
}

// PeerView provides a view into [AssembleState], providing access to what the
// peer that this structure represents knows about the cluster.
type PeerView struct {
	as   *AssembleState
	rdt  string
	ip   net.IP
	port int
	fp   FP
}

// UnidentifiedDevices returns a list of RDTs that our local node does not know
// about, but this peer should have identifying information for.
func (pv *PeerView) UnidentifiedDevices() []string {
	pv.as.lock.Lock()
	defer pv.as.lock.Unlock()

	var unknown []string
	for _, d := range pv.as.views[pv.fp].devices {
		if _, ok := pv.as.identities[d.rdt]; !ok {
			unknown = append(unknown, d.rdt)
		}
	}

	return unknown
}

// UnknownRoutes returns routes that our local node has verified, but this peer
// does not yet have knowledge of. All routes returned will only contain devices
// that the local node has seen an assemble-devices message for.
func (pv *PeerView) UnknownRoutes() (*graph, error) {
	pv.as.lock.Lock()
	defer pv.as.lock.Unlock()

	known := pv.as.views[pv.fp]
	unknown := newGraph()

	for _, d := range pv.as.verified.devices {
		for via, peer := range d.connections {
			if known.known(d.rdt, peer.rdt, via) {
				continue
			}

			if err := unknown.connect(d.rdt, peer.rdt, via); err != nil {
				return nil, err
			}
		}
	}

	for addr := range pv.as.verified.addresses {
		if _, ok := known.addresses[addr]; ok {
			continue
		}

		unknown.addresses[addr] = struct{}{}
	}

	// manually add the route from this peer to the receiving peer. this is a
	// special case, since we might not have seen an assemble-devices message
	// that includes this peer
	if err := unknown.connect(pv.as.rdt, pv.rdt, peerAddress(pv.ip, pv.port)); err != nil {
		return nil, err
	}

	// similarly, make sure that the route back to our node is always present,
	// even if it might not be involved in any of the routes we are sending
	unknown.addresses[peerAddress(pv.as.ip, pv.as.port)] = struct{}{}

	return unknown, nil
}

// AckRoutes updates this peer's view of the cluster, adding the given routes to
// this peer's set of known routes. This should be called once we successfully
// publish the given information to this peer.
func (pv *PeerView) AckRoutes(ar AssembleRoutes) error {
	pv.as.lock.Lock()
	defer pv.as.lock.Unlock()

	if err := pv.as.views[pv.fp].add(ar); err != nil {
		return err
	}

	return nil
}

// UnknownDevices returns a list of device identities that this peer has
// requested information for. Any devices that this local node doesn't know
// about are skipped.
func (pv *PeerView) UnknownDevices() ([]DeviceIdentity, error) {
	pv.as.lock.Lock()
	defer pv.as.lock.Unlock()

	devices := make([]DeviceIdentity, 0, len(pv.as.queries[pv.fp]))
	for rdt := range pv.as.queries[pv.fp] {
		id, ok := pv.as.identities[rdt]
		if !ok {
			continue
		}
		devices = append(devices, id)
	}

	return devices, nil
}

// AckDevices removes the given devices from the set of devices that this peer
// has requested information for. This should be called once we've successfully
// sent the given devices to this peer.
func (pv *PeerView) AckDevices(devices []DeviceIdentity) {
	pv.as.lock.Lock()
	defer pv.as.lock.Unlock()

	for _, d := range devices {
		delete(pv.as.queries[pv.fp], d.RDT)
	}
}

// Address returns the address of this peer.
func (pv *PeerView) Address() string {
	return peerAddress(pv.ip, pv.port)
}

// FP returns the TLS certificate fingerprint that is associated with this peer.
func (pv *PeerView) FP() FP {
	return pv.fp
}

// TODO: is it going to be safe to store this in state? maybe when rejoining, we
// need the admin to provide the secret again?
func (as *AssembleState) Secret() string {
	return as.secret
}

// RDT returns the RDT that this local node is using.
func (as *AssembleState) RDT() string {
	return as.rdt
}

// HMAC returns the HMAC that this local node should use in assemble-auth
// messages.
func (as *AssembleState) HMAC() []byte {
	return as.hmac
}

// Trusted returns true if the given TLS certificate fingerprint has already
// been associated with a device that we have established trust with, via the
// shared secret.
func (as *AssembleState) Trusted(fp FP) bool {
	as.lock.Lock()
	defer as.lock.Unlock()

	if _, ok := as.views[fp]; ok {
		return true
	}
	return false
}

// Trust indicates that we can trust the device using the given TLS certificate
// fingerprint.
func (as *AssembleState) Trust(fp FP) {
	as.lock.Lock()
	defer as.lock.Unlock()

	if _, ok := as.views[fp]; !ok {
		as.views[fp] = newGraph()
	}
}

// RecordPeerDeviceQueries adds the given devices to the queue of queries
// originating from the device associated with the given TLS certificate
// fingerprint. If any devices are unknown, no devices are added to the queue
// and an error is returned. If this local node is queried for devices that we
// do not know, either this local node or the requesting peer has a bug.
func (as *AssembleState) RecordPeerDeviceQueries(fp FP, devices []string) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	if _, ok := as.views[fp]; !ok {
		return errors.New("peer is untrusted")
	}

	for _, rdt := range devices {
		if _, ok := as.identities[rdt]; !ok {
			return fmt.Errorf("unknown device: %s", rdt)
		}
	}

	if _, ok := as.queries[fp]; !ok {
		as.queries[fp] = make(map[string]struct{})
	}

	for _, rdt := range devices {
		as.queries[fp][rdt] = struct{}{}
	}

	return nil
}

// RecordPeerRoutes updates our view of what the device associated with the
// given TLS fingerprint knows about the cluster. Additionally we recalculate
// our view of the verified routes in the cluster.
func (as *AssembleState) RecordPeerRoutes(fp FP, ar AssembleRoutes) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	g, ok := as.views[fp]
	if !ok {
		return errors.New("peer is untrusted")
	}

	if err := g.add(ar); err != nil {
		return err
	}

	return as.reverify()
}

// RecordIdentities records the given device identities. All new device
// identities are added. For any devices that we are already aware of, we check
// that our view of the device's identity is consistent with the new data.
func (as *AssembleState) RecordIdentities(ad AssembleDevices) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	var dirty bool
	for _, d := range ad.Devices {
		if known, ok := as.identities[d.RDT]; ok {
			if d != known {
				return fmt.Errorf("inconsistent knowledge of device with RDT %q", d.RDT)
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

// reverify updates our internal view of what routes we can publish to other
// peers. This should be called whenever we see a new set of routes from another
// peer and when we see a new set of device identities.
func (as *AssembleState) reverify() error {
	for _, g := range as.views {
		for _, d := range g.devices {
			if _, ok := as.identities[d.rdt]; !ok {
				continue
			}

			for via, peer := range d.connections {
				if _, ok := as.identities[peer.rdt]; !ok {
					continue
				}

				if err := as.verified.connect(d.rdt, peer.rdt, via); err != nil {
					return err
				}
			}
		}
	}
	return nil
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

	res, err := sendWithResponse(ctx, &client, peerAddress(up.IP, up.Port), "auth", AssembleAuth{
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
	var auth AssembleAuth
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

	a.peers[peerFP] = newPeer(
		a.server.TLSConfig.Certificates[0],
		pv,
	)

	return nil
}

type peer struct {
	publish chan struct{}
	query   chan struct{}
	inform  chan struct{}
	wg      sync.WaitGroup
	errors  func(error)
}

func newPeer(cert tls.Certificate, pv *PeerView) *peer {
	p := &peer{
		publish: make(chan struct{}, 1024),
		query:   make(chan struct{}, 1024),
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

			unknown, err := pv.UnknownRoutes()
			if err != nil {
				p.errors(err)
				continue
			}

			msg := unknown.export()
			if err := send(context.Background(), &client, pv.Address(), "routes", unknown.export()); err != nil {
				retry = true
				p.errors(err)
				continue
			}
			backoff = time.Millisecond * 500

			if err := pv.AckRoutes(msg); err != nil {
				p.errors(err)
				continue
			}
		}
	}()
	p.publish <- struct{}{}

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

			devices := pv.UnidentifiedDevices()
			if len(devices) == 0 {
				continue
			}

			if err := send(context.Background(), &client, pv.Address(), "unknown", AssembleUnknownDevices{
				Devices: devices,
			}); err != nil {
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

			devices, err := pv.UnknownDevices()
			if err != nil {
				p.errors(err)
				continue
			}

			if len(devices) == 0 {
				retry = false
				continue
			}

			if err := send(context.Background(), &client, pv.Address(), "devices", AssembleDevices{
				Devices: devices,
			}); err != nil {
				retry = true
				p.errors(err)
				continue
			}
			backoff = time.Millisecond * 500

			pv.AckDevices(devices)
		}
	}()
	p.inform <- struct{}{}

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

func calculateFP(cert []byte) FP {
	return sha512.Sum512(cert)
}

func calculatePeerFP(conn *tls.ConnectionState) (FP, error) {
	if len(conn.PeerCertificates) != 1 {
		return FP{}, fmt.Errorf("exactly one peer certificate expected, got %d", len(conn.PeerCertificates))
	}

	return calculateFP(conn.PeerCertificates[0].Raw), nil
}

func calculateHMAC(rdt string, fp FP, secret string) []byte {
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

type AssembleAuth struct {
	HMAC []byte `json:"hmac"`
	RDT  string `json:"rdt"`
}

type AssembleUnknownDevices struct {
	Devices []string `json:"devices"`
}

type AssembleRoutes struct {
	Devices   []string `json:"devices"`
	Addresses []string `json:"addresses"`
	Routes    []int    `json:"routes"`
}

type AssembleDevices struct {
	Devices []DeviceIdentity `json:"devices"`
}

type (
	FP    [64]byte
	Proof [64]byte
)

type DeviceIdentity struct {
	RDT string `json:"rdt"`
	FP  FP     `json:"fp"`

	// TODO: we're not using these yet
	Serial      string `json:"serial"`
	SerialProof Proof  `json:"serial-proof"`
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

	// TODO: eventually, this will be lazy-initialized from the state we pass in
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
