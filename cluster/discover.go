package cluster

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	// TODO: we could patch that if we do fork this library
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

type TrustedPeer struct {
	RDT  string
	IP   net.IP
	Port int
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
	secret string
	host   string
	me     TrustedPeer

	lock sync.Mutex

	// trusted is a mapping of verifed peer RDTs to a [TrustedPeer] that describes that
	// peer. This will be used to verify incoming messages from trusted.
	trusted map[string]TrustedPeer

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

	peers []chan<- AssembleRoutes
	wg    sync.WaitGroup

	errors func(error)
}

type routes struct {
	devices   []string
	addresses []string
	routes    []route
}

type route struct {
	from string
	via  string
	to   string
}

func (r *routes) addRoute(rt route) {
	if !contains(r.devices, rt.from) {
		r.devices = append(r.devices, rt.from)
	}

	if !contains(r.devices, rt.to) {
		r.devices = append(r.devices, rt.to)
	}

	if !contains(r.addresses, rt.via) {
		r.addresses = append(r.addresses, rt.via)
	}

	if !contains(r.routes, rt) {
		r.routes = append(r.routes, rt)
	}
}

func (r *routes) addAddress(addr string) {
	if !contains(r.addresses, addr) {
		r.addresses = append(r.addresses, addr)
	}
}

func (r *routes) export() AssembleRoutes {
	devices := sort.StringSlice(r.devices)
	addresses := sort.StringSlice(r.addresses)

	var routes []int
	for _, rt := range r.routes {
		routes = append(routes, []int{
			sort.SearchStrings(devices, rt.from),
			sort.SearchStrings(devices, rt.to),
			sort.SearchStrings(addresses, rt.via),
		}...)
	}

	return AssembleRoutes{
		Devices:   devices,
		Addresses: addresses,
		Routes:    routes,
	}
}

func (r *routes) merge(ar AssembleRoutes) error {
	if len(ar.Routes)%3 != 0 {
		return errors.New("length of routes list in assemble-routes must be a multiple of three")
	}

	var routes []route
	for i := 0; i+2 < len(ar.Routes); i += 3 {
		if ar.Routes[i] < 0 || ar.Routes[i+1] < 0 || ar.Routes[i+2] < 0 {
			return errors.New("invalid index in assemble-routes")
		}

		if ar.Routes[i] > len(ar.Devices) || ar.Routes[i+1] > len(ar.Devices) || ar.Routes[i+2] > len(ar.Addresses) {
			return errors.New("invalid index in assemble-routes")
		}

		routes = append(routes, route{
			from: ar.Devices[ar.Routes[i]],
			to:   ar.Devices[ar.Routes[i+1]],
			via:  ar.Addresses[ar.Routes[i+2]],
		})
	}

	// TODO: consider if this is actually what we want to do here
	for _, other := range routes {
		for _, rt := range r.routes {
			if rt.from == other.from && rt.to == other.to && rt.via != other.via {
				return fmt.Errorf(
					"route inconsistency found: %s -> %s via both %s and %s",
					rt.from,
					rt.to,
					rt.via,
					other.via,
				)
			}
		}
	}

	for _, rt := range routes {
		r.addRoute(rt)
	}

	return nil
}

func contains[S ~[]E, E comparable](s S, v E) bool {
	return slices.Contains(s, v)
}

func newAssembler(secret string, rdt string, ip net.IP, port int) *assembler {
	return &assembler{
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
		me: TrustedPeer{
			IP:   ip,
			Port: port,
			RDT:  rdt,
		},
		secret:  secret,
		trusted: make(map[string]TrustedPeer),
	}
}

func (a *assembler) stop() {
	a.lock.Lock()
	defer a.lock.Unlock()

	for _, ch := range a.peers {
		close(ch)
	}

	a.wg.Wait()
}

func (a *assembler) trust(ctx context.Context, up UntrustedPeer) error {
	res, err := send(ctx, &a.client, up.IP, up.Port, "assemble-auth", AssembleAuth{
		HMAC: []byte("TODO"),
		RDT:  a.me.RDT,
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

	// TODO: check that these don't already exist and handle those conflicts
	peer := TrustedPeer{
		RDT:  auth.RDT,
		IP:   up.IP,
		Port: up.Port,
	}
	a.trusted[auth.RDT] = peer

	updates := make(chan AssembleRoutes, 1024)
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()

		// var previous AssembleRoutes
		var pending *AssembleRoutes
		backoff := time.Second

		for {
			var update AssembleRoutes
			if pending != nil {
				select {
				case u, ok := <-updates:
					if !ok {
						return
					}
					update = u
				case <-time.After(backoff):
					update = *pending
				}
				pending = nil
			} else {
				u, ok := <-updates
				if !ok {
					return
				}
				update = u
			}

			// make sure that we include the route from this node to the peer
			ensureRoute(&update, a.me, peer)

			if err := sendNoResponse(ctx, &a.client, peer.IP, peer.Port, "assemble-routes", update); err != nil {
				if a.errors != nil {
					a.errors(err)
				}

				pending = &update
				backoff = min(backoff*2, time.Minute)
				continue
			}

			// previous = update
			backoff = time.Second
		}
	}()

	a.peers = append(a.peers, updates)

	// the first update here might be entirely empty, but the thread interfacing
	// with the peer is responsible for adding the route from this node to
	// destination peer
	updates <- a.verified.export()

	// once this happens, we will notify all peers that we have new info? what
	// is that new info. for each peer, generate a assemble-routes message.
	// check if the assemble-routes message is different than the last one we
	// sucessfully sent to that peer. if it is different, then we should send it
	// again. remember that each peer gets a custom assemble-routes message that

	// we can make all of the routes from us on our own, via this verified
	// mapping above (we know our advertised ip, so we can make the full tuple)
	//
	// all the other routes we need to combine info from the other peers.
	// we will consider what all the peers have sent us, and filter out routes
	// for devices we haven't seen an assemble-known-devices message about. of
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

func ensureRoute(ar *AssembleRoutes, src TrustedPeer, dest TrustedPeer) {
	var srcIndex int
	if i := slices.Index(ar.Devices, src.RDT); i >= 0 {
		srcIndex = i
	} else {
		ar.Devices = append(ar.Devices, src.RDT)
		srcIndex = len(ar.Devices) - 1
	}

	var destIndex int
	if i := slices.Index(ar.Devices, dest.RDT); i >= 0 {
		destIndex = i
	} else {
		ar.Devices = append(ar.Devices, dest.RDT)
		destIndex = len(ar.Devices) - 1
	}

	destAddress := peerAddress(dest.IP, dest.Port)
	var routeIndex int
	if i := slices.Index(ar.Addresses, destAddress); i >= 0 {
		routeIndex = i
	} else {
		ar.Addresses = append(ar.Addresses, destAddress)
		routeIndex = len(ar.Addresses) - 1
	}

	srcAddress := peerAddress(src.IP, src.Port)
	if !slices.Contains(ar.Addresses, srcAddress) {
		ar.Addresses = append(ar.Addresses, srcAddress)
	}

	srcToDest := []int{srcIndex, destIndex, routeIndex}
	for i := 0; i+2 < len(ar.Routes); i += 3 {
		route := []int{ar.Routes[i], ar.Routes[i+1], ar.Routes[i+2]}
		if slices.Equal(route, srcToDest) {
			return
		}
	}

	ar.Routes = append(ar.Routes, srcToDest...)
}

func peerAddress(ip net.IP, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

func calculateFP(conn *tls.ConnectionState) ([]byte, error) {
	if len(conn.PeerCertificates) != 1 {
		return nil, fmt.Errorf("exactly one peer certificate expected, got %d", len(conn.PeerCertificates))
	}

	hash := sha512.Sum512(conn.PeerCertificates[0].Raw)
	return bytes.Clone(hash[:]), nil
}

func calculateHMAC(rdt string, fp []byte, secret string) []byte {
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write(fp)
	mac.Write([]byte(rdt))
	return mac.Sum(nil)
}

func sendNoResponse(ctx context.Context, client *http.Client, ip net.IP, port int, kind string, data any) error {
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

func (a AssembleRoutes) clone() AssembleRoutes {
	devices := make([]string, len(a.Devices))
	copy(devices, a.Devices)

	addresses := make([]string, len(a.Addresses))
	copy(addresses, a.Addresses)

	routes := make([]int, len(a.Routes))
	copy(routes, a.Routes)

	return AssembleRoutes{
		Devices:   devices,
		Addresses: addresses,
		Routes:    routes,
	}
}

func Assemble(ctx context.Context, discover Discoverer, opts AssembleOpts) ([]TrustedPeer, error) {
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

	assembler := newAssembler(opts.Secret, "TODO", opts.ListenIP, opts.ListenPort)
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

		for _, up := range untrusted {
			if err := assembler.trust(ctx, up); err != nil {
				opts.ErrorHandler(err)
			}
		}
	}

	return nil, nil
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
