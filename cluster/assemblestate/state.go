package assemblestate

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"sort"
	"sync"

	"github.com/google/uuid"
)

type Auth struct {
	HMAC []byte `json:"hmac"`
	RDT  RDT    `json:"rdt"`
}

type UnknownDevices struct {
	Devices []RDT `json:"devices"`
}

type Routes struct {
	Devices   []RDT    `json:"devices"`
	Addresses []string `json:"addresses"`
	Routes    []int    `json:"routes"`
}

type Edge struct {
	From RDT
	To   RDT
	Via  string
}

type Devices struct {
	Devices []Identity `json:"devices"`
}

type (
	FP    [64]byte
	Proof [64]byte
	RDT   string
)

type Identity struct {
	RDT RDT `json:"rdt"`
	FP  FP  `json:"fp"`

	// TODO: we're not using these yet, but we eventually will
	Serial      string `json:"serial"`
	SerialProof Proof  `json:"serial-proof"`
}

func NewRDT() (RDT, error) {
	uid, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return RDT(uid.String()), nil
}

// ClusterView contains this device's knowledge of the state of an assembly
// session. Eventually, this'll read and write from a state.State instance. That
// is why some things are methods when they really don't need to be.
type ClusterView struct {
	secret string
	rdt    RDT
	hmac   []byte
	ip     net.IP
	port   int
	cert   tls.Certificate

	// fields below this are mutated from multiple threads, and must be accessed
	// with the lock held.
	lock sync.Mutex

	// trusted keeps track of TLS fingerprints that we can trust, and which RDT
	// they are associated with.
	trusted map[FP]RDT

	// addresses keeps track of which address we can reach each device at. We
	// can trust a peer and start receiving their information before we have
	// their address, but we cannot publish data to them.
	addresses map[RDT]string

	// tracker helps keep track of routes and device identities. Specifically,
	// it keeps track of which routes have been published to each peer.
	tracker RouteTracker

	// queries keeps track of the requests for device information from each
	// peers. It is a mapping of requester RDT -> set of requested RDTs.
	queries map[RDT]map[RDT]struct{}
}

func NewClusterView(secret string, rdt RDT, ip net.IP, port int, cert tls.Certificate) (*ClusterView, error) {
	if len(cert.Certificate) != 1 {
		return nil, fmt.Errorf("exactly one certificate expected, got %d", len(cert.Certificate))
	}

	fp := calculateFP(cert.Certificate[0])

	tracker := NewRouteTracker()

	// we know ourselves, add that immediately
	tracker.RecordIdentities([]Identity{{
		RDT: rdt,
		FP:  fp,
	}})

	return &ClusterView{
		secret:    secret,
		rdt:       rdt,
		ip:        ip,
		port:      port,
		cert:      cert,
		hmac:      calculateHMAC(rdt, fp, secret),
		trusted:   make(map[FP]RDT),
		addresses: make(map[RDT]string),
		queries:   make(map[RDT]map[RDT]struct{}),
		tracker:   tracker,
	}, nil
}

func (cv *ClusterView) Export() Routes {
	cv.lock.Lock()
	defer cv.lock.Unlock()

	return EdgesToRoutes(cv.tracker.VerifiedEdges(), true)
}

// Auth returns the [Auth] message that we should send to other peers to prove
// our knowledge of the shared secret.
func (cv *ClusterView) Auth() Auth {
	return Auth{
		HMAC: bytes.Clone(cv.hmac),
		RDT:  cv.rdt,
	}
}

// Address returns the address of this local node.
func (cv *ClusterView) Address() string {
	return peerAddress(cv.ip, cv.port)
}

// Cert returns the TLS certificate that this local node should use when
// communicating with other peers.
func (cv *ClusterView) Cert() tls.Certificate {
	return cv.cert
}

// Trusted checks if the given certificate is trusted and maps to a known RDT.
// If it is, then a [PeerView] is returned that can be used to modify the state
// of the cluster on this peer's behalf.
//
// An error is returned if the certificate isn't trusted.
func (cv *ClusterView) Trusted(cert []byte) (*PeerView, error) {
	cv.lock.Lock()
	defer cv.lock.Unlock()

	fp := calculateFP(cert)

	rdt, ok := cv.trusted[fp]
	if !ok {
		return nil, errors.New("given TLS certificate is not associated with a trusted RDT")
	}

	return &PeerView{
		rdt:  rdt,
		cert: cert,
		cv:   cv,
	}, nil
}

// Authenticate checks that the given [Auth] message is valid and proves
// knowledge of the shared secert. If this check is passed, this [ClusterView]
// will start accepting updates that are associated with the given RDT. An error
// is returned if the message's HMAC is found to be invalid.
//
// On success, a [PeerView] is returned that can be used to modify the state of
// the cluster on this peer's behalf.
func (cv *ClusterView) Authenticate(auth Auth, cert []byte, address string) (*PeerView, error) {
	cv.lock.Lock()
	defer cv.lock.Unlock()

	fp := calculateFP(cert)

	expectedHMAC := calculateHMAC(auth.RDT, fp, cv.secret)
	if !hmac.Equal(expectedHMAC, auth.HMAC) {
		return nil, errors.New("received invalid HMAC from peer")
	}

	if _, ok := cv.trusted[fp]; ok {
		if cv.trusted[fp] != auth.RDT {
			return nil, fmt.Errorf("peer with rdt %v is using a new TLS certificate", auth.RDT)
		}
	} else {
		cv.trusted[fp] = auth.RDT
	}

	// TODO: this kinda sucks, is it possible that assemble-auth could contain
	// the return address?
	if address != "" {
		cv.addresses[auth.RDT] = address
	}

	if _, ok := cv.queries[auth.RDT]; !ok {
		cv.queries[auth.RDT] = make(map[RDT]struct{})
	}

	return &PeerView{
		rdt:  auth.RDT,
		cert: cert,
		cv:   cv,
	}, nil
}

// PeerView provides a peer's view into [ClusterView], providing access to what
// we think this peer knows about the cluster. Having one of these proves that
// this peer has provided proof that it knows the shared secret.
type PeerView struct {
	rdt  RDT
	cert []byte
	cv   *ClusterView
}

// RecordDeviceQueries adds the given devices to the queue of queries for this
// peer. If any devices are unknown, no devices are added to the queue and an
// error is returned. If this local node is queried for devices that we do not
// know, either this local node or the requesting peer has a bug.
func (pv *PeerView) RecordDeviceQueries(unknown UnknownDevices) error {
	pv.cv.lock.Lock()
	defer pv.cv.lock.Unlock()

	for _, rdt := range unknown.Devices {
		if _, ok := pv.cv.tracker.DeviceID(rdt); !ok {
			return fmt.Errorf("unknown device: %s", rdt)
		}
	}

	for _, rdt := range unknown.Devices {
		pv.cv.queries[pv.rdt][rdt] = struct{}{}
	}

	return nil
}

// RecordRoutes updates the state of the cluster with the given routes.
func (pv *PeerView) RecordRoutes(routes Routes) error {
	pv.cv.lock.Lock()
	defer pv.cv.lock.Unlock()

	edges, err := RoutesToEdges(routes)
	if err != nil {
		return err
	}

	pv.cv.tracker.RecordEdges(pv.rdt, edges)

	return nil
}

// RecordIdentities records the given device identities. All new device
// identities are recorded. For any devices that we are already aware of, we
// check that our view of the device's identity is consistent with the new data.
func (pv *PeerView) RecordIdentities(devices Devices) error {
	pv.cv.lock.Lock()
	defer pv.cv.lock.Unlock()

	return pv.cv.tracker.RecordIdentities(devices.Devices)
}

// IdentifiableDevices returns the devices that our local node does not know
// about, but this peer should have identifying information for.
//
// TODO: This could use name that is more clear.
func (pv *PeerView) IdentifiableDevices() UnknownDevices {
	pv.cv.lock.Lock()
	defer pv.cv.lock.Unlock()

	return UnknownDevices{
		Devices: pv.cv.tracker.UnknownDevicesKnownBy(pv.rdt),
	}
}

// UnknownRoutes returns routes that our local node has verified, but this peer
// does not yet have knowledge of. All routes returned will only contain devices
// that the local node has seen an assemble-devices message for.
func (pv *PeerView) UnknownRoutes() (Routes, error) {
	pv.cv.lock.Lock()
	defer pv.cv.lock.Unlock()

	// we set a cap on the number of known routes that we'll report, for a
	// couple reasons. this limits what a newly joined peer might see.
	// additionally, it helps us limit how much memory we're using at any one
	// time.
	unknown := pv.cv.tracker.UnknownEdges(pv.rdt, 5000)

	addr, ok := pv.cv.addresses[pv.rdt]
	if !ok {
		return Routes{}, fmt.Errorf("unable to list unknown routes for peer %q with undiscovered address", pv.rdt)
	}

	// manually add the route from the local node to the receiving peer. this is
	// a special case, since we might not have seen an assemble-devices message
	// that includes this peer
	outbound := Edge{From: pv.cv.rdt, To: pv.rdt, Via: addr}
	if !pv.cv.tracker.KnowsEdge(pv.rdt, outbound) {
		unknown = append(unknown, outbound)
	}

	// TODO: add extra addresses here, will be treated by the peer as
	// "discovered" devices.

	return EdgesToRoutes(unknown, false), nil
}

// AckRoutes updates this peer's view of the cluster, adding the given routes to
// this peer's set of known routes. This should be called once we successfully
// publish the given information to this peer.
func (pv *PeerView) AckRoutes(routes Routes) error {
	pv.cv.lock.Lock()
	defer pv.cv.lock.Unlock()

	edges, err := RoutesToEdges(routes)
	if err != nil {
		return nil
	}

	return pv.cv.tracker.MarkSentEdges(pv.rdt, edges)
}

// UnknownDevices returns a list of device identities that this peer has
// requested information for. Any devices that this local node doesn't know
// about are skipped.
func (pv *PeerView) UnknownDevices() (Devices, error) {
	pv.cv.lock.Lock()
	defer pv.cv.lock.Unlock()

	devices := make([]Identity, 0, len(pv.cv.queries[pv.rdt]))
	for rdt := range pv.cv.queries[pv.rdt] {
		id, ok := pv.cv.tracker.DeviceID(rdt)
		if !ok {
			continue
		}
		devices = append(devices, id)
	}

	return Devices{Devices: devices}, nil
}

// AckDevices removes the given devices from the set of devices that this peer
// has requested information for. This should be called once we've successfully
// sent the given devices to this peer.
func (pv *PeerView) AckDevices(devices Devices) {
	pv.cv.lock.Lock()
	defer pv.cv.lock.Unlock()

	for _, d := range devices.Devices {
		delete(pv.cv.queries[pv.rdt], d.RDT)
	}
}

// FP returns the TLS certificate fingerprint that is associated with this peer.
func (pv *PeerView) Cert() []byte {
	return bytes.Clone(pv.cert)
}

// FP returns the RDT that is associated with this peer.
func (pv *PeerView) RDT() RDT {
	return pv.rdt
}

// Address returns the address that this peer can be reached at. We might not
// know the address of this peer yet. In that case, this method returns an empty
// string and false.
func (pv *PeerView) Address() (string, bool) {
	pv.cv.lock.Lock()
	defer pv.cv.lock.Unlock()

	addr, ok := pv.cv.addresses[pv.rdt]
	return addr, ok
}

func peerAddress(ip net.IP, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

func calculateHMAC(rdt RDT, fp FP, secret string) []byte {
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write(fp[:])
	mac.Write([]byte(rdt))
	return mac.Sum(nil)
}

func calculateFP(cert []byte) FP {
	return sha512.Sum512(cert)
}

func RoutesToEdges(r Routes) ([]Edge, error) {
	if len(r.Routes)%3 != 0 {
		return nil, errors.New("length of routes list in assemble-routes must be a multiple of three")
	}

	edges := make([]Edge, 0, len(r.Routes)/3)
	for i := 0; i+2 < len(r.Routes); i += 3 {
		if r.Routes[i] < 0 || r.Routes[i+1] < 0 || r.Routes[i+2] < 0 {
			return nil, errors.New("invalid index in assemble-routes")
		}

		if r.Routes[i] >= len(r.Devices) || r.Routes[i+1] >= len(r.Devices) || r.Routes[i+2] >= len(r.Addresses) {
			return nil, errors.New("invalid index in assemble-routes")
		}

		edges = append(edges, Edge{
			From: r.Devices[r.Routes[i]],
			To:   r.Devices[r.Routes[i+1]],
			Via:  r.Addresses[r.Routes[i+2]],
		})
	}

	return edges, nil
}

func EdgesToRoutes(edges []Edge, sorted bool) Routes {
	devs := make(map[RDT]struct{}, len(edges)*2)
	addrs := make(map[string]struct{}, len(edges))
	for _, e := range edges {
		devs[e.From] = struct{}{}
		devs[e.To] = struct{}{}
		addrs[e.Via] = struct{}{}
	}

	devices := slices.Sorted(maps.Keys(devs))
	addresses := slices.Sorted(maps.Keys(addrs))

	if sorted {
		sort.Slice(edges, func(i, j int) bool {
			a, b := edges[i], edges[j]
			if a.From != b.From {
				return a.From < b.From
			}
			if a.To != b.To {
				return a.To < b.To
			}
			return a.Via < b.Via
		})
	}

	routes := make([]int, 0, 3*len(edges))
	for _, e := range edges {
		from, _ := slices.BinarySearch(devices, e.From)
		to, _ := slices.BinarySearch(devices, e.To)
		via, _ := slices.BinarySearch(addresses, e.Via)
		routes = append(routes, from, to, via)
	}

	return Routes{Devices: devices, Addresses: addresses, Routes: routes}
}
