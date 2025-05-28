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

	// addresses keeps track of which address we can reach each device at. This
	// data isn't kept in the set of [PeerView] structs because we might receive
	// and trust information from a peer before we know how to talk back to
	// them.
	addresses map[RDT]string

	// views keeps track of what the local node believes each trusted peer knows
	// of the cluster. This information is a combination of routes that we have
	// successfully sent each peer and the routes that each peer has sent us.
	//
	// We use this information to help us keep track of what new information
	// needs to be published to each peer, and it is also used to determine
	// which peer should be queried for identifying device information.
	views map[RDT]*PeerView

	// verified keeps track of the routes for which we have identifying
	// information for both devices involved in the route. The routes here can
	// be safely published to other peers.
	verified Graph

	// identities keeps track of device identities that we've received from
	// other trusted peers.
	identities map[RDT]Identity
}

func NewClusterView(secret string, rdt RDT, ip net.IP, port int, cert tls.Certificate) (*ClusterView, error) {
	if len(cert.Certificate) != 1 {
		return nil, fmt.Errorf("exactly one certificate expected, got %d", len(cert.Certificate))
	}

	fp := calculateFP(cert.Certificate[0])
	return &ClusterView{
		secret:    secret,
		rdt:       rdt,
		ip:        ip,
		port:      port,
		cert:      cert,
		hmac:      calculateHMAC(rdt, fp, secret),
		verified:  NewGraph(),
		views:     make(map[RDT]*PeerView),
		trusted:   make(map[FP]RDT),
		addresses: make(map[RDT]string),
		identities: map[RDT]Identity{
			rdt: {
				RDT: rdt,
				FP:  fp,
			},
		},
	}, nil
}

func (cv *ClusterView) Export() (Routes, error) {
	cv.lock.Lock()
	defer cv.lock.Unlock()

	rs, err := cv.verified.Export()
	if err != nil {
		return Routes{}, err
	}

	return rs, nil
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

// Trusted returns the RDT associated with this TLS certificate, if it is
// trusted. An error is returned if the certificate isn't trusted.
func (cv *ClusterView) Trusted(cert []byte) (RDT, error) {
	cv.lock.Lock()
	defer cv.lock.Unlock()

	rdt, ok := cv.trusted[calculateFP(cert)]
	if !ok {
		return "", errors.New("given TLS fingerprint is not associated with a trusted RDT")
	}

	return rdt, nil
}

// RecordPeerDeviceQueries adds the given devices to the queue of queries
// originating from the device associated with the given TLS certificate
// fingerprint. If any devices are unknown, no devices are added to the queue
// and an error is returned. If this local node is queried for devices that we
// do not know, either this local node or the requesting peer has a bug.
func (cv *ClusterView) RecordPeerDeviceQueries(peerRDT RDT, unknown UnknownDevices) error {
	cv.lock.Lock()
	defer cv.lock.Unlock()

	if _, ok := cv.views[peerRDT]; !ok {
		return errors.New("peer is untrusted")
	}

	for _, rdt := range unknown.Devices {
		// TODO: should we just drop unanswerable queries? it would really be a
		// bug if the other side is requesting data that we don't know about
		if _, ok := cv.identities[rdt]; !ok {
			return fmt.Errorf("unknown device: %s", rdt)
		}
	}

	for _, rdt := range unknown.Devices {
		cv.views[peerRDT].queries[rdt] = struct{}{}
	}

	return nil
}

// RecordPeerRoutes updates our view of what the device associated with the
// given TLS fingerprint knows about the cluster. Additionally we recalculate
// our view of the verified routes in the cluster.
func (cv *ClusterView) RecordPeerRoutes(peerRDT RDT, routes Routes) error {
	cv.lock.Lock()
	defer cv.lock.Unlock()

	pv, ok := cv.views[peerRDT]
	if !ok {
		return errors.New("peer is untrusted")
	}

	changes, err := pv.graph.Add(routes)
	if err != nil {
		return err
	}

	for _, e := range changes {
		if _, ok := cv.identities[e.From]; !ok {
			continue
		}

		if _, ok := cv.identities[e.To]; !ok {
			continue
		}

		if _, err := cv.verified.Connect(e); err != nil {
			return err
		}
	}

	return nil
}

// RecordIdentities records the given device identities. All new device
// identities are recorded. For any devices that we are already aware of, we
// check that our view of the device's identity is consistent with the new data.
func (cv *ClusterView) RecordIdentities(devices Devices) error {
	cv.lock.Lock()
	defer cv.lock.Unlock()

	var dirty bool
	for _, d := range devices.Devices {
		if known, ok := cv.identities[d.RDT]; ok {
			if d != known {
				return fmt.Errorf("inconsistent knowledge of device with RDT %q", d.RDT)
			}
			continue
		}

		cv.identities[d.RDT] = d
		dirty = true
	}

	if !dirty {
		return nil
	}

	// if we got some new devices, we need to add all of routes from our peers
	// that aren't yet verified that involve those routes
	for _, pv := range cv.views {
		for edge := range pv.graph.edges {
			if _, ok := cv.identities[edge.From]; !ok {
				continue
			}

			if _, ok := cv.identities[edge.To]; !ok {
				continue
			}

			if _, err := cv.verified.Connect(edge); err != nil {
				return err
			}
		}
	}

	return nil
}

// Authenticate checks that the given [Auth] message is valid and proves
// knowledge of the shared secert. If this check is passed, this [ClusterView]
// will start accepting updates that are associated with the given RDT. An error
// is returned if the message's HMAC is found to be invalid.
//
// On success, a [PeerView] is returned. This can be used to fetch and record
// information about what this local node believes the given peer knows about
// the cluster.
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

	if _, ok := cv.views[auth.RDT]; !ok {
		cv.views[auth.RDT] = &PeerView{
			cluster: cv,
			fp:      fp,
			rdt:     auth.RDT,
			queries: make(map[RDT]struct{}),
			graph:   NewGraph(),
		}
	}

	return cv.views[auth.RDT], nil
}

// PeerView provides a peer's view into [ClusterView], providing access to what
// we think the peer that this structure represents knows about the cluster.
type PeerView struct {
	queries map[RDT]struct{}
	graph   Graph
	rdt     RDT
	fp      FP
	cluster *ClusterView
}

// UnidentifiedDevices returns a list of RDTs that our local node does not know
// about, but this peer should have identifying information for.
//
// TODO: This could use name that is more clear.
func (pv *PeerView) UnidentifiedDevices() UnknownDevices {
	pv.cluster.lock.Lock()
	defer pv.cluster.lock.Unlock()

	var unknown []RDT
	for edge := range pv.graph.edges {
		if _, ok := pv.cluster.identities[edge.From]; !ok {
			unknown = append(unknown, edge.From)
		}

		if _, ok := pv.cluster.identities[edge.To]; !ok {
			unknown = append(unknown, edge.To)
		}
	}

	return UnknownDevices{Devices: unknown}
}

// UnknownRoutes returns routes that our local node has verified, but this peer
// does not yet have knowledge of. All routes returned will only contain devices
// that the local node has seen an assemble-devices message for.
func (pv *PeerView) UnknownRoutes() (Routes, error) {
	pv.cluster.lock.Lock()
	defer pv.cluster.lock.Unlock()

	unknown := NewGraph()

	for edge := range pv.cluster.verified.edges {
		if pv.graph.Contains(edge) {
			continue
		}

		if _, err := unknown.Connect(edge); err != nil {
			return Routes{}, err
		}
	}

	for addr := range pv.cluster.verified.addresses {
		if pv.graph.addresses[addr] {
			continue
		}

		unknown.addresses[addr] = true
	}

	peerAddr, ok := pv.cluster.addresses[pv.rdt]
	if !ok {
		return Routes{}, fmt.Errorf("unable to list unknown routes for peer %q with undiscovered address", pv.rdt)
	}

	// manually add the route from the local node to the receiving peer. this is
	// a special case, since we might not have seen an assemble-devices message
	// that includes this peer
	edge := Edge{From: pv.cluster.rdt, To: pv.rdt, Via: peerAddr}
	if !pv.graph.Contains(edge) {
		if _, err := unknown.Connect(edge); err != nil {
			return Routes{}, err
		}
	}

	// similarly, make sure that the route back to the local node is always
	// present, even if it might not be involved in any of the routes we are
	// sending
	localAddr := pv.cluster.Address()
	if !pv.graph.addresses[localAddr] {
		unknown.addresses[localAddr] = true
	}

	return unknown.Export()
}

// AckRoutes updates this peer's view of the cluster, adding the given routes to
// this peer's set of known routes. This should be called once we successfully
// publish the given information to this peer.
func (pv *PeerView) AckRoutes(routes Routes) error {
	pv.cluster.lock.Lock()
	defer pv.cluster.lock.Unlock()

	if _, err := pv.graph.Add(routes); err != nil {
		return err
	}

	return nil
}

// UnknownDevices returns a list of device identities that this peer has
// requested information for. Any devices that this local node doesn't know
// about are skipped.
func (pv *PeerView) UnknownDevices() (Devices, error) {
	pv.cluster.lock.Lock()
	defer pv.cluster.lock.Unlock()

	devices := make([]Identity, 0, len(pv.queries))
	for rdt := range pv.queries {
		id, ok := pv.cluster.identities[rdt]
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
	pv.cluster.lock.Lock()
	defer pv.cluster.lock.Unlock()

	for _, d := range devices.Devices {
		delete(pv.queries, d.RDT)
	}
}

// FP returns the TLS certificate fingerprint that is associated with this peer.
func (pv *PeerView) FP() FP {
	return pv.fp
}

// FP returns the RDT that is associated with this peer.
func (pv *PeerView) RDT() RDT {
	return pv.rdt
}

func (pv *PeerView) Address() (string, bool) {
	pv.cluster.lock.Lock()
	defer pv.cluster.lock.Unlock()

	addr, ok := pv.cluster.addresses[pv.rdt]
	return addr, ok
}

// Graph contains a view of the cluster.
type Graph struct {
	edges map[Edge]bool

	// addresses is a set of addresses involved in the cluster. This might
	// include addresses that are not an edge in the graph.
	addresses map[string]bool
}

type Edge struct {
	From RDT
	To   RDT
	Via  string
}

func NewGraph() Graph {
	return Graph{
		edges:     make(map[Edge]bool),
		addresses: make(map[string]bool),
	}
}

func (g *Graph) Connect(edge Edge) (bool, error) {
	if edge.From == edge.To {
		return false, errors.New("internal error: cannot connect an RDT to itself")
	}

	if g.edges[edge] {
		return false, nil
	}

	g.edges[edge] = true
	g.addresses[edge.Via] = true

	return true, nil
}

// Contains checks if this graph Contains of the the given route.
func (r *Graph) Contains(edge Edge) bool {
	return r.edges[edge]
}

// Add adds all routes in the given [Routes] to this graph.
func (r *Graph) Add(ar Routes) ([]Edge, error) {
	if len(ar.Routes)%3 != 0 {
		return nil, errors.New("length of routes list in assemble-routes must be a multiple of three")
	}

	var changes []Edge
	for i := 0; i+2 < len(ar.Routes); i += 3 {
		if ar.Routes[i] < 0 || ar.Routes[i+1] < 0 || ar.Routes[i+2] < 0 {
			return nil, errors.New("invalid index in assemble-routes")
		}

		if ar.Routes[i] >= len(ar.Devices) || ar.Routes[i+1] >= len(ar.Devices) || ar.Routes[i+2] >= len(ar.Addresses) {
			return nil, errors.New("invalid index in assemble-routes")
		}

		edge := Edge{
			From: ar.Devices[ar.Routes[i]],
			To:   ar.Devices[ar.Routes[i+1]],
			Via:  ar.Addresses[ar.Routes[i+2]],
		}

		changed, err := r.Connect(edge)
		if err != nil {
			return nil, err
		}

		if changed {
			changes = append(changes, edge)
		}

	}

	return changes, nil
}

// Export deterministically converts this graph to a respresentation that is
// suitable to send to other peers.
func (g *Graph) Export() (Routes, error) {
	devs := make(map[RDT]struct{}, len(g.edges)*2)
	for e := range g.edges {
		devs[e.From] = struct{}{}
		devs[e.To] = struct{}{}
	}

	devices := slices.Sorted(maps.Keys(devs))
	addresses := slices.Sorted(maps.Keys(g.addresses))
	edges := slices.SortedFunc(maps.Keys(g.edges), func(a, b Edge) int {
		if a.From < b.From {
			return -1
		}
		if a.From > b.From {
			return 1
		}

		if a.To < b.To {
			return -1
		}
		if a.To > b.To {
			return 1
		}

		if a.Via < b.Via {
			return -1
		}
		if a.Via > b.Via {
			return 1
		}
		return 0
	})

	routes := make([]int, 0, len(g.edges)*3)
	for _, e := range edges {
		routes = append(routes,
			slices.Index(devices, e.From),
			slices.Index(devices, e.To),
			slices.Index(addresses, e.Via),
		)
	}

	return Routes{
		Devices:   devices,
		Addresses: addresses,
		Routes:    routes,
	}, nil
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
