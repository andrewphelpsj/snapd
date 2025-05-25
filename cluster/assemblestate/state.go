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
	Devices []Device `json:"devices"`
}

type (
	FP    [64]byte
	Proof [64]byte
	RDT   string
)

type Device struct {
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
	verified *graph

	// identities keeps track of device identities that we've received from
	// other trusted peers.
	identities map[RDT]Device
}

func NewView(secret string, rdt RDT, ip net.IP, port int, cert tls.Certificate) (*ClusterView, error) {
	if len(cert.Certificate) != 1 {
		return nil, fmt.Errorf("exactly one certificate expected, got %d", len(cert.Certificate))
	}

	fp := calculateFP(cert.Certificate[0])
	return &ClusterView{
		secret:   secret,
		rdt:      rdt,
		ip:       ip,
		port:     port,
		cert:     cert,
		views:    make(map[RDT]*PeerView),
		trusted:  make(map[FP]RDT),
		verified: newGraph(),
		identities: map[RDT]Device{
			rdt: {
				RDT: rdt,
				FP:  fp,
			},
		},
		hmac: calculateHMAC(rdt, fp, secret),
	}, nil
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

	if err := pv.graph.add(routes); err != nil {
		return err
	}

	return cv.reverify()
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

	// if we don't see any new peers, then we don't need to recalculate what we
	// can publish to other peers
	if dirty {
		return cv.reverify()
	}
	return nil
}

// reverify updates our internal view of what routes we can publish to other
// peers. This should be called whenever we see a new set of routes from another
// peer and when we see a new set of device identities.
func (cv *ClusterView) reverify() error {
	for _, pv := range cv.views {
		for _, d := range pv.graph.devices {
			if _, ok := cv.identities[d.rdt]; !ok {
				continue
			}

			for via, peer := range d.connections {
				if _, ok := cv.identities[peer]; !ok {
					continue
				}

				if err := cv.verified.connect(d.rdt, peer, via); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Authenticate checks that the given [Auth] message is valid and proves
// knowledge of the shared secert. If this check is passed, this [ClusterView]
// will start accepting updates that are associated with the given [FP]. An
// error is returned if the message's HMAC is found to be invalid.
//
// On success, a [PeerView] is returned. This can be used to fetch and record
// information about what this local node believes the given peer knows about
// the cluster.
func (cv *ClusterView) Authenticate(auth Auth, cert []byte, ip net.IP, port int) (*PeerView, error) {
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

	if _, ok := cv.views[auth.RDT]; !ok {
		cv.views[auth.RDT] = &PeerView{
			cluster: cv,
			fp:      fp,
			rdt:     auth.RDT,
			ip:      ip,
			port:    port,
			queries: make(map[RDT]struct{}),
			graph:   newGraph(),
		}
	}

	return cv.views[auth.RDT], nil
}

// CheckAuth checks if the given [Auth] message proves knowledge of the shared
// secret. An error is returned if the HMAC cannot be verified and the peer
// should not be trusted. This method doesn't change the internal state of our
// view of the cluster.
func (cv *ClusterView) CheckAuth(auth Auth, cert []byte) error {
	cv.lock.Lock()
	defer cv.lock.Unlock()

	fp := calculateFP(cert)

	expectedHMAC := calculateHMAC(auth.RDT, fp, cv.secret)
	if !hmac.Equal(expectedHMAC, auth.HMAC) {
		return errors.New("received invalid HMAC from peer")
	}
	return nil
}

// PeerView provides a peer's view into [ClusterView], providing access to what
// we think the peer that this structure represents knows about the cluster.
type PeerView struct {
	queries map[RDT]struct{}
	graph   *graph
	rdt     RDT
	fp      FP
	ip      net.IP
	port    int

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
	for _, d := range pv.graph.devices {
		if _, ok := pv.cluster.identities[d.rdt]; !ok {
			unknown = append(unknown, d.rdt)
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

	unknown := newGraph()

	for _, d := range pv.cluster.verified.devices {
		for via, peerRDT := range d.connections {
			if pv.graph.contains(d.rdt, peerRDT, via) {
				continue
			}

			if err := unknown.connect(d.rdt, peerRDT, via); err != nil {
				return Routes{}, err
			}
		}
	}

	for addr := range pv.cluster.verified.addresses {
		if _, ok := pv.graph.addresses[addr]; ok {
			continue
		}

		unknown.addresses[addr] = struct{}{}
	}

	// manually add the route from the local node to the receiving peer. this is
	// a special case, since we might not have seen an assemble-devices message
	// that includes this peer
	addr := pv.Address()
	if !pv.graph.contains(pv.cluster.rdt, pv.rdt, addr) {
		if err := unknown.connect(pv.cluster.rdt, pv.rdt, addr); err != nil {
			return Routes{}, err
		}
	}

	// similarly, make sure that the route back to the local node is always
	// present, even if it might not be involved in any of the routes we are
	// sending
	localAddr := pv.cluster.Address()
	if _, ok := pv.graph.addresses[localAddr]; !ok {
		unknown.addresses[localAddr] = struct{}{}
	}

	return unknown.export()
}

// AckRoutes updates this peer's view of the cluster, adding the given routes to
// this peer's set of known routes. This should be called once we successfully
// publish the given information to this peer.
func (pv *PeerView) AckRoutes(routes Routes) error {
	pv.cluster.lock.Lock()
	defer pv.cluster.lock.Unlock()

	if err := pv.graph.add(routes); err != nil {
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

	devices := make([]Device, 0, len(pv.queries))
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

// Address returns the address of this peer.
func (pv *PeerView) Address() string {
	return peerAddress(pv.ip, pv.port)
}

// FP returns the TLS certificate fingerprint that is associated with this peer.
func (pv *PeerView) FP() FP {
	return pv.fp
}

// FP returns the RDT that is associated with this peer.
func (pv *PeerView) RDT() RDT {
	return pv.rdt
}

// graph contains a view of the cluster.
type graph struct {
	// devices is a mapping of device RDTs to devices.
	devices map[RDT]*device

	// addresses is a set of addresses involved in the cluster. This might
	// include addresses that are not an edge in the graph.
	addresses map[string]struct{}
}

// device represents a device in the cluster.
type device struct {
	// rdt is the RDT of this device.
	rdt RDT

	// connections contains all routes that originate from this device. It is a
	// mapping of addresses to other device RDTs.
	connections map[string]RDT
}

func newGraph() *graph {
	return &graph{
		devices:   make(map[RDT]*device),
		addresses: make(map[string]struct{}),
	}
}

// connect create a connection in the graph using the given device RDTs and
// address.
func (r *graph) connect(from, to RDT, via string) error {
	if from == to {
		return errors.New("internal error: cannot connect an RDT to itself")
	}

	if _, ok := r.devices[from]; !ok {
		r.devices[from] = &device{
			rdt:         from,
			connections: make(map[string]RDT),
		}
	}

	if _, ok := r.devices[to]; !ok {
		r.devices[to] = &device{
			rdt:         to,
			connections: make(map[string]RDT),
		}
	}

	if peer, ok := r.devices[from].connections[via]; ok && peer != r.devices[to].rdt {
		return errors.New("cannot overwrite already existing route with new destination")
	}

	r.devices[from].connections[via] = r.devices[to].rdt
	r.addresses[via] = struct{}{}

	return nil
}

// contains checks if this graph contains of the the given route.
func (r *graph) contains(from, to RDT, via string) bool {
	if _, ok := r.devices[from]; !ok {
		return false
	}

	if _, ok := r.devices[to]; !ok {
		return false
	}

	if _, ok := r.addresses[via]; !ok {
		return false
	}

	return r.devices[from].connections[via] == r.devices[to].rdt
}

// add adds all routes in the given [Routes] to this graph.
func (r *graph) add(ar Routes) error {
	if len(ar.Routes)%3 != 0 {
		return errors.New("length of routes list in assemble-routes must be a multiple of three")
	}

	// TODO: some sort of pending system here for routes???
	for i := 0; i+2 < len(ar.Routes); i += 3 {
		if ar.Routes[i] < 0 || ar.Routes[i+1] < 0 || ar.Routes[i+2] < 0 {
			return errors.New("invalid index in assemble-routes")
		}

		if ar.Routes[i] >= len(ar.Devices) || ar.Routes[i+1] >= len(ar.Devices) || ar.Routes[i+2] >= len(ar.Addresses) {
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

// export deterministically converts this graph to a respresentation that is
// suitable to send to other peers.
func (r *graph) export() (Routes, error) {
	devices := slices.Sorted(maps.Keys(r.devices))
	addresses := slices.Sorted(maps.Keys(r.addresses))

	var routes []int
	for _, from := range devices {
		from := r.devices[from]
		connections := slices.Sorted(maps.Keys(from.connections))
		for _, via := range connections {
			toRDT := from.connections[via]

			fromIndex, ok := slices.BinarySearch(devices, from.rdt)
			if !ok {
				return Routes{}, errors.New("internal error: graph contains a connection from a missing device")
			}

			toIndex, ok := slices.BinarySearch(devices, toRDT)
			if !ok {
				return Routes{}, errors.New("internal error: graph contains a connection to a missing device")
			}

			addrIndex, ok := slices.BinarySearch(addresses, via)
			if !ok {
				return Routes{}, errors.New("internal error: graph contains a connection via a missing address")
			}

			routes = append(routes, fromIndex, toIndex, addrIndex)
		}
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
