package assemblestate

import (
	"errors"
	"fmt"
	"maps"
	"math/bits"
	"slices"
	"sort"

	"github.com/snapcore/snapd/cluster/assemblestate/bimap"
)

type bitset[T ~int] struct {
	words []uint64
}

// set turns on the bit for id.
func (b *bitset[T]) set(id T) {
	word, bit := id/64, id%64
	if int(word) >= len(b.words) {
		cp := make([]uint64, word+1)
		copy(cp, b.words)
		b.words = cp
	}
	b.words[word] |= 1 << bit
}

// has reports whether the bit for id is set.
func (bs *bitset[T]) has(id T) bool {
	word, bit := id/64, id%64
	if int(word) >= len(bs.words) {
		return false
	}
	return bs.words[word]&(1<<bit) != 0
}

// clear turns off the bit for id.
func (b *bitset[T]) clear(id T) {
	word, bit := id/64, id%64
	if int(word) < len(b.words) {
		b.words[word] &^= 1 << bit
	}
}

// all returns all of the values that are set in the bitset.
func (b *bitset[T]) all() []T {
	var result []T
	for wi, word := range b.words {
		result = values(result, wi, word)
	}
	return result
}

// diff returns the set difference between this and the given [bitset].
func (b *bitset[T]) diff(other *bitset[T]) []T {
	var result []T
	for wi, w := range b.words {
		mask := w
		if wi < len(other.words) {
			mask &= ^other.words[wi]
		}
		result = values(result, wi, mask)
	}
	return result
}

// diff returns the set intersection of this and the given [bitset].
func (b *bitset[T]) intersection(other *bitset[T]) []T {
	var result []T
	for wi := range min(len(other.words), len(b.words)) {
		mask := b.words[wi] & other.words[wi]
		result = values(result, wi, mask)
	}
	return result
}

// values appends to slice the values corresponding to each set bit in word. wi
// is the index of the 64-bit word within a [bitset].
func values[T ~int](slice []T, wi int, word uint64) []T {
	for word != 0 {
		tz := bits.TrailingZeros64(word)
		slice = append(slice, T((wi*64)+tz))
		word &= word - 1
	}
	return slice
}

type (
	peerID int
	edgeID int
	addrID int
)

type edge struct {
	from, to peerID
	via      addrID
}

type RouteTracker struct {
	self RDT

	peers *bimap.BiMap[RDT, peerID]
	addrs *bimap.BiMap[string, addrID]
	edges *bimap.BiMap[edge, edgeID]

	// known keeps track of which edges each peer knows about.
	known map[peerID]*bitset[edgeID]

	// unverified keeps track of edges that we know about but are not yet
	// verified.
	unverified *bitset[edgeID]

	// verified keeps track of which edges we've verified.
	verified *bitset[edgeID]

	// identified keeps track of device identities. This information is used to
	// verify routes.
	identified map[peerID]Identity
}

func NewRouteTracker(self RDT) RouteTracker {
	return RouteTracker{
		self:       self,
		peers:      bimap.New[RDT, peerID](),
		addrs:      bimap.New[string, addrID](),
		edges:      bimap.New[edge, edgeID](),
		known:      make(map[peerID]*bitset[edgeID]),
		identified: make(map[peerID]Identity),
		unverified: &bitset[edgeID]{},
		verified:   &bitset[edgeID]{},
	}
}

func (rt *RouteTracker) peerID(p RDT) peerID {
	if id, ok := rt.peers.IndexOf(p); ok {
		return id
	}

	id := rt.peers.Add(p)
	rt.known[id] = &bitset[edgeID]{}

	return id
}

func (rt *RouteTracker) edgeID(e edge) edgeID {
	if id, ok := rt.edges.IndexOf(e); ok {
		return id
	}

	id := rt.edges.Add(e)
	rt.unverified.set(id)

	return id
}

func (rt *RouteTracker) addrID(a string) addrID {
	return rt.addrs.Add(a)
}

func (rt *RouteTracker) RecordIdentities(ids []Identity) error {
	dirty := false
	for _, id := range ids {
		pid := rt.peerID(id.RDT)
		if existing, ok := rt.identified[pid]; ok {
			if existing != id {
				return fmt.Errorf("got new identifying information for device with rdt %q", id.RDT)
			}
			continue
		}

		dirty = true
		rt.identified[pid] = id
	}

	if !dirty {
		return nil
	}

	for _, eid := range rt.unverified.all() {
		edge := rt.edges.Value(eid)
		if _, ok := rt.identified[edge.from]; !ok {
			continue
		}

		if _, ok := rt.identified[edge.to]; !ok {
			continue
		}

		rt.unverified.clear(eid)
		rt.verified.set(eid)
	}

	return nil
}

func (rt *RouteTracker) DeviceID(rdt RDT) (Identity, bool) {
	pid, ok := rt.peers.IndexOf(rdt)
	if !ok {
		return Identity{}, false
	}

	id, ok := rt.identified[pid]
	if !ok {
		return Identity{}, false
	}

	return id, true
}

func (rt *RouteTracker) RecordRoutes(from RDT, r Routes) error {
	pid := rt.peerID(from)

	if len(r.Routes)%3 != 0 {
		return errors.New("length of routes list must be a multiple of three")
	}

	for i := 0; i+2 < len(r.Routes); i += 3 {
		if r.Routes[i] < 0 || r.Routes[i+1] < 0 || r.Routes[i+2] < 0 {
			return errors.New("invalid index in routes")
		}

		if r.Routes[i] >= len(r.Devices) || r.Routes[i+1] >= len(r.Devices) || r.Routes[i+2] >= len(r.Addresses) {
			return errors.New("invalid index in routes")
		}

		fromID := rt.peerID(r.Devices[r.Routes[i]])
		toID := rt.peerID(r.Devices[r.Routes[i+1]])
		viaID := rt.addrID(r.Addresses[r.Routes[i+2]])

		eid := rt.edgeID(edge{
			from: fromID,
			to:   toID,
			via:  viaID,
		})

		rt.known[pid].set(eid)

		if _, ok := rt.identified[fromID]; !ok {
			continue
		}

		if _, ok := rt.identified[toID]; !ok {
			continue
		}

		if rt.unverified.has(eid) {
			rt.unverified.clear(eid)
			rt.verified.set(eid)
		}
	}

	return nil
}

func (rt *RouteTracker) MarkSentRoutes(to RDT, r Routes) error {
	pid := rt.peerID(to)

	if len(r.Routes)%3 != 0 {
		return errors.New("length of routes list must be a multiple of three")
	}

	for i := 0; i+2 < len(r.Routes); i += 3 {
		if r.Routes[i] < 0 || r.Routes[i+1] < 0 || r.Routes[i+2] < 0 {
			return errors.New("invalid index in routes")
		}

		if r.Routes[i] >= len(r.Devices) || r.Routes[i+1] >= len(r.Devices) || r.Routes[i+2] >= len(r.Addresses) {
			return errors.New("invalid index in routes")
		}

		fromID := rt.peerID(r.Devices[r.Routes[i]])
		toID := rt.peerID(r.Devices[r.Routes[i+1]])
		viaID := rt.addrID(r.Addresses[r.Routes[i+2]])

		eid := rt.edgeID(edge{
			from: fromID,
			to:   toID,
			via:  viaID,
		})

		rt.known[pid].set(eid)
	}

	return nil
}

func (rt *RouteTracker) UnknownRoutes(peer RDT, destination string, limit int) Routes {
	pid := rt.peerID(peer)

	unknown := rt.verified.diff(rt.known[pid])
	if len(unknown) > limit {
		unknown = unknown[:limit]
	}

	rdts := bimap.New[RDT, int]()
	addrs := bimap.New[string, int]()

	routes := make([]int, 0, len(unknown)*3)
	for _, eid := range unknown {
		edge := rt.edges.Value(eid)

		from := rt.peers.Value(edge.from)
		to := rt.peers.Value(edge.to)
		address := rt.addrs.Value(edge.via)

		routes = append(routes,
			rdts.Add(from),
			rdts.Add(to),
			addrs.Add(address),
		)
	}

	selfID := rt.peerID(rt.self)
	addrID := rt.addrID(destination)
	directID := rt.edgeID(edge{from: selfID, to: pid, via: addrID})

	if !rt.known[pid].has(directID) && !rt.verified.has(directID) {
		routes = append(routes,
			rdts.Add(rt.self),
			rdts.Add(peer),
			addrs.Add(destination),
		)
	}

	return Routes{
		Devices:   rdts.Values(),
		Addresses: addrs.Values(),
		Routes:    routes,
	}
}

func (rt *RouteTracker) VerifiedRoutes() Routes {
	eids := rt.verified.all()

	devs := make(map[RDT]struct{})
	addrs := make(map[string]struct{})

	for _, eid := range eids {
		edge := rt.edges.Value(eid)
		devs[rt.peers.Value(edge.from)] = struct{}{}
		devs[rt.peers.Value(edge.to)] = struct{}{}
		addrs[rt.addrs.Value(edge.via)] = struct{}{}
	}

	devices := slices.Sorted(maps.Keys(devs))
	addresses := slices.Sorted(maps.Keys(addrs))

	sort.Slice(eids, func(i, j int) bool {
		a, b := rt.edges.Value(eids[i]), rt.edges.Value(eids[j])

		if rt.peers.Value(a.from) != rt.peers.Value(b.from) {
			return rt.peers.Value(a.from) < rt.peers.Value(b.from)
		}

		if rt.peers.Value(a.to) != rt.peers.Value(b.to) {
			return rt.peers.Value(a.to) < rt.peers.Value(b.to)
		}

		return rt.addrs.Value(a.via) < rt.addrs.Value(b.via)
	})

	routes := make([]int, 0, len(eids)*3)
	for _, eid := range eids {
		edge := rt.edges.Value(eid)
		from, _ := slices.BinarySearch(devices, rt.peers.Value(edge.from))
		to, _ := slices.BinarySearch(devices, rt.peers.Value(edge.to))
		via, _ := slices.BinarySearch(addresses, rt.addrs.Value(edge.via))

		routes = append(routes,
			from,
			to,
			via,
		)
	}

	return Routes{
		Devices:   devices,
		Addresses: addresses,
		Routes:    routes,
	}
}

func (rt *RouteTracker) UnknownDevicesKnownBy(p RDT) []RDT {
	pid := rt.peerID(p)
	ids := rt.unverified.intersection(rt.known[pid])
	missing := make(map[RDT]struct{})
	for _, eid := range ids {
		edge := rt.edges.Value(eid)

		from := rt.peers.Value(edge.from)
		to := rt.peers.Value(edge.to)

		if _, ok := rt.identified[edge.from]; !ok {
			missing[from] = struct{}{}
		}

		if _, ok := rt.identified[edge.to]; !ok {
			missing[to] = struct{}{}
		}
	}
	return slices.Collect(maps.Keys(missing))
}
