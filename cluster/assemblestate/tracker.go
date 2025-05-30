package assemblestate

import (
	"fmt"
	"maps"
	"math/bits"
	"slices"
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

type peerID int
type edgeID int

type RouteTracker struct {
	// peers keeps a mapping of RDTs to an ID we assign each peer. This is here
	// to help keep track of which peers we've seen before.
	peers map[RDT]peerID

	// edges keeps track of all edges that we know about, verified or not.
	edges []Edge

	// indexes keeps a mapping of edges to indexes into the edges slice, for
	// quick lookup.
	indexes map[Edge]edgeID

	// known keeps track of which edges each peer knows about.
	known map[peerID]*bitset[edgeID]

	// unverified keeps track of edges that we know about but are not yet
	// verified.
	unverified *bitset[edgeID]

	// verified keeps track of which edges we've verified.
	verified *bitset[edgeID]

	// identified keeps track of device identities. This information is used to
	// verify routes.
	identified map[RDT]Identity
}

func NewRouteTracker() RouteTracker {
	return RouteTracker{
		peers:      make(map[RDT]peerID),
		indexes:    make(map[Edge]edgeID),
		known:      make(map[peerID]*bitset[edgeID]),
		identified: make(map[RDT]Identity),
		unverified: &bitset[edgeID]{},
		verified:   &bitset[edgeID]{},
	}
}

func (rt *RouteTracker) peerID(p RDT) peerID {
	if id, ok := rt.peers[p]; ok {
		return id
	}

	id := peerID(len(rt.peers))
	rt.peers[p] = id
	rt.known[id] = &bitset[edgeID]{}

	return id
}

func (rt *RouteTracker) edgeID(e Edge) edgeID {
	if id, ok := rt.indexes[e]; ok {
		return id
	}

	id := edgeID(len(rt.edges))
	rt.indexes[e] = id
	rt.edges = append(rt.edges, e)
	rt.unverified.set(id)

	return id
}

func (rt *RouteTracker) RecordIdentities(ids []Identity) error {
	dirty := false
	for _, id := range ids {
		if existing, ok := rt.identified[id.RDT]; ok {
			if existing != id {
				return fmt.Errorf("got new identifying information for device with rdt %q", id.RDT)
			}
			continue
		}

		dirty = true
		rt.identified[id.RDT] = id
	}

	if !dirty {
		return nil
	}

	for _, eid := range rt.unverified.all() {
		edge := rt.edges[eid]
		if _, ok := rt.identified[edge.From]; !ok {
			continue
		}

		if _, ok := rt.identified[edge.To]; !ok {
			continue
		}

		rt.unverified.clear(eid)
		rt.verified.set(eid)
	}

	return nil
}

func (rt *RouteTracker) DeviceID(rdt RDT) (Identity, bool) {
	id, ok := rt.identified[rdt]
	if !ok {
		return Identity{}, false
	}
	return id, true
}

func (rt *RouteTracker) RecordEdges(from RDT, edges []Edge) {
	pid := rt.peerID(from)
	for _, edge := range edges {
		eid := rt.edgeID(edge)
		rt.known[pid].set(eid)

		if _, ok := rt.identified[edge.From]; !ok {
			continue
		}

		if _, ok := rt.identified[edge.To]; !ok {
			continue
		}

		if rt.unverified.has(eid) {
			rt.unverified.clear(eid)
			rt.verified.set(eid)
		}
	}
}

func (rt *RouteTracker) MarkSentEdges(to RDT, sent []Edge) error {
	pid := rt.peerID(to)
	for _, edge := range sent {
		rt.known[pid].set(rt.edgeID(edge))
	}
	return nil
}

func (rt *RouteTracker) UnknownEdges(p RDT, limit int) []Edge {
	pid := rt.peerID(p)
	unknown := rt.verified.diff(rt.known[pid])

	edges := make([]Edge, 0, min(len(unknown), limit))
	for _, id := range unknown {
		if len(edges) == limit {
			break
		}
		edges = append(edges, rt.edges[id])
	}

	return edges
}

func (rt *RouteTracker) VerifiedEdges() []Edge {
	ids := rt.verified.all()
	verified := make([]Edge, 0, len(ids))
	for _, eid := range ids {
		verified = append(verified, rt.edges[eid])
	}
	return verified
}

func (rt *RouteTracker) KnowsEdge(p RDT, e Edge) bool {
	pid, ok := rt.peers[p]
	if !ok {
		return false
	}

	eid, ok := rt.indexes[e]
	if !ok {
		return false
	}

	return rt.known[pid].has(eid)
}

func (rt *RouteTracker) UnknownDevicesKnownBy(p RDT) []RDT {
	pid := rt.peerID(p)
	ids := rt.unverified.intersection(rt.known[pid])
	missing := make(map[RDT]struct{})
	for _, eid := range ids {
		edge := rt.edges[eid]

		if _, ok := rt.identified[edge.From]; !ok {
			missing[edge.From] = struct{}{}
		}

		if _, ok := rt.identified[edge.To]; !ok {
			missing[edge.To] = struct{}{}
		}
	}
	return slices.Collect(maps.Keys(missing))
}
