package assemblestate

import (
	"fmt"
	"maps"
	"slices"
)

type bitset struct {
	words []uint64
}

// set turns on the bit for id.
func (b *bitset) set(id int) {
	word, bit := id/64, id%64
	if word >= len(b.words) {
		cp := make([]uint64, word+1)
		copy(cp, b.words)
		b.words = cp
	}
	b.words[word] |= 1 << bit
}

// has reports whether the bit for id is set.
func (bs *bitset) has(id int) bool {
	word, bit := id/64, id%64
	if word >= len(bs.words) {
		return false
	}
	return bs.words[word]&(1<<bit) != 0
}

type peerID = int
type edgeID = int

type RouteTracker struct {
	// peers keeps a mapping of RDTs to an ID we assign each peer. These IDs are
	// used so that we can keep a compact representation of which edges each
	// peer knows.
	peers map[RDT]peerID

	// edges keeps track of all edges that we know about, verified or not.
	edges []Edge
	// indexes keeps a mapping of edges to indexes into the edges slice, for
	// quick lookup.
	indexes map[Edge]edgeID

	// known keeps track of which edges are known by each peer. An edge is known
	// to a peer if either they have reported the edge to us or we have sent the
	// edge to them. The [bitset] associated with each edge stores peer IDs.
	known map[edgeID]*bitset

	// unverified keeps track of edges that we know about but are not yet
	// verified. We use a map here for quick lookup and easy deletion.
	unverified map[edgeID]struct{}

	// verified keeps track of which edges are verified. Since this list only
	// grows and we don't need to perform lookups on it, it is better as a
	// slice.
	verified []edgeID

	// identified keeps track of device identities. This information is used to
	// verify routes.
	identified map[RDT]Identity
}

func NewRouteTracker() RouteTracker {
	return RouteTracker{
		peers:      make(map[RDT]peerID),
		indexes:    make(map[Edge]edgeID),
		known:      make(map[edgeID]*bitset),
		identified: make(map[RDT]Identity),
		unverified: make(map[edgeID]struct{}),
	}
}

func (rt *RouteTracker) peerID(p RDT) peerID {
	if id, ok := rt.peers[p]; ok {
		return id
	}

	id := peerID(len(rt.peers))
	rt.peers[p] = id
	return id
}

func (rt *RouteTracker) edgeID(e Edge) edgeID {
	if id, ok := rt.indexes[e]; ok {
		return id
	}

	id := edgeID(len(rt.edges))
	rt.indexes[e] = id
	rt.edges = append(rt.edges, e)

	rt.unverified[id] = struct{}{}
	rt.known[id] = &bitset{}

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

	for edgeID := range rt.unverified {
		e := rt.edges[edgeID]

		if _, ok := rt.identified[e.From]; !ok {
			continue
		}

		if _, ok := rt.identified[e.To]; !ok {
			continue
		}

		delete(rt.unverified, edgeID)
		rt.verified = append(rt.verified, edgeID)
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
	peerID := rt.peerID(from)
	for _, e := range edges {
		edgeID := rt.edgeID(e)

		rt.known[edgeID].set(peerID)

		if _, ok := rt.identified[e.From]; !ok {
			continue
		}

		if _, ok := rt.identified[e.To]; !ok {
			continue
		}

		if _, ok := rt.unverified[edgeID]; ok {
			delete(rt.unverified, edgeID)
			rt.verified = append(rt.verified, edgeID)
		}
	}
}

func (rt *RouteTracker) MarkSentEdges(to RDT, sent []Edge) error {
	peerID := rt.peerID(to)
	for _, e := range sent {
		edgeID, ok := rt.indexes[e]
		if !ok {
			continue
		}

		rt.known[edgeID].set(peerID)
	}
	return nil
}

func (rt *RouteTracker) UnknownEdges(p RDT) []Edge {
	peerID := rt.peerID(p)
	var unseen []Edge
	for _, edgeID := range rt.verified {
		if rt.known[edgeID].has(peerID) {
			continue
		}

		unseen = append(unseen, rt.edges[edgeID])
	}
	return unseen
}

func (rt *RouteTracker) VerifiedEdges() []Edge {
	all := make([]Edge, 0, len(rt.verified))
	for _, edgeID := range rt.verified {
		all = append(all, rt.edges[edgeID])
	}
	return all
}

func (rt *RouteTracker) KnowsEdge(p RDT, e Edge) bool {
	peerID, ok := rt.peers[p]
	if !ok {
		return false
	}

	edgeID, ok := rt.indexes[e]
	if !ok {
		return false
	}

	return rt.known[edgeID].has(peerID)
}

func (rt *RouteTracker) UnknownDevicesKnownBy(p RDT) []RDT {
	peerID, ok := rt.peers[p]
	if !ok {
		return nil
	}

	missing := make(map[RDT]struct{}, len(rt.unverified))
	for edgeID := range rt.unverified {
		if !rt.known[edgeID].has(peerID) {
			continue
		}

		e := rt.edges[edgeID]

		if _, ok := rt.identified[e.From]; !ok {
			missing[e.From] = struct{}{}
		}

		if _, ok := rt.identified[e.To]; !ok {
			missing[e.To] = struct{}{}
		}
	}

	return slices.Collect(maps.Keys(missing))
}
