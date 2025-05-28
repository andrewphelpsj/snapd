package assemblestate

import (
	"maps"
	"slices"
)

type bitset struct {
	words []uint64
}

// Set turns on the bit for id.
func (b *bitset) Set(id uint32) {
	word, bit := id/64, id%64
	if int(word) >= len(b.words) {
		cp := make([]uint64, word+1)
		copy(cp, b.words)
		b.words = cp
	}
	b.words[word] |= 1 << bit
}

// has reports whether the bit for id is set.
func (bs *bitset) has(id uint32) bool {
	word, bit := id/64, id%64
	if int(word) >= len(bs.words) {
		return false
	}
	return bs.words[word]&(1<<bit) != 0
}

type peerID uint32
type edgeID uint32

type RouteTracker struct {
	peers map[RDT]peerID

	indices map[Edge]edgeID
	edges   []Edge

	seen       map[edgeID]*bitset
	identified map[RDT]Identity
	unverified map[edgeID]struct{}
	verified   []edgeID
}

func NewRouteTracker() *RouteTracker {
	return &RouteTracker{
		peers:      make(map[RDT]peerID),
		indices:    make(map[Edge]edgeID),
		seen:       make(map[edgeID]*bitset),
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
	if id, ok := rt.indices[e]; ok {
		return id
	}

	id := edgeID(len(rt.edges))
	rt.indices[e] = id
	rt.edges = append(rt.edges, e)

	rt.unverified[id] = struct{}{}
	rt.seen[id] = &bitset{}

	return id
}

func (rt *RouteTracker) IdentifyDevices(ids []Identity) {
	dirty := false
	for _, id := range ids {
		if _, ok := rt.identified[id.RDT]; ok {
			continue
		}

		dirty = true
		rt.identified[id.RDT] = id
	}

	if !dirty {
		return
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

		rt.seen[edgeID].Set(uint32(peerID))

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
		edgeID, ok := rt.indices[e]
		if !ok {
			continue
		}

		rt.seen[edgeID].Set(uint32(peerID))
	}
	return nil
}

func (rt *RouteTracker) UnseenEdges(p RDT) []Edge {
	peerID := rt.peerID(p)
	var unseen []Edge
	for _, edgeID := range rt.verified {
		if rt.seen[edgeID].has(uint32(peerID)) {
			continue
		}

		unseen = append(unseen, rt.edges[edgeID])
	}
	return unseen
}

func (rt *RouteTracker) Verified() []Edge {
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

	edgeID, ok := rt.indices[e]
	if !ok {
		return false
	}

	return rt.seen[edgeID].has(uint32(peerID))
}

func (rt *RouteTracker) UnknownDevicesKnownBy(p RDT) []RDT {
	peerID, ok := rt.peers[p]
	if !ok {
		return nil
	}

	// use a map to dedupe RDTs
	missing := make(map[RDT]struct{}, len(rt.unverified))
	for edgeID := range rt.unverified {
		if !rt.seen[edgeID].has(uint32(peerID)) {
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
