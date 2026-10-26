package tunnel

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Per-flow port accounting for the hub's observability pages.
//
// The hub is an L3 relay: it sees whole IP packets and already parses their
// headers for routing (relay.go). The only extra work here is reading the four
// bytes of the transport port, so one map lookup per forwarded packet is the
// entire hot-path cost. The table is bounded — when it fills up it degrades to
// "counters only" instead of growing without limit, because observability must
// never be able to take the data plane down.
//
// Key choice: (agent, client, proto, site address, site port). Not the full
// 5-tuple (source port adds nothing the UI needs and multiplies the entry
// count by the number of connections), and not a bare per-peer port counter
// (which cannot say *which* machine inside the site is being reached or by
// which client). Both directions of one conversation land on the same key:
// towards the site the destination is (dst IP, dst port), from the site the
// service endpoint is (src IP, src port).
const (
	defaultFlowLimit  = 4096
	flowIdleTTL       = 2 * time.Minute
	flowSweepInterval = time.Second
	flowRateMinDelta  = 500 * time.Millisecond
	flowRateEMA       = 0.5
)

// flowKey identifies one conversation direction-agnostically.
type flowKey struct {
	agent  uint64 // peerState.uid of the site agent
	client uint64 // peerState.uid of the client device
	proto  uint8  // IP protocol number
	site   netip.Addr
	port   uint16 // 0 for ICMP and for fragments without a transport header
}

// flowEntry holds the counters of one flow. Bytes/packets are atomics so the
// relay can update them without taking the table lock for counters; the lock
// still guards insertion/eviction and the rate sampler.
type flowEntry struct {
	toPkts, toBytes     atomic.Uint64
	fromPkts, fromBytes atomic.Uint64
	firstSeen           time.Time
	lastSeen            atomic.Int64 // unix nanoseconds

	// Rate sampling state, guarded by flowTable.mu.
	rateAt   time.Time
	rateTo   uint64
	rateFrom uint64
	bpsTo    float64
	bpsFrom  float64
}

// flowTable is a bounded flow map with idle eviction.
type flowTable struct {
	mu          sync.Mutex
	m           map[flowKey]*flowEntry
	max         int
	lastSweep   time.Time
	unaccounted uint64 // packets dropped from accounting because the table was full
}

func newFlowTable(max int) *flowTable {
	if max <= 0 {
		max = defaultFlowLimit
	}
	return &flowTable{m: make(map[flowKey]*flowEntry, 128), max: max}
}

// observe records one forwarded packet. toSite reports the direction.
func (t *flowTable) observe(k flowKey, toSite bool, n int) {
	now := time.Now()
	t.mu.Lock()
	e := t.m[k]
	if e == nil {
		if len(t.m) >= t.max {
			t.sweepLocked(now)
			if len(t.m) >= t.max {
				t.unaccounted++
				t.mu.Unlock()
				return
			}
		}
		e = &flowEntry{firstSeen: now, rateAt: now}
		t.m[k] = e
	}
	if toSite {
		e.toPkts.Add(1)
		e.toBytes.Add(uint64(n))
	} else {
		e.fromPkts.Add(1)
		e.fromBytes.Add(uint64(n))
	}
	e.lastSeen.Store(now.UnixNano())
	t.mu.Unlock()
}

// sweepLocked evicts idle flows, then the oldest tenth when the table is still
// full. Caller holds t.mu.
func (t *flowTable) sweepLocked(now time.Time) {
	if !t.lastSweep.IsZero() && now.Sub(t.lastSweep) < flowSweepInterval {
		return
	}
	t.lastSweep = now
	cut := now.Add(-flowIdleTTL).UnixNano()
	for k, e := range t.m {
		if e.lastSeen.Load() < cut {
			delete(t.m, k)
		}
	}
	if len(t.m) < t.max {
		return
	}
	// Still full: drop the oldest 10% by last-seen so a burst of short-lived
	// flows cannot pin the table forever.
	type aged struct {
		k  flowKey
		at int64
	}
	all := make([]aged, 0, len(t.m))
	for k, e := range t.m {
		all = append(all, aged{k, e.lastSeen.Load()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at < all[j].at })
	drop := len(all) / 10
	if drop < 1 {
		drop = 1
	}
	for i := 0; i < drop; i++ {
		delete(t.m, all[i].k)
	}
}

// flowSample is one flow with the rates computed at snapshot time.
type flowSample struct {
	key       flowKey
	toPkts    uint64
	toBytes   uint64
	fromPkts  uint64
	fromBytes uint64
	bpsTo     uint64
	bpsFrom   uint64
	firstSeen time.Time
	lastSeen  time.Time
}

// sample snapshots every flow and refreshes the per-flow rates. Called at most
// a couple of times per second (the control API caches its own snapshot), so
// the O(n) walk and the lock hold are cheap.
func (t *flowTable) sample(now time.Time) []flowSample {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]flowSample, 0, len(t.m))
	for k, e := range t.m {
		to := e.toBytes.Load()
		from := e.fromBytes.Load()
		if dt := now.Sub(e.rateAt).Seconds(); dt >= flowRateMinDelta.Seconds() {
			instTo := float64(to-e.rateTo) / dt
			instFrom := float64(from-e.rateFrom) / dt
			if e.bpsTo == 0 && e.bpsFrom == 0 && e.rateTo == 0 && e.rateFrom == 0 {
				e.bpsTo, e.bpsFrom = instTo, instFrom
			} else {
				e.bpsTo = flowRateEMA*e.bpsTo + (1-flowRateEMA)*instTo
				e.bpsFrom = flowRateEMA*e.bpsFrom + (1-flowRateEMA)*instFrom
			}
			e.rateAt, e.rateTo, e.rateFrom = now, to, from
		}
		out = append(out, flowSample{
			key:       k,
			toPkts:    e.toPkts.Load(),
			toBytes:   to,
			fromPkts:  e.fromPkts.Load(),
			fromBytes: from,
			bpsTo:     uint64(e.bpsTo),
			bpsFrom:   uint64(e.bpsFrom),
			firstSeen: e.firstSeen,
			lastSeen:  time.Unix(0, e.lastSeen.Load()),
		})
	}
	return out
}

func (t *flowTable) stats() (flows int, unaccounted uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m), t.unaccounted
}

// ---------------------------------------------------------------------------
// Public snapshot types (consumed by the control API and the web plane).

// FlowRow is one conversation as the UI shows it.
type FlowRow struct {
	AgentID     string `json:"agent_id"`
	AgentName   string `json:"agent_name"`
	ClientID    string `json:"client_id"`
	ClientName  string `json:"client_name"`
	Proto       uint8  `json:"proto"`
	ProtoName   string `json:"proto_name"`
	SiteIP      string `json:"site_ip"`
	Port        uint16 `json:"port"`
	BytesToSite uint64 `json:"bytes_to_site"`
	BytesFrom   uint64 `json:"bytes_from_site"`
	PktsToSite  uint64 `json:"pkts_to_site"`
	PktsFrom    uint64 `json:"pkts_from_site"`
	BpsToSite   uint64 `json:"bps_to_site"`
	BpsFrom     uint64 `json:"bps_from_site"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
}

// PortRow is one (proto, site address, port) aggregate for one peer.
type PortRow struct {
	Proto       uint8  `json:"proto"`
	ProtoName   string `json:"proto_name"`
	SiteIP      string `json:"site_ip"`
	Port        uint16 `json:"port"`
	Clients     int    `json:"clients,omitempty"`
	BytesToSite uint64 `json:"bytes_to_site"`
	BytesFrom   uint64 `json:"bytes_from_site"`
	PktsToSite  uint64 `json:"pkts_to_site"`
	PktsFrom    uint64 `json:"pkts_from_site"`
	BpsToSite   uint64 `json:"bps_to_site"`
	BpsFrom     uint64 `json:"bps_from_site"`
	LastSeen    string `json:"last_seen"`
}

type peerRef struct {
	ID   string
	Name string
	Role string
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	}
	return fmt.Sprintf("proto-%d", p)
}

// peerRefs maps peer uid -> display identity. Caller must not hold e.mu.
func (e *Engine) peerRefs() map[uint64]peerRef {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[uint64]peerRef, len(e.peers))
	for _, p := range e.peers {
		out[p.uid] = peerRef{ID: p.cfg.id(), Name: p.cfg.Name, Role: p.cfg.Role.String()}
	}
	return out
}

// FlowSnapshot returns the busiest flows, newest rates included.
func (e *Engine) FlowSnapshot(limit int) []FlowRow {
	refs := e.peerRefs()
	samples := e.flows.sample(time.Now())
	rows := make([]FlowRow, 0, len(samples))
	for _, s := range samples {
		ag, okA := refs[s.key.agent]
		cl, okC := refs[s.key.client]
		if !okA || !okC {
			continue // peer was revoked; the entry ages out on its own
		}
		rows = append(rows, FlowRow{
			AgentID:     ag.ID,
			AgentName:   ag.Name,
			ClientID:    cl.ID,
			ClientName:  cl.Name,
			Proto:       s.key.proto,
			ProtoName:   protoName(s.key.proto),
			SiteIP:      s.key.site.String(),
			Port:        s.key.port,
			BytesToSite: s.toBytes,
			BytesFrom:   s.fromBytes,
			PktsToSite:  s.toPkts,
			PktsFrom:    s.fromPkts,
			BpsToSite:   s.bpsTo,
			BpsFrom:     s.bpsFrom,
			FirstSeen:   s.firstSeen.Format(time.RFC3339),
			LastSeen:    s.lastSeen.Format(time.RFC3339),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].BytesToSite+rows[i].BytesFrom > rows[j].BytesToSite+rows[j].BytesFrom
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// PeerPorts aggregates the flows of one peer (agent id or client id) by
// (proto, site address, port). Returns nil when the peer is unknown.
func (e *Engine) PeerPorts(peerID string, limit int) []PortRow {
	refs := e.peerRefs()
	var target uint64
	found := false
	for uid, r := range refs {
		if r.ID == peerID {
			target, found = uid, true
			break
		}
	}
	if !found {
		return nil
	}
	type aggKey struct {
		proto uint8
		site  netip.Addr
		port  uint16
	}
	type agg struct {
		row     PortRow
		clients map[uint64]struct{}
	}
	samples := e.flows.sample(time.Now())
	aggs := make(map[aggKey]*agg)
	for _, s := range samples {
		if s.key.agent != target && s.key.client != target {
			continue
		}
		k := aggKey{s.key.proto, s.key.site, s.key.port}
		a := aggs[k]
		if a == nil {
			a = &agg{
				row: PortRow{
					Proto:     s.key.proto,
					ProtoName: protoName(s.key.proto),
					SiteIP:    s.key.site.String(),
					Port:      s.key.port,
				},
				clients: make(map[uint64]struct{}, 2),
			}
			aggs[k] = a
		}
		a.row.BytesToSite += s.toBytes
		a.row.BytesFrom += s.fromBytes
		a.row.PktsToSite += s.toPkts
		a.row.PktsFrom += s.fromPkts
		a.row.BpsToSite += s.bpsTo
		a.row.BpsFrom += s.bpsFrom
		a.row.Clients = len(a.clients) // refreshed below
		if s.key.client == target {
			a.clients[s.key.agent] = struct{}{} // peer is a client: count sites touched
		} else {
			a.clients[s.key.client] = struct{}{}
		}
		if ts := s.lastSeen.Format(time.RFC3339); ts > a.row.LastSeen {
			a.row.LastSeen = ts
		}
	}
	out := make([]PortRow, 0, len(aggs))
	for _, a := range aggs {
		a.row.Clients = len(a.clients)
		out = append(out, a.row)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].BytesToSite+out[i].BytesFrom > out[j].BytesToSite+out[j].BytesFrom
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// FlowStats reports the table occupancy (diagnostics).
func (e *Engine) FlowStats() (flows int, unaccounted uint64) {
	return e.flows.stats()
}

// flowKeyFor builds the flow key of one forwarded packet. The site endpoint is
// the destination on the way in and the source on the way out.
func flowKeyFor(client, agent *peerState, pkt []byte, h *ipHeaderView, toSite bool) flowKey {
	k := flowKey{
		agent:  agent.uid,
		client: client.uid,
		proto:  h.l4Proto,
	}
	if toSite {
		k.site = h.dst
	} else {
		k.site = h.src
	}
	// Only TCP/UDP/SCTP carry ports; ICMP and non-first fragments do not.
	if h.l4Off >= 0 && len(pkt) >= h.l4Off+4 {
		switch h.l4Proto {
		case 6, 17, 132:
			if toSite {
				k.port = binary.BigEndian.Uint16(pkt[h.l4Off+2 : h.l4Off+4])
			} else {
				k.port = binary.BigEndian.Uint16(pkt[h.l4Off : h.l4Off+2])
			}
		}
	}
	return k
}
