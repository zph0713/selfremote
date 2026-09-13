package tunnel

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"
)

// The server is a user-space relay: it terminates both tunnels (clients and
// agents) and moves IP packets between them. Two properties matter more than
// anything else here:
//
//   - anti-spoofing: a client may only send packets whose source is its own
//     tunnel address; an agent may only send packets whose source lies inside
//     the prefixes it published (plus its own tunnel address).
//   - least privilege: a client reaches an agent only when the web-managed
//     ACL grants it, and only while the agent is enabled, connected and
//     authenticated. Sites cannot reach each other, and clients cannot reach
//     each other — the hub only forwards client <-> agent.
//
// The relay needs no TUN device and no kernel routing: it never touches the
// host network stack.

// routeEntry is one row of the server's routing table.
type routeEntry struct {
	prefix netip.Prefix
	peer   *peerState
}

// relayCounters counts what the hub did with packets (exposed to the web UI).
type relayCounters struct {
	Forwarded atomic.Uint64
	ToAgents  atomic.Uint64
	ToClients atomic.Uint64
	LocalICMP atomic.Uint64
	NoRoute   atomic.Uint64
	Denied    atomic.Uint64
	Spoofed   atomic.Uint64
	Offline   atomic.Uint64
	Malformed atomic.Uint64
}

// RelayStats is a snapshot of the relay counters.
type RelayStats struct {
	Forwarded uint64 `json:"forwarded"`
	ToAgents  uint64 `json:"to_agents"`
	ToClients uint64 `json:"to_clients"`
	LocalICMP uint64 `json:"local_icmp"`
	NoRoute   uint64 `json:"dropped_no_route"`
	Denied    uint64 `json:"dropped_denied"`
	Spoofed   uint64 `json:"dropped_spoofed"`
	Offline   uint64 `json:"dropped_offline"`
	Malformed uint64 `json:"dropped_malformed"`
}

// RelayStats returns the counters (server mode).
func (e *Engine) RelayStats() RelayStats {
	return RelayStats{
		Forwarded: e.relay.Forwarded.Load(),
		ToAgents:  e.relay.ToAgents.Load(),
		ToClients: e.relay.ToClients.Load(),
		LocalICMP: e.relay.LocalICMP.Load(),
		NoRoute:   e.relay.NoRoute.Load(),
		Denied:    e.relay.Denied.Load(),
		Spoofed:   e.relay.Spoofed.Load(),
		Offline:   e.relay.Offline.Load(),
		Malformed: e.relay.Malformed.Load(),
	}
}

// Conflicts returns the duplicate-prefix conflicts spotted while building the
// routing table (web shows them as a configuration warning).
func (e *Engine) Conflicts() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.conflicts...)
}

// rebuildTablesLocked rebuilds the routing table (virtual prefix -> agent) and
// the client lookup (tunnel IP -> client) from the current peer set.
// Caller holds e.mu.
func (e *Engine) rebuildTablesLocked() {
	byIP := make(map[netip.Addr]*peerState)
	byAgentIP := make(map[netip.Addr]*peerState)
	agents := make([]*peerState, 0, len(e.peers))
	for _, p := range e.peers {
		switch p.cfg.Role {
		case RoleAgent:
			agents = append(agents, p)
			if p.cfg.TunnelIP.IsValid() {
				byAgentIP[p.cfg.TunnelIP] = p
			}
		default:
			if p.cfg.TunnelIP.IsValid() {
				byIP[p.cfg.TunnelIP] = p
			}
		}
	}
	// Deterministic order so conflicts resolve the same way every reload.
	sort.Slice(agents, func(i, j int) bool { return agents[i].cfg.id() < agents[j].cfg.id() })

	seen := make(map[netip.Prefix]string, len(agents))
	entries := make([]routeEntry, 0, len(agents))
	var conflicts []string
	for _, p := range agents {
		for _, m := range p.cfg.Routes {
			if owner, dup := seen[m.Virtual]; dup {
				conflicts = append(conflicts,
					fmt.Sprintf("%s 与 %s 都声明了 %s（后者被忽略，请改虚拟网段）", p.cfg.id(), owner, m.Virtual))
				continue
			}
			seen[m.Virtual] = p.cfg.id()
			entries = append(entries, routeEntry{prefix: m.Virtual, peer: p})
		}
	}
	// Longest prefix first: the relay walks the table in order.
	sort.Slice(entries, func(i, j int) bool { return entries[i].prefix.Bits() > entries[j].prefix.Bits() })

	e.routes = entries
	e.clientsByIP = byIP
	e.agentsByIP = byAgentIP
	e.conflicts = conflicts
}

// routeLookupLocked finds the agent serving dst. Caller holds e.mu.
func (e *Engine) routeLookupLocked(dst netip.Addr) *peerState {
	for _, r := range e.routes {
		if r.prefix.Contains(dst) {
			return r.peer
		}
	}
	return nil
}

// isLocalAddr reports whether addr is one of our own tunnel addresses.
func (e *Engine) isLocalAddr(a netip.Addr) bool {
	return e.localAddr.IsValid() && a == e.localAddr
}

// relayFromPeer is the server's entry point for a decrypted DATA payload.
func (e *Engine) relayFromPeer(p *peerState, pkt []byte) {
	h, err := parseIPHeader(pkt)
	if err != nil {
		e.relay.Malformed.Add(1)
		e.logDrop(p, "无法解析的 IP 包")
		return
	}
	if p.cfg.Role == RoleAgent {
		e.relayFromAgent(p, pkt, h)
		return
	}
	e.relayFromClient(p, pkt, h)
}

// relayFromClient forwards a client packet to the agent that serves its
// destination.
func (e *Engine) relayFromClient(p *peerState, pkt []byte, h *ipHeaderView) {
	if !p.cfg.TunnelIP.IsValid() || h.src != p.cfg.TunnelIP {
		e.relay.Spoofed.Add(1)
		e.logDrop(p, fmt.Sprintf("源地址 %s 不是它的隧道地址 %s", h.src, p.cfg.TunnelIP))
		return
	}
	if e.isLocalAddr(h.dst) {
		// Traffic addressed to the hub itself: answer pings so users can
		// tell "server reachable" from "site unreachable".
		if e.replyLocalICMP(p, pkt, h) {
			e.relay.LocalICMP.Add(1)
		}
		return
	}
	e.mu.Lock()
	// Traffic to an agent's own tunnel address (diagnostics: ping the site
	// edge) goes straight to that agent; everything else follows the routes.
	ag := e.agentsByIP[h.dst]
	if ag == nil {
		ag = e.routeLookupLocked(h.dst)
	}
	allowed := ag != nil && p.ClientAllowed(ag.cfg.id())
	live := ag != nil && ag.cfg.Enabled && ag.cur != nil && ag.authed
	e.mu.Unlock()

	switch {
	case ag == nil:
		e.relay.NoRoute.Add(1)
		e.logDrop(p, fmt.Sprintf("没有 agent 声明网段 %s", h.dst))
		return
	case !allowed:
		e.relay.Denied.Add(1)
		e.logDrop(p, fmt.Sprintf("没有访问站点 %s 的权限（请在网页端为该设备勾选站点）", ag.cfg.id()))
		return
	case !live:
		e.relay.Offline.Add(1)
		e.logDrop(p, fmt.Sprintf("站点 %s 当前不可用", ag.cfg.id()))
		return
	}
	if e.sendTo(ag, pkt) {
		e.relay.Forwarded.Add(1)
		e.relay.ToAgents.Add(1)
	}
}

// relayFromAgent forwards a site packet back to the client it is addressed to.
func (e *Engine) relayFromAgent(p *peerState, pkt []byte, h *ipHeaderView) {
	if !p.allowsSource(h.src) {
		e.relay.Spoofed.Add(1)
		e.logDrop(p, fmt.Sprintf("源地址 %s 不在它声明的网段内", h.src))
		return
	}
	e.mu.Lock()
	cl := e.clientsByIP[h.dst]
	allowed := cl != nil && cl.ClientAllowed(p.cfg.id())
	live := cl != nil && cl.cfg.Enabled && cl.cur != nil && cl.authed
	e.mu.Unlock()

	switch {
	case cl == nil:
		e.relay.NoRoute.Add(1)
		e.logDrop(p, fmt.Sprintf("目标 %s 不是已注册的客户端隧道地址", h.dst))
		return
	case !allowed:
		e.relay.Denied.Add(1)
		e.logDrop(p, fmt.Sprintf("客户端 %s 无权访问本站点", cl.cfg.Name))
		return
	case !live:
		e.relay.Offline.Add(1)
		e.logDrop(p, fmt.Sprintf("客户端 %s 当前不在线", cl.cfg.Name))
		return
	}
	if e.sendTo(cl, pkt) {
		e.relay.Forwarded.Add(1)
		e.relay.ToClients.Add(1)
	}
}

// allowsSource reports whether src may legitimately originate from this agent.
func (p *peerState) allowsSource(src netip.Addr) bool {
	if p.cfg.TunnelIP.IsValid() && src == p.cfg.TunnelIP {
		return true
	}
	for _, m := range p.cfg.Routes {
		if m.Virtual.Contains(src) {
			return true
		}
	}
	return false
}

// replyLocalICMP answers an ICMP echo request addressed to the hub's own
// tunnel address, in place. Returns false when the packet is not a ping.
func (e *Engine) replyLocalICMP(p *peerState, pkt []byte, h *ipHeaderView) bool {
	if h.l4Off < 0 || len(pkt) < h.l4Off+8 {
		return false
	}
	l4 := pkt[h.l4Off:]
	switch {
	case h.v4 && h.l4Proto == 1 && l4[0] == 8: // ICMPv4 echo request
		copy(pkt[h.srcOff:h.srcOff+4], h.dst.AsSlice())
		copy(pkt[h.dstOff:h.dstOff+4], h.src.AsSlice())
		l4[0] = 0 // echo reply
		l4[2], l4[3] = 0, 0
		binary.BigEndian.PutUint16(l4[2:4], onesComplement(l4))
		pkt[10], pkt[11] = 0, 0
		binary.BigEndian.PutUint16(pkt[10:12], onesComplement(pkt[:h.l4Off]))
	case !h.v4 && h.l4Proto == 58 && l4[0] == 128: // ICMPv6 echo request
		src, dst := h.dst, h.src // the reply swaps them
		copy(pkt[h.srcOff:h.srcOff+16], h.dst.AsSlice())
		copy(pkt[h.dstOff:h.dstOff+16], h.src.AsSlice())
		l4[0] = 129 // echo reply
		l4[2], l4[3] = 0, 0
		pseudo := make([]byte, 0, 40+len(l4))
		pseudo = append(pseudo, src.AsSlice()...)
		pseudo = append(pseudo, dst.AsSlice()...)
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(l4)))
		pseudo = append(pseudo, lb[:]...)
		pseudo = append(pseudo, 0, 0, 0, 58)
		pseudo = append(pseudo, l4...)
		binary.BigEndian.PutUint16(l4[2:4], onesComplement(pseudo))
	default:
		return false
	}
	e.sendTo(p, pkt)
	return true
}

// logDrop rate-limits per-peer drop logging (the packet path is hot).
func (e *Engine) logDrop(p *peerState, reason string) {
	e.mu.Lock()
	quiet := time.Since(p.dropAt) < 5*time.Second
	if !quiet {
		p.dropAt = time.Now()
	}
	e.mu.Unlock()
	if !quiet {
		e.logf("relay: 丢弃来自 %s(%s) 的包：%s", p.cfg.Name, p.cfg.Role, reason)
	}
}

// dropAt counts and (rate-limited) logs a packet dropped at the local edge —
// used by agent mode when address translation rejects a packet.
func (e *Engine) dropAt(reason string, pkt ...[]byte) {
	e.agentDrops.Add(1)
	e.mu.Lock()
	quiet := time.Since(e.agentDropLog) < 5*time.Second
	if !quiet {
		e.agentDropLog = time.Now()
	}
	e.mu.Unlock()
	if quiet {
		return
	}
	if len(pkt) > 0 {
		if h, err := parseIPHeader(pkt[0]); err == nil {
			e.logf("agent: 丢弃数据包（%s）：%s -> %s proto %d", reason, h.src, h.dst, h.l4Proto)
			return
		}
	}
	e.logf("agent: 丢弃数据包（%s）", reason)
}

// AgentDrops returns how many packets the agent edge discarded.
func (e *Engine) AgentDrops() uint64 { return e.agentDrops.Load() }
