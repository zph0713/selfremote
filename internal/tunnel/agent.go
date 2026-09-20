package tunnel

import (
	"encoding/json"
	"net/netip"
	"os"
	"sort"
	"time"
)

// AgentInfo is what a site agent publishes to the server: identity, the
// prefixes it serves and liveness. It doubles as the agent's heartbeat.
type AgentInfo struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	Version  string   `json:"version,omitempty"`
	TunnelIP string   `json:"tunnel_ip,omitempty"`
	Serving  bool     `json:"serving"`
	UptimeS  int64    `json:"uptime_s"`
	Routes   []string `json:"routes,omitempty"` // "real=virtual"
	RxBytes  uint64   `json:"rx_bytes"`
	TxBytes  uint64   `json:"tx_bytes"`
	TS       string   `json:"ts,omitempty"`
}

// agentCmdMsg is a control command sent by the server to an agent.
type agentCmdMsg struct {
	Cmd    string `json:"cmd"` // disable | enable | kick | stat
	Reason string `json:"reason,omitempty"`
}

// agentInfoJSONLocked builds our announce payload. Caller holds e.mu.
func (e *Engine) agentInfoJSONLocked() []byte {
	host, _ := os.Hostname()
	var rx, tx uint64
	for _, p := range e.peers {
		rx += p.bytesIn
		tx += p.bytesOut
	}
	routes := make([]string, 0, len(e.opts.RouteMaps))
	for _, m := range e.opts.RouteMaps {
		routes = append(routes, m.String())
	}
	sort.Strings(routes)
	info := AgentInfo{
		ID:       e.opts.AgentID,
		Hostname: host,
		Version:  e.opts.Version,
		TunnelIP: tunnelIPString(e.localAddr),
		Serving:  e.forwarding.Load(),
		UptimeS:  int64(time.Since(e.agentStarted).Seconds()),
		Routes:   routes,
		RxBytes:  rx,
		TxBytes:  tx,
		TS:       time.Now().Format(time.RFC3339),
	}
	e.lastAgentInfo = &info
	return mustJSON(info)
}

// tunnelIPString renders an optional tunnel address.
func tunnelIPString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// AgentStatus is a snapshot of an agent-mode engine for status displays.
func (e *Engine) AgentStatus() *AgentInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastAgentInfo == nil {
		// Not announced yet: report the live view.
		e.agentInfoJSONLocked()
	}
	if e.lastAgentInfo == nil {
		return nil
	}
	cp := *e.lastAgentInfo
	cp.Serving = e.forwarding.Load()
	return &cp
}

// Forwarding reports whether the agent currently moves traffic.
func (e *Engine) Forwarding() bool { return e.forwarding.Load() }

// handleAgentInfo (server): store what the agent reported and flag drift
// between the running agent and the web-managed registry.
func (e *Engine) handleAgentInfo(p *peerState, pt []byte) {
	var info AgentInfo
	if err := json.Unmarshal(pt, &info); err != nil {
		return
	}
	e.mu.Lock()
	first := p.info == nil
	p.info = &info
	p.announceAt = time.Now()
	mismatch := !sameRoutes(p.cfg.AgentRouteStrings(), info.Routes)
	if mismatch != p.mismatch {
		if mismatch {
			e.logf("agent %s: 上报的网段与注册表不一致（agent: %v，注册表: %v）— 请在网页端核对后重新下发配置",
				p.cfg.Name, info.Routes, p.cfg.AgentRouteStrings())
		}
		p.mismatch = mismatch
	}
	e.mu.Unlock()
	if first {
		e.logf("agent %s (%s) announce: 版本 %s, 网段 %v, 隧道 %s",
			p.cfg.Name, info.Hostname, info.Version, info.Routes, info.TunnelIP)
	}
}

// sameRoutes compares two string sets (order-insensitive).
func sameRoutes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// handleAgentCmd (agent): apply a control command from the server.
func (e *Engine) handleAgentCmd(p *peerState, pt []byte) {
	var m agentCmdMsg
	if err := json.Unmarshal(pt, &m); err != nil {
		return
	}
	switch m.Cmd {
	case "disable":
		if e.forwarding.Swap(false) {
			e.logf("agent: 服务端已停用本节点（%s），隧道转发暂停，进程继续保持心跳", m.Reason)
		}
	case "enable":
		if !e.forwarding.Swap(true) {
			e.logf("agent: 服务端已重新启用本节点，隧道转发恢复")
		}
	case "kick":
		e.logf("agent: 服务端要求重连（%s）", m.Reason)
		e.mu.Lock()
		p.cur, p.prev = nil, nil
		p.authed = false
		p.authSentAt = time.Time{}
		p.nextAttempt = time.Now()
		p.hs = nil
		e.mu.Unlock()
	case "stat":
		e.mu.Lock()
		e.announceAt = time.Time{} // force an announce on the next tick
		e.mu.Unlock()
	}
}

// sendAgentCmd seals and sends a control command to an agent peer.
func (e *Engine) sendAgentCmd(p *peerState, cmd, reason string) {
	payload := mustJSON(agentCmdMsg{Cmd: cmd, Reason: reason})
	e.sendSealed(p, frameAgentCmd, payload)
}

// agentByIDLocked finds an agent peer by its registry id. Caller holds e.mu.
func (e *Engine) agentByIDLocked(id string) *peerState {
	for _, p := range e.peers {
		if p.cfg.Role == RoleAgent && p.cfg.id() == id {
			return p
		}
	}
	return nil
}

// KickAgent tells an agent to reconnect right away and drops its session.
// Returns false when no agent with that id is registered.
func (e *Engine) KickAgent(id string) bool {
	e.mu.Lock()
	target := e.agentByIDLocked(id)
	connected := target != nil && target.cur != nil
	e.mu.Unlock()
	if target == nil {
		return false
	}
	if connected {
		// Tell it first (the frame needs the old session), then drop our side
		// so the agent shows up as offline until it reconnects.
		e.sendAgentCmd(target, "kick", "管理员要求重连")
		e.mu.Lock()
		target.cur, target.prev = nil, nil
		target.resetAuth()
		e.mu.Unlock()
	}
	return true
}

// RefreshAgent asks an agent to announce its status immediately.
func (e *Engine) RefreshAgent(id string) bool {
	e.mu.Lock()
	target := e.agentByIDLocked(id)
	e.mu.Unlock()
	if target == nil {
		return false
	}
	e.sendAgentCmd(target, "stat", "")
	return true
}
