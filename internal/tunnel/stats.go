package tunnel

import (
	"sort"
	"time"
)

// PeerStats is a snapshot of one peer, used by CLI status displays, the server
// control API and the web control plane.
type PeerStats struct {
	Name      string `json:"name"`
	User      string `json:"user,omitempty"`
	ID        string `json:"id,omitempty"`
	Role      string `json:"role"`
	MFA       bool   `json:"mfa"`
	Connected bool   `json:"connected"`
	Authed    bool   `json:"authed"`
	Remote    string `json:"remote,omitempty"`
	Since     string `json:"since,omitempty"`
	LastRecv  string `json:"last_recv,omitempty"`
	BytesIn   uint64 `json:"rx_bytes"`
	BytesOut  uint64 `json:"tx_bytes"`

	// Agent peers (server view).
	Enabled    *bool      `json:"enabled,omitempty"`
	TunnelIP   string     `json:"tunnel_ip,omitempty"`
	Routes     []string   `json:"routes,omitempty"`
	AnnounceAt string     `json:"announce_at,omitempty"`
	Mismatch   bool       `json:"config_mismatch,omitempty"`
	Info       *AgentInfo `json:"info,omitempty"`

	// Client peers (server view).
	AllowAgents []string `json:"allow_agents,omitempty"`
}

// Stats returns a snapshot of all peers.
func (e *Engine) Stats() []PeerStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]PeerStats, 0, len(e.peers))
	for _, p := range e.peers {
		st := PeerStats{
			Name:        p.cfg.Name,
			User:        p.cfg.User,
			ID:          p.cfg.id(),
			Role:        p.cfg.Role.String(),
			MFA:         p.requiresMFA(),
			Connected:   p.cur != nil,
			Authed:      p.authed,
			LastRecv:    fmtTime(p.lastRecv),
			BytesIn:     p.bytesIn,
			BytesOut:    p.bytesOut,
			TunnelIP:    tunnelIPString(p.cfg.TunnelIP),
			Routes:      p.cfg.AgentRouteStrings(),
			AnnounceAt:  fmtTime(p.announceAt),
			Mismatch:    p.mismatch,
			AllowAgents: append([]string(nil), p.cfg.AllowAgents...),
		}
		if p.cfg.Role == RoleAgent {
			enabled := p.cfg.Enabled
			st.Enabled = &enabled
		}
		if p.info != nil {
			cp := *p.info
			st.Info = &cp
		}
		if p.cur != nil {
			st.Since = p.cur.established.Format(time.RFC3339)
		}
		if p.addr != nil {
			st.Remote = p.addr.String()
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
