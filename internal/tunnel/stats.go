package tunnel

import (
	"sort"
	"time"
)

// PeerStats is a snapshot of one peer, used by CLI status displays and the
// web control plane.
type PeerStats struct {
	Name      string
	User      string
	MFA       bool
	Connected bool
	Authed    bool
	Remote    string
	Since     time.Time
	LastRecv  time.Time
	BytesIn   uint64
	BytesOut  uint64
}

// Stats returns a snapshot of all peers.
func (e *Engine) Stats() []PeerStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]PeerStats, 0, len(e.peers))
	for _, p := range e.peers {
		st := PeerStats{
			Name:      p.cfg.Name,
			User:      p.cfg.User,
			MFA:       p.requiresMFA(),
			Connected: p.cur != nil,
			Authed:    p.authed,
			LastRecv:  p.lastRecv,
			BytesIn:   p.bytesIn,
			BytesOut:  p.bytesOut,
		}
		if p.cur != nil {
			st.Since = p.cur.established
		}
		if p.addr != nil {
			st.Remote = p.addr.String()
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
