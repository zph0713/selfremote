package tunnel

import (
	"encoding/hex"
	"os"
)

// addPeerLocked installs a peer. Static config peers keep their legacy
// semantics; registry peers are re-evaluated on every reload.
// Caller holds e.mu.
func (e *Engine) addPeerLocked(pc PeerConfig, static bool) {
	p := &peerState{cfg: pc, static: static}
	// Peers that do not require MFA are usable immediately; MFA peers stay
	// gated until a valid code arrives.
	p.authed = !p.requiresMFA()
	e.peers[hex.EncodeToString(pc.PublicKey)] = p
}

// dropPeerLocked removes any session state for p and forgets its address.
// Caller holds e.mu.
func (e *Engine) dropPeerLocked(p *peerState) {
	p.cur, p.prev = nil, nil
	p.authed = false
	if p.addr != nil {
		delete(e.addr2peer, p.addr.String())
	}
}

// applyRegistryLocked reconciles the peer set with a freshly parsed registry:
// new keys are added, vanished keys are revoked (sessions dropped at once),
// a changed MFA secret resets auth. Caller holds e.mu.
func (e *Engine) applyRegistryLocked(m map[string]PeerConfig) {
	for k, p := range e.peers {
		if p.static {
			continue // static config peers are not managed by the registry
		}
		if _, ok := m[k]; !ok {
			e.logf("registry: peer %s (%s) revoked", p.cfg.Name, p.cfg.User)
			e.dropPeerLocked(p)
			delete(e.peers, k)
		}
	}
	for k, pc := range m {
		if p, ok := e.peers[k]; ok {
			if p.cfg.TOTPSecret != pc.TOTPSecret {
				p.authAttempts = 0
				p.authed = false
			}
			p.cfg.Name = pc.Name
			p.cfg.User = pc.User
			p.cfg.TOTPSecret = pc.TOTPSecret
			continue
		}
		e.logf("registry: peer %s (%s) added", pc.Name, pc.User)
		e.addPeerLocked(pc, false)
	}
}

// reloadRegistry re-reads the clients registry when the file changed (polled
// from the tick loop; mtime-based, so writers should use atomic rename).
func (e *Engine) reloadRegistry() {
	path := e.opts.ClientsFile
	if path == "" {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		e.mu.Lock()
		firstSeen := !e.regMissing
		e.regMissing = true
		e.mu.Unlock()
		if firstSeen {
			e.logf("registry: %s not found (waiting for the control plane)", path)
		}
		return
	}
	e.mu.Lock()
	unchanged := e.regInit && !fi.ModTime().After(e.regMod) && !e.regMissing
	e.regMissing = false
	e.mu.Unlock()
	if unchanged {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	m, err := ParseRegistry(data)
	if err != nil {
		e.logf("registry: %v", err)
		e.mu.Lock()
		e.regMod = fi.ModTime()
		e.regInit = true
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	e.applyRegistryLocked(m)
	e.regMod = fi.ModTime()
	e.regInit = true
	e.mu.Unlock()
}
