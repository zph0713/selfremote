package tunnel

import (
	"encoding/hex"
	"os"
	"time"
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

// applyRegistryLocked reconciles the CLIENT peer set with a freshly parsed
// clients.json: new keys are added, vanished keys are revoked (sessions
// dropped at once), changed ACLs/addresses take effect immediately, a changed
// MFA secret resets auth. Caller holds e.mu.
func (e *Engine) applyRegistryLocked(m map[string]PeerConfig) {
	for k, p := range e.peers {
		if p.static || p.cfg.Role == RoleAgent {
			continue // static config peers and agents have their own paths
		}
		if _, ok := m[k]; !ok {
			e.logf("registry: peer %s (%s) revoked", p.cfg.Name, p.cfg.User)
			e.dropPeerLocked(p)
			delete(e.peers, k)
		}
	}
	for k, pc := range m {
		if p, ok := e.peers[k]; ok {
			if p.cfg.Role == RoleAgent {
				e.logf("registry: 公钥冲突 — %s 同时出现在 clients.json 与 agents.json，保留 agent 角色", pc.Name)
				continue
			}
			if p.cfg.TOTPSecret != pc.TOTPSecret {
				p.authAttempts = 0
				p.authed = false
			}
			p.cfg.Name = pc.Name
			p.cfg.User = pc.User
			p.cfg.TOTPSecret = pc.TOTPSecret
			p.cfg.TunnelIP = pc.TunnelIP
			p.cfg.AllowAgents = pc.AllowAgents
			continue
		}
		e.logf("registry: peer %s (%s) added", pc.Name, pc.User)
		e.addPeerLocked(pc, false)
	}
}

// agentCmdOut is a control command queued while holding e.mu, to be flushed
// after the lock is released.
type agentCmdOut struct {
	p      *peerState
	cmd    string
	reason string
}

// applyAgentRegistryLocked reconciles the AGENT peer set with a freshly parsed
// agents.json. Returns the enable/disable commands to send after unlocking.
// Caller holds e.mu.
func (e *Engine) applyAgentRegistryLocked(m map[string]PeerConfig) []agentCmdOut {
	var out []agentCmdOut
	for k, p := range e.peers {
		if p.static || p.cfg.Role != RoleAgent {
			continue
		}
		pc, ok := m[k]
		if !ok {
			e.logf("agent registry: agent %s (%s) 已从注册表移除，会话断开且不再接受握手", p.cfg.Name, p.cfg.id())
			e.dropPeerLocked(p)
			delete(e.peers, k)
			continue
		}
		if p.cfg.TOTPSecret != pc.TOTPSecret {
			e.logf("agent registry: agent %s 的 MFA 密钥已更新，重新认证", p.cfg.Name)
			p.cfg.TOTPSecret = pc.TOTPSecret
			p.authAttempts = 0
			p.authed = false
		}
		if p.cfg.Enabled != pc.Enabled {
			p.cfg.Enabled = pc.Enabled
			cmd, reason := "enable", "管理员在网页端启用该节点"
			if !pc.Enabled {
				cmd, reason = "disable", "管理员在网页端停用该节点"
			}
			e.logf("agent registry: %s -> %s", p.cfg.Name, cmd)
			out = append(out, agentCmdOut{p: p, cmd: cmd, reason: reason})
		}
		p.cfg.Name = pc.Name
		p.cfg.TunnelIP = pc.TunnelIP
		p.cfg.Routes = pc.Routes
	}
	for k, pc := range m {
		if p, ok := e.peers[k]; ok {
			if p.cfg.Role != RoleAgent {
				e.logf("registry: 公钥冲突 — %s 已是客户端且又出现在 agents.json，保留客户端角色", pc.Name)
			}
			continue
		}
		e.logf("agent registry: agent %s (%s) 已授权，路由 %v", pc.Name, pc.id(), pc.AgentRouteStrings())
		e.addPeerLocked(pc, false)
	}
	return out
}

// reloadRegistry re-reads the registry files that changed (polled from the
// tick loop; mtime-based, so writers must use atomic rename).
func (e *Engine) reloadRegistry() {
	e.reloadClients()
	e.reloadAgents()
}

func (e *Engine) reloadClients() {
	path := e.opts.ClientsFile
	if path == "" {
		return
	}
	data, changed := e.readIfChanged(path, &e.regMod, &e.regInit, &e.regMissing, "clients registry")
	if !changed {
		return
	}
	m, err := ParseRegistry(data)
	if err != nil {
		e.logf("registry: %v", err)
		return
	}
	e.mu.Lock()
	e.applyRegistryLocked(m)
	if e.opts.Mode == ModeServer {
		e.rebuildTablesLocked()
	}
	e.mu.Unlock()
}

func (e *Engine) reloadAgents() {
	path := e.opts.AgentsFile
	if path == "" {
		return
	}
	data, changed := e.readIfChanged(path, &e.aregMod, &e.aregInit, &e.aregMissing, "agent registry")
	if !changed {
		return
	}
	m, err := ParseAgentRegistry(data)
	if err != nil {
		e.logf("agent registry: %v", err)
		return
	}
	e.mu.Lock()
	cmds := e.applyAgentRegistryLocked(m)
	e.rebuildTablesLocked()
	e.mu.Unlock()
	for _, c := range cmds {
		e.sendAgentCmd(c.p, c.cmd, c.reason)
	}
}

// readIfChanged returns the file contents when they changed since last read.
// It tracks (modTime, initialized, missing) state per file.
func (e *Engine) readIfChanged(path string, mod *time.Time, init *bool, missing *bool, label string) ([]byte, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		e.mu.Lock()
		firstSeen := !*missing
		*missing = true
		e.mu.Unlock()
		if firstSeen {
			e.logf("%s: %s 不存在（等待控制面写入）", label, path)
		}
		return nil, false
	}
	e.mu.Lock()
	unchanged := *init && !fi.ModTime().After(*mod) && !*missing
	*missing = false
	e.mu.Unlock()
	if unchanged {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	e.mu.Lock()
	*mod = fi.ModTime()
	*init = true
	e.mu.Unlock()
	return data, true
}
