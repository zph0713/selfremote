package tunnel

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// PeerRole tells the engine what a peer is: a user device reaching sites
// through the server, or a site agent publishing a network.
type PeerRole int

const (
	// RoleClient is a user device (Mac/laptop). Zero value so that peers from
	// the legacy single-gateway setup keep their old semantics.
	RoleClient PeerRole = iota
	// RoleAgent is a site edge that dials the server from behind NAT.
	RoleAgent
)

func (r PeerRole) String() string {
	if r == RoleAgent {
		return "agent"
	}
	return "client"
}

// RegistryClient is one entry of the hot-reloaded clients.json registry,
// written by the web control plane and read (and re-read) by the server.
type RegistryClient struct {
	Name       string   `json:"name"`
	User       string   `json:"user,omitempty"`
	PublicKey  string   `json:"public_key"`            // base64, 32 bytes
	Enabled    *bool    `json:"enabled,omitempty"`     // default true
	TOTPSecret string   `json:"totp_secret,omitempty"` // base32; when set, MFA is required
	TunnelIP   string   `json:"tunnel_ip,omitempty"`   // e.g. "10.77.0.2" (server relay addressing)
	Agents     []string `json:"agents,omitempty"`      // ACL: agent ids this client may reach
}

// RegistryFile is the on-disk format of clients.json.
type RegistryFile struct {
	Clients []RegistryClient `json:"clients"`
}

// RegistryRoute maps one site prefix as published by an agent.
type RegistryRoute struct {
	Real    string `json:"real"`
	Virtual string `json:"virtual,omitempty"` // empty = same as real
}

// RegistryAgent is one entry of agents.json (site edges known to the server).
type RegistryAgent struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	PublicKey  string          `json:"public_key"`        // base64, 32 bytes
	Enabled    *bool           `json:"enabled,omitempty"` // default true
	TOTPSecret string          `json:"totp_secret,omitempty"`
	TunnelIP   string          `json:"tunnel_ip,omitempty"` // agent's own address on the tunnel
	Routes     []RegistryRoute `json:"routes,omitempty"`
}

// AgentRegistryFile is the on-disk format of agents.json.
type AgentRegistryFile struct {
	Agents []RegistryAgent `json:"agents"`
}

func parsePubKey(raw string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("public_key must be base64 of 32 bytes")
	}
	return key, nil
}

// ParseRegistry parses a clients.json registry into engine-ready peers, keyed
// by hex(public key). Disabled entries are skipped.
func ParseRegistry(data []byte) (map[string]PeerConfig, error) {
	var rf RegistryFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	out := make(map[string]PeerConfig, len(rf.Clients))
	for i, c := range rf.Clients {
		if c.Enabled != nil && !*c.Enabled {
			continue
		}
		key, err := parsePubKey(c.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("registry: clients[%d] (%s): %w", i, c.Name, err)
		}
		if c.Name == "" {
			return nil, fmt.Errorf("registry: clients[%d]: name is required", i)
		}
		pc := PeerConfig{
			Name:        c.Name,
			User:        c.User,
			PublicKey:   key,
			TOTPSecret:  c.TOTPSecret,
			Role:        RoleClient,
			AllowAgents: c.Agents,
			Enabled:     true,
		}
		if c.TunnelIP != "" {
			ip, err := netip.ParseAddr(c.TunnelIP)
			if err != nil {
				return nil, fmt.Errorf("registry: clients[%d] (%s): tunnel_ip: %w", i, c.Name, err)
			}
			pc.TunnelIP = ip
		}
		out[hex.EncodeToString(key)] = pc
	}
	return out, nil
}

// ParseAgentRegistry parses an agents.json registry into engine-ready peers,
// keyed by hex(public key). Disabled entries are kept but flagged so the
// server can both refuse their traffic and tell them to stand down.
func ParseAgentRegistry(data []byte) (map[string]PeerConfig, error) {
	var rf AgentRegistryFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("agent registry: %w", err)
	}
	out := make(map[string]PeerConfig, len(rf.Agents))
	for i, a := range rf.Agents {
		key, err := parsePubKey(a.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("agent registry: agents[%d] (%s): %w", i, a.ID, err)
		}
		id := a.ID
		if id == "" {
			id = a.Name
		}
		if id == "" {
			return nil, fmt.Errorf("agent registry: agents[%d]: id is required", i)
		}
		pc := PeerConfig{
			Name:       a.Name,
			ID:         id,
			PublicKey:  key,
			TOTPSecret: a.TOTPSecret,
			Role:       RoleAgent,
			Enabled:    a.Enabled == nil || *a.Enabled,
		}
		if pc.Name == "" {
			pc.Name = id
		}
		if a.TunnelIP != "" {
			ip, err := netip.ParseAddr(a.TunnelIP)
			if err != nil {
				return nil, fmt.Errorf("agent registry: agents[%d] (%s): tunnel_ip: %w", i, id, err)
			}
			pc.TunnelIP = ip
		}
		for j, r := range a.Routes {
			m, err := ParseRouteMap(r.Real, r.Virtual)
			if err != nil {
				return nil, fmt.Errorf("agent registry: agents[%d] (%s): routes[%d]: %w", i, id, j, err)
			}
			pc.Routes = append(pc.Routes, m)
		}
		out[hex.EncodeToString(key)] = pc
	}
	return out, nil
}

// VirtualPrefixes returns the prefixes an agent presents inside the tunnel
// (what clients address and the server routes on).
func (pc PeerConfig) VirtualPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(pc.Routes))
	for _, m := range pc.Routes {
		out = append(out, m.Virtual)
	}
	return out
}

// AgentRouteStrings renders the routes for status displays.
func (pc PeerConfig) AgentRouteStrings() []string {
	out := make([]string, 0, len(pc.Routes))
	for _, m := range pc.Routes {
		out = append(out, m.String())
	}
	return out
}

// ClientAllowed reports whether this client may reach the given agent id.
func (p *peerState) ClientAllowed(agentID string) bool {
	for _, id := range p.cfg.AllowAgents {
		if strings.EqualFold(id, agentID) {
			return true
		}
	}
	return false
}
