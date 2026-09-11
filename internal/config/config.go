// Package config loads and validates selfremote configuration files.
package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// Key is a 32-byte X25519 key.
type Key [32]byte

// ParseKey decodes a base64-encoded 32-byte key.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("invalid base64: %w", err)
	}
	if len(b) != 32 {
		return k, fmt.Errorf("key must be 32 bytes, got %d", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// Peer is an authorized client of the gateway.
type Peer struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// Gateway is the NAS-side (home) configuration.
type Gateway struct {
	Listen     string `json:"listen"`      // e.g. "[::]:28333"
	PrivateKey string `json:"private_key"` // base64
	TunnelCIDR string `json:"tunnel_cidr"` // e.g. "10.77.0.1/24"
	Peers      []Peer `json:"peers"`

	// Web control plane integration (all optional).
	ClientsFile string `json:"clients_file,omitempty"` // hot-reloaded client registry (JSON)
	StatusFile  string `json:"status_file,omitempty"`  // live status written for the web UI
	NetInfoFile string `json:"netinfo_file,omitempty"` // host network info written for the web UI

	// Parsed on load.
	Private  Key   `json:"-"`
	PeerKeys []Key `json:"-"`
}

// Client is the Mac-side configuration.
type Client struct {
	Server          string   `json:"server"` // host:port, e.g. "nas.example.com:28333"
	PrivateKey      string   `json:"private_key"`
	ServerPublicKey string   `json:"server_public_key"`
	TunnelCIDR      string   `json:"tunnel_cidr"` // e.g. "10.77.0.2/24"
	Routes          []string `json:"routes"`      // e.g. ["192.168.1.0/24"]

	// Parsed on load.
	Private      Key `json:"-"`
	ServerPublic Key `json:"-"`
}

// LoadGateway reads, validates and parses a gateway config file.
func LoadGateway(path string) (*Gateway, error) {
	var g Gateway
	if err := load(path, &g); err != nil {
		return nil, err
	}
	if g.Listen == "" {
		return nil, fmt.Errorf("%s: listen is required", path)
	}
	var err error
	if g.Private, err = ParseKey(g.PrivateKey); err != nil {
		return nil, fmt.Errorf("%s: private_key: %w", path, err)
	}
	if len(g.Peers) == 0 && g.ClientsFile == "" {
		return nil, fmt.Errorf("%s: at least one peer (or clients_file) is required", path)
	}
	for i, p := range g.Peers {
		k, err := ParseKey(p.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%s: peers[%d].public_key: %w", path, i, err)
		}
		g.PeerKeys = append(g.PeerKeys, k)
	}
	return &g, nil
}

// LoadClient reads, validates and parses a client config file.
func LoadClient(path string) (*Client, error) {
	var c Client
	if err := load(path, &c); err != nil {
		return nil, err
	}
	if err := c.validate(path); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadClientBytes parses a client config from raw bytes (e.g. after
// decrypting a key file). name is used in error messages.
func LoadClientBytes(data []byte, name string) (*Client, error) {
	var c Client
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	if err := c.validate(name); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Client) validate(name string) error {
	if c.Server == "" {
		return fmt.Errorf("%s: server is required", name)
	}
	var err error
	if c.Private, err = ParseKey(c.PrivateKey); err != nil {
		return fmt.Errorf("%s: private_key: %w", name, err)
	}
	if c.ServerPublic, err = ParseKey(c.ServerPublicKey); err != nil {
		return fmt.Errorf("%s: server_public_key: %w", name, err)
	}
	return nil
}

func load(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}
