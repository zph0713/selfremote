package tunnel

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// RegistryClient is one entry of the hot-reloaded clients.json registry,
// written by the web control plane and read (and re-read) by the gateway.
type RegistryClient struct {
	Name       string `json:"name"`
	User       string `json:"user,omitempty"`
	PublicKey  string `json:"public_key"`            // base64, 32 bytes
	Enabled    *bool  `json:"enabled,omitempty"`     // default true
	TOTPSecret string `json:"totp_secret,omitempty"` // base32; when set, MFA is required
}

// RegistryFile is the on-disk format of clients.json.
type RegistryFile struct {
	Clients []RegistryClient `json:"clients"`
}

// ParseRegistry parses a clients.json registry into engineer-ready peers,
// keyed by hex(public key). Disabled entries are skipped.
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
		key, err := base64.StdEncoding.DecodeString(c.PublicKey)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("registry: clients[%d] (%s): public_key must be base64 of 32 bytes", i, c.Name)
		}
		if c.Name == "" {
			return nil, fmt.Errorf("registry: clients[%d]: name is required", i)
		}
		out[hex.EncodeToString(key)] = PeerConfig{
			Name:       c.Name,
			User:       c.User,
			PublicKey:  key,
			TOTPSecret: c.TOTPSecret,
		}
	}
	return out, nil
}
