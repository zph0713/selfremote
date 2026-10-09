package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseKeyRoundTrip(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	var want Key
	copy(want[:], raw)

	k, err := ParseKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	if k != want {
		t.Fatalf("ParseKey round trip mismatch")
	}
}

func TestParseKeyRejectsBadInput(t *testing.T) {
	if _, err := ParseKey("!!!not-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := ParseKey(short); err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestLoadServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	priv := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	content := fmt.Sprintf(`{
	  "listen": "[::]:28333",
	  "private_key": %q,
	  "clients_file": "/data/clients.json",
	  "agents_file": "/data/agents.json",
	  "api_listen": "0.0.0.0:8770",
	  "api_token": "secret-token"
	}`, priv)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if s.TunnelCIDR != "10.77.0.1/24" {
		t.Errorf("default tunnel_cidr = %q", s.TunnelCIDR)
	}
	if s.APIToken != "secret-token" || s.AgentsFile == "" || s.ClientsFile == "" {
		t.Errorf("server config = %+v", s)
	}
	var want Key
	copy(want[:], bytes.Repeat([]byte{3}, 32))
	if s.Private != want {
		t.Errorf("private key mismatch")
	}

	// A hub without any registry file cannot authorize anyone.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(fmt.Sprintf(`{"listen":"[::]:28333","private_key":%q}`, priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(bad); err == nil {
		t.Error("expected an error when neither clients_file nor agents_file is set")
	}
}

func TestLoadAgentConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	priv := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	srvPub := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	content := fmt.Sprintf(`{
	  "id": "home",
	  "name": "家里 NAS",
	  "server": "nas.example.com:28333",
	  "private_key": %q,
	  "server_public_key": %q,
	  "tunnel_cidr": "10.77.0.101/24",
	  "mfa_secret": "JBSWY3DPEHPK3PXP",
	  "routes": [{"real": "192.168.1.0/24"}, {"real": "192.168.1.0/24", "virtual": "10.200.7.0/24"}]
	}`, priv, srvPub)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := LoadAgent(path)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if a.ID != "home" || a.MFASecret == "" || len(a.Routes) != 2 {
		t.Errorf("agent config = %+v", a)
	}

	// The same content must load from raw bytes (the .srkey path).
	raw, _ := os.ReadFile(path)
	if _, err := LoadAgentBytes(raw, "agent.srkey"); err != nil {
		t.Errorf("LoadAgentBytes: %v", err)
	}

	// Route validation: mismatched prefix lengths are rejected.
	bad := strings.Replace(string(raw), `"real": "192.168.1.0/24", "virtual": "10.200.7.0/24"`,
		`"real": "192.168.1.0/24", "virtual": "10.200.7.0/16"`, 1)
	if _, err := LoadAgentBytes([]byte(bad), "bad.srkey"); err == nil {
		t.Error("expected an error for a route with mismatched prefix lengths")
	}
	// Unknown fields are typos, not silently ignored.
	if _, err := LoadAgentBytes([]byte(strings.Replace(string(raw), `"id": "home",`, `"idd": "home",`, 1)), "typo.srkey"); err == nil {
		t.Error("expected an error for an unknown field")
	}
}

func TestLoadGateway(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")

	priv := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	peer := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	content := fmt.Sprintf(
		`{"listen":"[::]:28333","private_key":%q,"tunnel_cidr":"10.77.0.1/24","peers":[{"name":"mac","public_key":%q}]}`,
		priv, peer)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	g, err := LoadGateway(path)
	if err != nil {
		t.Fatalf("LoadGateway: %v", err)
	}
	if g.Listen != "[::]:28333" {
		t.Errorf("listen = %q", g.Listen)
	}
	if len(g.Peers) != 1 || g.Peers[0].Name != "mac" {
		t.Errorf("peers = %+v", g.Peers)
	}
	if len(g.PeerKeys) != 1 {
		t.Errorf("parsed peer keys = %d", len(g.PeerKeys))
	}
	var wantPriv Key
	copy(wantPriv[:], bytes.Repeat([]byte{1}, 32))
	if g.Private != wantPriv {
		t.Errorf("private key mismatch")
	}
}

func TestLoadGatewayRejectsBadPeerKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")

	priv := base64.StdEncoding.EncodeToString(make([]byte, 32))
	content := fmt.Sprintf(
		`{"listen":"[::]:28333","private_key":%q,"tunnel_cidr":"10.77.0.1/24","peers":[{"name":"mac","public_key":"tooshort"}]}`,
		priv)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGateway(path); err == nil {
		t.Fatal("expected error for invalid peer key")
	}
}

func TestLoadGatewayRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")

	priv := base64.StdEncoding.EncodeToString(make([]byte, 32))
	content := fmt.Sprintf(
		`{"listen":"[::]:28333","private_key":%q,"tunnel_cidr":"10.77.0.1/24","peers":[],"typo_field":true}`,
		priv)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGateway(path); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestNormalizeServerAddr(t *testing.T) {
	good := []string{
		"[240e:3a1:621:d20::54]:28333",
		"nas.example.com:28333",
		"127.0.0.1:1",
		"[2001:db8::1]:65535",
	}
	for _, a := range good {
		if got, err := NormalizeServerAddr(a); err != nil || got != a {
			t.Errorf("NormalizeServerAddr(%q) = %q, %v; want it unchanged", a, got, err)
		}
	}
	if got, err := NormalizeServerAddr("  nas.example.com:28333  "); err != nil || got != "nas.example.com:28333" {
		t.Errorf("NormalizeServerAddr trims whitespace: got %q, %v", got, err)
	}

	bad := []struct{ addr, want string }{
		{"", "不能为空"},
		{"240e:3a1:621:d20::54:28333", "方括号"}, // bare IPv6, no brackets
		{"[240e:3a1:621:d20::54]", "方括号"},     // brackets but no port
		{"nas.example.com", "主机:端口"},          // no port
		{":28333", "缺少主机名"},
		{"nas.example.com:abc", "端口"},
		{"nas.example.com:0", "端口"},
		{"nas.example.com:65536", "端口"},
	}
	for _, tc := range bad {
		_, err := NormalizeServerAddr(tc.addr)
		if err == nil {
			t.Errorf("NormalizeServerAddr(%q) = nil, want error", tc.addr)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("NormalizeServerAddr(%q) = %q, want it to mention %q", tc.addr, err, tc.want)
		}
	}
}

func TestSetClientServer(t *testing.T) {
	plain := []byte(`{
  "server": "old.example.com:28333",
  "private_key": "AAAA",
  "server_public_key": "BBBB",
  "tunnel_cidr": "10.77.0.2/24",
  "routes": ["192.168.1.0/24"],
  "future_field": 123
}`)
	out, err := SetClientServer(plain, "[240e:1:2::3]:28333")
	if err != nil {
		t.Fatalf("SetClientServer: %v", err)
	}
	var v struct {
		Server      string   `json:"server"`
		PrivateKey  string   `json:"private_key"`
		TunnelCIDR  string   `json:"tunnel_cidr"`
		Routes      []string `json:"routes"`
		FutureField int      `json:"future_field"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if v.Server != "[240e:1:2::3]:28333" || v.PrivateKey != "AAAA" || v.TunnelCIDR != "10.77.0.2/24" ||
		len(v.Routes) != 1 || v.FutureField != 123 {
		t.Errorf("re-written config = %+v", v)
	}

	// ClientInfo reads back the display fields.
	server, tunnel, routes, err := ClientInfo(out)
	if err != nil || server != "[240e:1:2::3]:28333" || tunnel != "10.77.0.2/24" || len(routes) != 1 {
		t.Errorf("ClientInfo = %q %q %v %v", server, tunnel, routes, err)
	}

	// A bad address is rejected before any change.
	if _, err := SetClientServer(plain, "no-port"); err == nil {
		t.Error("expected an error for an address without a port")
	}
	// A JSON document that is not a client config is rejected.
	if _, err := SetClientServer([]byte(`{"hello":1}`), "nas.example.com:1"); err == nil {
		t.Error("expected an error for a config without a server field")
	}
	if _, _, _, err := ClientInfo([]byte(`{"hello":1}`)); err == nil {
		t.Error("expected an error from ClientInfo without a server field")
	}
}
