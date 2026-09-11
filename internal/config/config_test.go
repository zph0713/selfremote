package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
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
