package tunnel

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestParseRegistry(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(key)

	raw := `{"clients":[
		{"name":"a","user":"u1","public_key":"` + b64 + `","totp_secret":"ABCDEF","enabled":true},
		{"name":"b","user":"u2","public_key":"` + b64 + `","enabled":false}
	]}`
	m, err := ParseRegistry([]byte(raw))
	if err != nil {
		t.Fatalf("ParseRegistry: %v", err)
	}
	if len(m) != 1 {
		t.Fatalf("got %d entries, want 1 (disabled must be skipped)", len(m))
	}
	var got PeerConfig
	for _, pc := range m {
		got = pc
	}
	if got.Name != "a" || got.User != "u1" || got.TOTPSecret != "ABCDEF" {
		t.Fatalf("unexpected entry: %+v", got)
	}
	if len(got.PublicKey) != 32 {
		t.Fatalf("public key length = %d", len(got.PublicKey))
	}

	if _, err := ParseRegistry([]byte(`{"clients":[{"name":"x","public_key":"bm90LWtleQ=="}]}`)); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := ParseRegistry([]byte(`{"clients":[{"public_key":"` + b64 + `"}]}`)); err == nil {
		t.Fatal("missing name accepted")
	}
	if _, err := ParseRegistry([]byte(`not json`)); err == nil {
		t.Fatal("garbage accepted")
	}
}

// TestRegistryHotReloadMFAConnectAndRevoke covers the full web-managed life
// cycle: empty registry → hot-add with MFA → connect → revoke.
func TestRegistryHotReloadMFAConnectAndRevoke(t *testing.T) {
	dir := t.TempDir()
	regPath := filepath.Join(dir, "clients.json")

	gwPriv, gwPub := mustKeypair(t)
	clPriv, clPub := mustKeypair(t)
	secret := newTOTPSecret(t)

	writeReg := func(clients []RegistryClient) {
		t.Helper()
		b, _ := json.Marshal(RegistryFile{Clients: clients})
		if err := os.WriteFile(regPath, b, 0o644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond) // let the mtime advance distinctly
	}
	writeReg(nil)

	gwDev := NewFakeDevice("gw0")
	clDev := NewFakeDevice("cl0")
	gw, err := New(Options{
		Mode: ModeGateway, PrivateKey: gwPriv, Listen: "127.0.0.1:0",
		ClientsFile: regPath,
		TunnelCIDR:  "10.77.0.1/24",
		Device:      gwDev, SkipNetConfig: true, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	cl, err := New(Options{
		Mode: ModeClient, PrivateKey: clPriv, ServerPublic: gwPub, Server: gw.LocalAddr(),
		TunnelCIDR: "10.77.0.2/24",
		Device:     clDev, SkipNetConfig: true, Logf: t.Logf,
		AuthPrompt: func(attempt int) (string, bool) {
			c, err := totp.GenerateCode(secret, time.Now())
			if err != nil {
				t.Errorf("generate: %v", err)
				return "", false
			}
			return c, true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	te := runEngines(t, gw, cl)
	te.gwDev, te.clDev = gwDev, clDev

	// The registry is empty: the client's handshakes are rejected.
	time.Sleep(1200 * time.Millisecond)
	if gw.Status().ActivePeers != 0 {
		t.Fatal("unknown client established a session")
	}

	// Hot-add the client with an MFA secret.
	writeReg([]RegistryClient{{
		Name: "mac", User: "hope",
		PublicKey:  base64.StdEncoding.EncodeToString(clPub),
		TOTPSecret: secret,
	}})
	waitAuthed(t, gw, "mac", 10*time.Second)

	// Data flows once MFA passed.
	te.clDev.Inject(testPacket(7))
	if got, err := gwDev.Recv(3 * time.Second); err != nil || !bytes.Equal(got, testPacket(7)) {
		t.Fatalf("data after hot-add failed (err=%v)", err)
	}

	// Revoke: the peer and its session must disappear, traffic must stop.
	writeReg(nil)
	waitCond(t, 5*time.Second, "revocation to take effect", func() bool {
		for _, st := range gw.Stats() {
			if st.Name == "mac" {
				return false
			}
		}
		return true
	})
	te.clDev.Inject(testPacket(8))
	if p, err := gwDev.Recv(500 * time.Millisecond); err == nil {
		t.Fatalf("data delivered after revocation: %x", p)
	}
}
