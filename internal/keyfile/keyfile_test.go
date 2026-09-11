package keyfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSealOpenRoundtrip(t *testing.T) {
	plain := []byte(`{"server":"[::1]:28333","private_key":"x","routes":["192.168.2.0/24"]}`)
	env, err := Seal(plain, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !IsEnvelope(env) {
		t.Fatal("IsEnvelope(sealed) = false, want true")
	}
	if bytes.Contains(env, []byte("private_key")) {
		t.Fatal("envelope leaks plaintext")
	}
	got, err := Open(env, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch:\n got %s\nwant %s", got, plain)
	}
}

func TestOpenWrongPassphrase(t *testing.T) {
	env, err := Seal([]byte("hello"), "passphrase-1")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, err = Open(env, "passphrase-2")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Open(wrong pass) = %v, want ErrWrongPassphrase", err)
	}
}

func TestOpenTampered(t *testing.T) {
	env, err := Seal([]byte("hello"), "passphrase-1")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip one base64 char inside ct.
	var e map[string]any
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	ct := e["ct"].(string)
	if ct[0] == 'A' {
		ct = "B" + ct[1:]
	} else {
		ct = "A" + ct[1:]
	}
	e["ct"] = ct
	tampered, _ := json.Marshal(e)
	if _, err := Open(tampered, "passphrase-1"); err == nil {
		t.Fatal("Open(tampered) succeeded, want failure")
	}
}

func TestSealTooShortPassphrase(t *testing.T) {
	if _, err := Seal([]byte("x"), "short"); err == nil {
		t.Fatal("Seal(short pass) succeeded, want error")
	}
}

func TestIsEnvelope(t *testing.T) {
	if IsEnvelope([]byte(`{"server":"x","private_key":"y"}`)) {
		t.Fatal("plain config detected as envelope")
	}
	if IsEnvelope([]byte("not json")) {
		t.Fatal("garbage detected as envelope")
	}
	env, _ := Seal([]byte("x"), "0123456789")
	if !IsEnvelope(env) {
		t.Fatal("envelope not detected")
	}
}

func TestEnvelopeParamsRecorded(t *testing.T) {
	env, err := Seal([]byte("x"), "0123456789")
	if err != nil {
		t.Fatal(err)
	}
	s := string(env)
	for _, want := range []string{`"srkey": 1`, `"name": "argon2id"`, `"name": "chacha20poly1305"`, `"memory": 65536`} {
		if !strings.Contains(s, want) {
			t.Errorf("envelope missing %q", want)
		}
	}
}
