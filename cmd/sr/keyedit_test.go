package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"selfremote/internal/keyfile"
)

const testClientJSON = `{
  "server": "old.example.com:28333",
  "private_key": "cHJpdmF0ZS1rZXk=",
  "server_public_key": "c2VydmVyLXB1Yg==",
  "tunnel_cidr": "10.77.0.2/24",
  "routes": ["192.168.1.0/24"]
}`

func TestKeyeditEncrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client-test.srkey")
	env, err := keyfile.Seal([]byte(testClientJSON), "test-passphrase-123")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := os.WriteFile(path, env, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := keyedit(path, "[240e:3a1:621:d20::54]:28333", false, "test-passphrase-123", &out); err != nil {
		t.Fatalf("keyedit: %v\noutput:\n%s", err, out.String())
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !keyfile.IsEnvelope(raw) {
		t.Fatal("edited file is no longer an encrypted envelope")
	}
	plain, err := keyfile.Open(raw, "test-passphrase-123")
	if err != nil {
		t.Fatalf("re-open with the same passphrase: %v", err)
	}
	s := string(plain)
	if !strings.Contains(s, "[240e:3a1:621:d20::54]:28333") {
		t.Fatalf("new server address missing from plaintext: %s", s)
	}
	if !strings.Contains(s, "cHJpdmF0ZS1rZXk=") {
		t.Fatalf("private key was not preserved: %s", s)
	}

	// The pre-edit file is kept as a .bak.
	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if !bytes.Equal(bak, env) {
		t.Error("backup does not match the pre-edit file")
	}

	// A wrong passphrase must never touch the file.
	before, _ := os.ReadFile(path)
	if err := keyedit(path, "[240e:9::9]:1", false, "wrong-passphrase-1", &out); err == nil {
		t.Fatal("expected an error for a wrong passphrase")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("file changed despite a wrong passphrase")
	}
}

func TestKeyeditPlainAndShow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	if err := os.WriteFile(path, []byte(testClientJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer

	// -show must not modify anything.
	if err := keyedit(path, "", true, "", &out); err != nil {
		t.Fatalf("keyedit -show: %v", err)
	}
	if !strings.Contains(out.String(), "old.example.com:28333") {
		t.Errorf("show output missing the current server:\n%s", out.String())
	}
	cur, _ := os.ReadFile(path)
	if string(cur) != testClientJSON {
		t.Error("-show modified the file")
	}

	// Plain config: rewrite in place, still plaintext.
	out.Reset()
	if err := keyedit(path, "nas.example.com:28334", false, "", &out); err != nil {
		t.Fatalf("keyedit: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if keyfile.IsEnvelope(raw) || !strings.Contains(string(raw), "nas.example.com:28334") {
		t.Fatalf("edited plain file = %s", raw)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("backup missing: %v", err)
	}

	// A malformed address is rejected and nothing changes.
	before, _ := os.ReadFile(path)
	err := keyedit(path, "240e:3a1:621:d20::54:28333", false, "", &out)
	if err == nil || !strings.Contains(err.Error(), "方括号") {
		t.Fatalf("expected a bracket hint, got %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("file changed despite a malformed address")
	}
}

func TestKeyeditInteractive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	if err := os.WriteFile(path, []byte(testClientJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	old := stdinReader
	defer func() { stdinReader = old }()

	// Typing an address at the prompt applies it.
	stdinReader = bufio.NewReader(strings.NewReader("host.example.com:9999\n"))
	var out bytes.Buffer
	if err := keyedit(path, "", false, "", &out); err != nil {
		t.Fatalf("interactive keyedit: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "host.example.com:9999") {
		t.Fatalf("interactive edit did not apply: %s", raw)
	}

	// Empty input cancels; the file stays as-is.
	stdinReader = bufio.NewReader(strings.NewReader("\n"))
	before, _ := os.ReadFile(path)
	if err := keyedit(path, "", false, "", &out); err != nil {
		t.Fatalf("cancelled keyedit: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("file changed despite a cancelled prompt")
	}
}
