package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// newTOTPSecret generates a fresh base32 TOTP secret for tests.
func newTOTPSecret(t *testing.T) string {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "selfremote-test", AccountName: "mac"})
	if err != nil {
		t.Fatalf("totp generate: %v", err)
	}
	return key.Secret()
}

// wrongCode returns a 6-digit code that does not match any step within the
// ±2 window around now (so it can never be accepted by checkTOTP).
func wrongCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	gen := func(ts time.Time) string {
		c, err := totp.GenerateCode(secret, ts)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		return c
	}
	bad := map[string]bool{}
	for off := -2; off <= 2; off++ {
		bad[gen(now.Add(time.Duration(off)*30*time.Second))] = true
	}
	c := gen(now)
	for f := 1; f <= 9; f++ {
		d := (c[len(c)-1]-'0'+byte(f))%10 + '0'
		cand := c[:len(c)-1] + string(d)
		if !bad[cand] {
			return cand
		}
	}
	return ""
}

func waitCond(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func waitAuthed(t *testing.T, e *Engine, name string, timeout time.Duration) {
	t.Helper()
	waitCond(t, timeout, name+" authed", func() bool {
		for _, st := range e.Stats() {
			if st.Name == name && st.Connected && st.Authed {
				return true
			}
		}
		return false
	})
}

// mfaPair builds a gateway that requires MFA for one client and a client
// whose AuthPrompt calls prompt (blocking is fine; it runs in a goroutine).
func mfaPair(t *testing.T, secret string, prompt func(attempt int) (string, bool), onReady func()) (*Engine, *Engine, *FakeDevice, *FakeDevice) {
	t.Helper()
	gwPriv, gwPub := mustKeypair(t)
	clPriv, clPub := mustKeypair(t)

	gwDev := NewFakeDevice("gw0")
	clDev := NewFakeDevice("cl0")
	gw, err := New(Options{
		Mode: ModeGateway, PrivateKey: gwPriv, Listen: "127.0.0.1:0",
		Peers:      []PeerConfig{{Name: "mac", User: "hope", PublicKey: clPub, TOTPSecret: secret}},
		TunnelCIDR: "10.77.0.1/24",
		Device:     gwDev, SkipNetConfig: true, Logf: t.Logf,
	})
	if err != nil {
		t.Fatalf("gateway New: %v", err)
	}
	cl, err := New(Options{
		Mode: ModeClient, PrivateKey: clPriv, ServerPublic: gwPub, Server: gw.LocalAddr(),
		TunnelCIDR: "10.77.0.2/24",
		Device:     clDev, SkipNetConfig: true, Logf: t.Logf,
		AuthPrompt: prompt, OnReady: onReady,
	})
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	return gw, cl, gwDev, clDev
}

func TestMFAGatingAndPass(t *testing.T) {
	secret := newTOTPSecret(t)
	codeCh := make(chan string, 4)
	var mu sync.Mutex
	var attempts []int
	ready := make(chan struct{})
	var once sync.Once

	gw, cl, gwDev, clDev := mfaPair(t, secret, func(attempt int) (string, bool) {
		mu.Lock()
		attempts = append(attempts, attempt)
		mu.Unlock()
		return <-codeCh, true
	}, func() { once.Do(func() { close(ready) }) })

	te := runEngines(t, gw, cl)
	te.gwDev, te.clDev = gwDev, clDev

	// The session comes up first; data must stay gated until the code passes.
	waitCond(t, 5*time.Second, "gateway session", func() bool { return gw.Status().ActivePeers == 1 })
	te.clDev.Inject(testPacket(1))
	if p, err := gwDev.Recv(400 * time.Millisecond); err == nil {
		t.Fatalf("client->gateway data leaked before MFA: %x", p)
	}
	te.gwDev.Inject(testPacket(2))
	if p, err := clDev.Recv(400 * time.Millisecond); err == nil {
		t.Fatalf("gateway->client data leaked before MFA: %x", p)
	}
	if gw.Status().ActivePeers != 1 {
		t.Fatal("session dropped while waiting for the code")
	}

	// Wait until the client is actually prompting, then submit a valid code.
	waitCond(t, 5*time.Second, "auth prompt", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(attempts) == 1
	})
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	codeCh <- code

	waitAuthed(t, gw, "mac", 5*time.Second)
	waitAuthed(t, cl, "gateway", 5*time.Second)
	waitCond(t, 2*time.Second, "OnReady callback", func() bool {
		select {
		case <-ready:
			return true
		default:
			return false
		}
	})

	// With MFA passed, data flows both ways.
	te.clDev.Inject(testPacket(3))
	if got, err := gwDev.Recv(2 * time.Second); err != nil || !bytes.Equal(got, testPacket(3)) {
		t.Fatalf("client->gateway after MFA failed (err=%v)", err)
	}
	te.gwDev.Inject(testPacket(4))
	if got, err := clDev.Recv(2 * time.Second); err != nil || !bytes.Equal(got, testPacket(4)) {
		t.Fatalf("gateway->client after MFA failed (err=%v)", err)
	}
}

func TestMFAWrongCodeThenRetry(t *testing.T) {
	secret := newTOTPSecret(t)
	var mu sync.Mutex
	var attempts []int

	gw, cl, gwDev, clDev := mfaPair(t, secret, func(attempt int) (string, bool) {
		mu.Lock()
		attempts = append(attempts, attempt)
		mu.Unlock()
		if attempt == 1 {
			return wrongCode(t, secret, time.Now()), true
		}
		c, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Errorf("generate: %v", err)
			return "", false
		}
		return c, true
	}, nil)

	te := runEngines(t, gw, cl)
	te.gwDev, te.clDev = gwDev, clDev

	waitAuthed(t, gw, "mac", 8*time.Second)

	mu.Lock()
	got := append([]int(nil), attempts...)
	mu.Unlock()
	if len(got) < 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("expected prompts 1 then 2, got %v", got)
	}
}

func TestMFAFailuresAbortClient(t *testing.T) {
	secret := newTOTPSecret(t)

	gw, cl, _, _ := mfaPair(t, secret, func(attempt int) (string, bool) {
		return wrongCode(t, secret, time.Now()), true
	}, nil)

	gwCtx, cancelGW := context.WithCancel(context.Background())
	clCtx, cancelCL := context.WithCancel(context.Background())
	doneGW := make(chan struct{})
	go func() { defer close(doneGW); gw.Run(gwCtx) }()
	clErr := make(chan error, 1)
	go func() { clErr <- cl.Run(clCtx) }()
	t.Cleanup(func() {
		cancelGW()
		cancelCL()
		<-doneGW
	})

	select {
	case err := <-clErr:
		if err == nil || !strings.Contains(err.Error(), "MFA") {
			t.Fatalf("client Run = %v, want an MFA failure", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("client did not abort after repeated MFA failures")
	}
}

func TestTOTPValidation(t *testing.T) {
	secret := newTOTPSecret(t)
	now := time.Now()

	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := checkTOTP(secret, code, now); !ok {
		t.Fatal("current code rejected")
	}
	if ok, _ := checkTOTP(secret, code, now.Add(-30*time.Second)); !ok {
		t.Fatal("code one step old must pass the ±1 window")
	}
	if ok, _ := checkTOTP(secret, code, now.Add(30*time.Second)); !ok {
		t.Fatal("code one step ahead must pass the ±1 window")
	}
	if ok, _ := checkTOTP(secret, code, now.Add(5*time.Minute)); ok {
		t.Fatal("stale code accepted")
	}
	if ok, _ := checkTOTP(secret, "12345", now); ok {
		t.Fatal("short code accepted")
	}
	if ok, _ := checkTOTP(secret, "abcdef", now); ok {
		t.Fatal("non-numeric code accepted")
	}
	ok, step := checkTOTP(secret, code, now)
	if !ok || step != now.Unix()/30 {
		t.Fatalf("matched step = %d, want %d", step, now.Unix()/30)
	}
}

func TestTOTPReplayRejected(t *testing.T) {
	gwPriv, _ := mustKeypair(t)
	_, clPub := mustKeypair(t)
	secret := newTOTPSecret(t)

	gw, err := New(Options{
		Mode: ModeGateway, PrivateKey: gwPriv, Listen: "127.0.0.1:0",
		Peers:      []PeerConfig{{Name: "mac", PublicKey: clPub, TOTPSecret: secret}},
		TunnelCIDR: "10.77.0.1/24",
		Device:     NewFakeDevice("gw0"), SkipNetConfig: true, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.conn.Close()

	p := gw.peerByPub(clPub)
	if p == nil {
		t.Fatal("peer not installed")
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(fmt.Sprintf(`{"code":%q}`, code))

	gw.handleAuthResp(p, payload)
	if !p.authed {
		t.Fatal("valid code not accepted")
	}
	firstStep := p.lastAuthStep
	if firstStep == 0 {
		t.Fatal("lastAuthStep not recorded")
	}

	// Simulate a reconnect within the same step: the same code must be
	// rejected (anti-replay) instead of authenticating the new session.
	p.authed = false
	gw.handleAuthResp(p, payload)
	if p.authed {
		t.Fatal("replayed code accepted")
	}
	if p.lastAuthStep != firstStep {
		t.Fatalf("lastAuthStep moved on a rejected code: %d -> %d", firstStep, p.lastAuthStep)
	}
	if p.authAttempts != 1 {
		t.Fatalf("authAttempts = %d, want 1", p.authAttempts)
	}
}

func TestClientByeDropsSessionFast(t *testing.T) {
	te := newTestEnv(t, func(gw, cl *Options) {
		gw.DeadTimeout = 30 * time.Second // long: only a BYE can explain a fast drop
	})
	waitUp(t, te.cl, 5*time.Second, "client")
	waitCond(t, 2*time.Second, "gateway session", func() bool { return te.gw.Status().ActivePeers == 1 })

	te.stopCL() // client ctx cancel → BYE frame → immediate teardown

	waitCond(t, 3*time.Second, "gateway to drop the session after BYE", func() bool {
		return te.gw.Status().ActivePeers == 0
	})
}
