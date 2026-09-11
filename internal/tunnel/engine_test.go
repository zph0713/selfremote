package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// FakeDevice is an in-memory Device for tests: packets injected with Inject
// come out of Read (test -> engine), packets the engine Writes land in Recv.
type FakeDevice struct {
	name string
	in   chan []byte
	out  chan []byte
	done chan struct{}
	once sync.Once
}

func NewFakeDevice(name string) *FakeDevice {
	return &FakeDevice{
		name: name,
		in:   make(chan []byte, 128),
		out:  make(chan []byte, 128),
		done: make(chan struct{}),
	}
}

// Inject queues a packet to be read by the engine.
func (f *FakeDevice) Inject(p []byte) {
	cp := append([]byte(nil), p...)
	select {
	case f.in <- cp:
	case <-f.done:
	}
}

// Recv returns the next packet written by the engine.
func (f *FakeDevice) Recv(timeout time.Duration) ([]byte, error) {
	select {
	case p := <-f.out:
		return p, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout after %v", timeout)
	case <-f.done:
		return nil, net.ErrClosed
	}
}

func (f *FakeDevice) Read(buf []byte, offset int) (int, error) {
	select {
	case p := <-f.in:
		return copy(buf[offset:], p), nil
	case <-f.done:
		return 0, net.ErrClosed
	}
}

func (f *FakeDevice) Write(buf []byte, offset int) (int, error) {
	cp := append([]byte(nil), buf[offset:]...)
	select {
	case f.out <- cp:
		return len(cp), nil
	case <-f.done:
		return 0, net.ErrClosed
	}
}

func (f *FakeDevice) Name() (string, error) { return f.name, nil }
func (f *FakeDevice) Close() error {
	f.once.Do(func() { close(f.done) })
	return nil
}

// ---------------------------------------------------------------- test env

type testEnv struct {
	gw, cl       *Engine
	gwDev, clDev *FakeDevice

	cancelGW, cancelCL context.CancelFunc
	doneGW, doneCL     chan struct{}
}

func runEngines(t *testing.T, gw, cl *Engine) *testEnv {
	t.Helper()
	te := &testEnv{
		gw: gw, cl: cl,
		doneGW: make(chan struct{}),
		doneCL: make(chan struct{}),
	}
	gwCtx, cancelGW := context.WithCancel(context.Background())
	clCtx, cancelCL := context.WithCancel(context.Background())
	te.cancelGW, te.cancelCL = cancelGW, cancelCL
	go func() { defer close(te.doneGW); gw.Run(gwCtx) }()
	go func() { defer close(te.doneCL); cl.Run(clCtx) }()
	t.Cleanup(te.stop) // runs before test completion: engines are stopped first
	return te
}

func (te *testEnv) stop() {
	te.cancelGW()
	te.cancelCL()
	<-te.doneGW
	<-te.doneCL
}

func (te *testEnv) stopGW() { te.cancelGW(); <-te.doneGW }
func (te *testEnv) stopCL() { te.cancelCL(); <-te.doneCL }

func newTestEnv(t *testing.T, mut func(gw, cl *Options)) *testEnv {
	t.Helper()
	gwPriv, gwPub := mustKeypair(t)
	clPriv, clPub := mustKeypair(t)
	gwDev := NewFakeDevice("gw0")
	clDev := NewFakeDevice("cl0")

	gwOpts := Options{
		Mode:          ModeGateway,
		PrivateKey:    gwPriv,
		Listen:        "127.0.0.1:0",
		Peers:         []PeerConfig{{Name: "mac", PublicKey: clPub}},
		TunnelCIDR:    "10.77.0.1/24",
		Device:        gwDev,
		SkipNetConfig: true,
		Logf:          t.Logf,
	}
	clOpts := Options{
		Mode:          ModeClient,
		PrivateKey:    clPriv,
		ServerPublic:  gwPub,
		TunnelCIDR:    "10.77.0.2/24",
		Routes:        []string{"192.168.1.0/24"},
		Device:        clDev,
		SkipNetConfig: true,
		Logf:          t.Logf,
	}
	if mut != nil {
		mut(&gwOpts, &clOpts)
	}

	gw, err := New(gwOpts)
	if err != nil {
		t.Fatalf("gateway New: %v", err)
	}
	clOpts.Server = gw.LocalAddr()
	cl, err := New(clOpts)
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	te := runEngines(t, gw, cl)
	te.gwDev, te.clDev = gwDev, clDev
	return te
}

func waitUp(t *testing.T, e *Engine, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if e.Status().Up {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("%s: not up after %v (status=%+v)", what, timeout, e.Status())
}

func testPacket(seed byte) []byte {
	p := make([]byte, 32)
	p[0] = 0x45
	for i := range p {
		p[i] = seed + byte(i)
	}
	return p
}

// ------------------------------------------------------------------- tests

func TestTunnelEndToEnd(t *testing.T) {
	te := newTestEnv(t, nil)
	waitUp(t, te.cl, 5*time.Second, "client")
	waitUp(t, te.gw, 2*time.Second, "gateway")

	p1 := testPacket(1)
	te.clDev.Inject(p1)
	got, err := te.gwDev.Recv(2 * time.Second)
	if err != nil {
		t.Fatalf("gateway did not receive: %v", err)
	}
	if !bytes.Equal(got, p1) {
		t.Fatalf("client->gateway mismatch:\n got %x\nwant %x", got, p1)
	}

	p2 := testPacket(0x40)
	te.gwDev.Inject(p2)
	got, err = te.clDev.Recv(2 * time.Second)
	if err != nil {
		t.Fatalf("client did not receive: %v", err)
	}
	if !bytes.Equal(got, p2) {
		t.Fatalf("gateway->client mismatch:\n got %x\nwant %x", got, p2)
	}

	// A burst verifies nonce progression in both directions.
	for i := 0; i < 8; i++ {
		te.clDev.Inject(testPacket(byte(i)))
		if _, err := te.gwDev.Recv(2 * time.Second); err != nil {
			t.Fatalf("burst packet %d lost: %v", i, err)
		}
	}
}

func TestUnknownClientRejected(t *testing.T) {
	gwPriv, gwPub := mustKeypair(t)
	_, otherPub := mustKeypair(t) // authorized on the gateway, unused by the client
	clPriv, _ := mustKeypair(t)   // the client's own (unauthorized) key

	gwDev := NewFakeDevice("gw0")
	clDev := NewFakeDevice("cl0")
	gw, err := New(Options{
		Mode: ModeGateway, PrivateKey: gwPriv, Listen: "127.0.0.1:0",
		Peers:      []PeerConfig{{Name: "authorized-other", PublicKey: otherPub}},
		TunnelCIDR: "10.77.0.1/24",
		Device:     gwDev, SkipNetConfig: true, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	cl, err := New(Options{
		Mode: ModeClient, PrivateKey: clPriv, ServerPublic: gwPub, Server: gw.LocalAddr(),
		TunnelCIDR: "10.77.0.2/24",
		Device:     clDev, SkipNetConfig: true, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	te := runEngines(t, gw, cl)
	te.gwDev, te.clDev = gwDev, clDev

	time.Sleep(1500 * time.Millisecond)
	if cl.Status().Up {
		t.Fatal("unauthorized client must not establish a session")
	}
	if gw.Status().ActivePeers != 0 {
		t.Fatal("gateway must not hold sessions for unauthorized clients")
	}
	clDev.Inject(testPacket(3))
	if p, err := gwDev.Recv(300 * time.Millisecond); err == nil {
		t.Fatalf("unexpected packet delivered: %x", p)
	}
}

func TestRekey(t *testing.T) {
	te := newTestEnv(t, func(gw, cl *Options) {
		cl.RekeyInterval = 700 * time.Millisecond
		cl.RekeyPackets = 1 << 40
	})
	waitUp(t, te.cl, 5*time.Second, "client")

	h0 := te.cl.Status().Handshakes
	time.Sleep(2200 * time.Millisecond)
	h1 := te.cl.Status().Handshakes
	if h1 <= h0 {
		t.Fatalf("expected a rekey handshake: %d -> %d", h0, h1)
	}

	te.clDev.Inject(testPacket(9))
	if _, err := te.gwDev.Recv(2 * time.Second); err != nil {
		t.Fatalf("data lost after rekey: %v", err)
	}
}

func TestGatewayDropsDeadPeer(t *testing.T) {
	te := newTestEnv(t, func(gw, cl *Options) {
		gw.KeepaliveInterval = 300 * time.Millisecond
		gw.DeadTimeout = 1200 * time.Millisecond
	})
	waitUp(t, te.cl, 5*time.Second, "client")
	te.stopCL()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if te.gw.Status().ActivePeers == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("gateway did not drop the dead peer (status=%+v)", te.gw.Status())
}

func TestClientReconnectsAfterGatewayRestart(t *testing.T) {
	te := newTestEnv(t, func(gw, cl *Options) {
		cl.KeepaliveInterval = 300 * time.Millisecond
		cl.DeadTimeout = 1200 * time.Millisecond
	})
	waitUp(t, te.cl, 5*time.Second, "client")
	addr := te.gw.LocalAddr()
	te.stopGW()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && te.cl.Status().Up {
		time.Sleep(100 * time.Millisecond)
	}
	if te.cl.Status().Up {
		t.Fatal("client did not notice the dead gateway")
	}

	// Restart a gateway on the same address; the client must recover on its own.
	gwOpts := te.gw.opts
	gwOpts.Listen = addr
	gwOpts.Device = NewFakeDevice("gw1")
	gw2, err := New(gwOpts)
	if err != nil {
		t.Fatalf("restart gateway: %v", err)
	}
	gwCtx, cancelGW := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); gw2.Run(gwCtx) }()
	t.Cleanup(func() { cancelGW(); <-done })

	waitUp(t, te.cl, 10*time.Second, "client after gateway restart")
}

func TestGarbageDatagramsIgnored(t *testing.T) {
	te := newTestEnv(t, nil)
	waitUp(t, te.cl, 5*time.Second, "client")

	junk, err := net.Dial("udp", te.gw.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer junk.Close()
	junk.Write([]byte{0x99})
	junk.Write([]byte("not a frame at all"))
	junk.Write(bytes.Repeat([]byte{0xab}, 1400))
	junk.Write([]byte{frameVersion, 0x77, 1, 2, 3}) // unknown frame type
	time.Sleep(200 * time.Millisecond)

	te.clDev.Inject(testPacket(5))
	if _, err := te.gwDev.Recv(2 * time.Second); err != nil {
		t.Fatalf("tunnel broken after garbage datagrams: %v", err)
	}
}

// startLossyRelay proxies UDP between the client and the gateway, dropping the
// first dropData DATA frames travelling client -> gateway. Returns the relay
// address (what the client should dial).
func startLossyRelay(t *testing.T, gwAddr string, dropData int) string {
	t.Helper()
	gwRaddr, err := net.ResolveUDPAddr("udp", gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })

	go func() {
		buf := make([]byte, maxDatagram)
		var clientAddr *net.UDPAddr
		dropped := 0
		for {
			n, addr, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			data := append([]byte(nil), buf[:n]...)
			if addr.Port == gwRaddr.Port && addr.IP.Equal(gwRaddr.IP) {
				if clientAddr != nil {
					relay.WriteToUDP(data, clientAddr)
				}
				continue
			}
			clientAddr = addr
			if dropped < dropData {
				if typ, _, err := parseFrame(data); err == nil && typ == frameData {
					dropped++
					continue
				}
			}
			relay.WriteToUDP(data, gwRaddr)
		}
	}()
	return relay.LocalAddr().String()
}

func TestPacketLossDoesNotKillSession(t *testing.T) {
	gwPriv, gwPub := mustKeypair(t)
	clPriv, clPub := mustKeypair(t)
	gwDev := NewFakeDevice("gw0")
	clDev := NewFakeDevice("cl0")

	gw, err := New(Options{
		Mode: ModeGateway, PrivateKey: gwPriv, Listen: "127.0.0.1:0",
		Peers:      []PeerConfig{{Name: "mac", PublicKey: clPub}},
		TunnelCIDR: "10.77.0.1/24",
		Device:     gwDev, SkipNetConfig: true, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	relayAddr := startLossyRelay(t, gw.LocalAddr(), 1)
	cl, err := New(Options{
		Mode: ModeClient, PrivateKey: clPriv, ServerPublic: gwPub, Server: relayAddr,
		TunnelCIDR: "10.77.0.2/24",
		Device:     clDev, SkipNetConfig: true, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	te := runEngines(t, gw, cl)
	te.gwDev, te.clDev = gwDev, clDev
	waitUp(t, te.cl, 5*time.Second, "client")

	p1 := testPacket(1)
	te.clDev.Inject(p1) // the relay drops this DATA frame
	time.Sleep(150 * time.Millisecond)
	p2 := testPacket(2)
	te.clDev.Inject(p2)

	got, err := te.gwDev.Recv(3 * time.Second)
	if err != nil {
		t.Fatalf("packet after a loss was not delivered (session desynced?): %v", err)
	}
	if !bytes.Equal(got, p2) {
		t.Fatalf("wrong packet delivered:\n got %x\nwant %x", got, p2)
	}
	if extra, err := te.gwDev.Recv(300 * time.Millisecond); err == nil {
		t.Fatalf("unexpected extra packet: %x", extra)
	}

	// The reverse direction is unaffected.
	p3 := testPacket(0x50)
	te.gwDev.Inject(p3)
	if got, err := te.clDev.Recv(2 * time.Second); err != nil || !bytes.Equal(got, p3) {
		t.Fatalf("reverse direction broken after loss (err=%v)", err)
	}
}

func TestRecvWindow(t *testing.T) {
	var w recvWindow
	if !w.acceptable(0) {
		t.Fatal("first nonce must be acceptable")
	}
	w.commit(0)
	if !w.acceptable(1) {
		t.Fatal("newer nonce must be acceptable")
	}
	w.commit(1)
	if w.acceptable(1) || w.acceptable(0) {
		t.Fatal("replayed nonce must be rejected")
	}
	if !w.acceptable(2) {
		t.Fatal("next nonce must be acceptable")
	}
	w.commit(2)
	w.commit(100) // big jump forward
	if w.acceptable(100) {
		t.Fatal("replayed nonce after jump must be rejected")
	}
	if !w.acceptable(37) { // age 63: still inside the window
		t.Fatal("nonce inside the window must be acceptable")
	}
	w.commit(37)
	if w.acceptable(37) {
		t.Fatal("replay inside the window must be rejected")
	}
	if w.acceptable(36) {
		t.Fatal("nonce older than the window must be rejected")
	}
}
