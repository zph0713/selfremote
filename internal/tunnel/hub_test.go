package tunnel

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// The hub tests exercise the v0.3 topology end to end over real loopback UDP:
//
//	client --(MFA)--> server --(MFA)--> agent --> fake site LAN
//
// with the server relaying in user space (no TUN) and the agent translating
// addresses at its edge.

const (
	testClientSecret = "JBSWY3DPEHPK3PXP"
	testAgentSecret  = "KRSXG5CTMVRXEZLU"
)

type hubSetup struct {
	// Client ACL (agent ids it may reach).
	allow []string
	// Client MFA: nil = no TOTP required on the client link.
	clientMFA bool
	agentMFA  bool

	// Agent options.
	agentTunnelIP string // default 10.77.0.101
	agentRoutes   []RegistryRoute
	agentEnabled  *bool
	agentsFile    bool // serve the agent from agents.json instead of a static peer

	// Extra static agent (for multi-site tests).
	extraAgent *hubExtraAgent

	// Timing knobs for the "session dies" tests: a short keepalive plus a
	// short hub dead-peer timeout make a stopped engine visible in ~1s.
	keepalive  time.Duration
	serverDead time.Duration
}

type hubExtraAgent struct {
	id      string
	routes  []RegistryRoute
	tunnel  string
	enabled *bool
}

type hubEnv struct {
	srv   *Engine
	cl    *Engine
	ag    *Engine
	clDev *FakeDevice
	agDev *FakeDevice

	extra    *Engine
	extraDev *FakeDevice

	// Agent options + its stop handle, so a test can restart the site machine
	// with the very same key and configuration.
	agOpts   Options
	cancelAg context.CancelFunc
	doneAg   chan struct{}

	srvPub   []byte
	clPub    []byte
	agPub    []byte
	agentsFD string

	cancels []context.CancelFunc
	dones   []chan struct{}
}

func (h *hubEnv) stop() {
	for _, c := range h.cancels {
		c()
	}
	for _, d := range h.dones {
		<-d
	}
}

func (h *hubEnv) start(t *testing.T, e *Engine) (context.CancelFunc, chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	h.cancels = append(h.cancels, cancel)
	h.dones = append(h.dones, done)
	go func() { defer close(done); e.Run(ctx) }()
	return cancel, done
}

// stopAg stops the site agent: its session dies exactly like a restarted
// container or a rebooted machine (no goodbye frame).
func (h *hubEnv) stopAg() {
	h.cancelAg()
	<-h.doneAg
}

func mustRoute(t *testing.T, real, virt string) RouteMap {
	t.Helper()
	m, err := ParseRouteMap(real, virt)
	if err != nil {
		t.Fatalf("route %s=%s: %v", real, virt, err)
	}
	return m
}

func registryRoutes(t *testing.T, rs []RegistryRoute) []RouteMap {
	t.Helper()
	out := make([]RouteMap, 0, len(rs))
	for _, r := range rs {
		out = append(out, mustRoute(t, r.Real, r.Virtual))
	}
	return out
}

func newHubEnv(t *testing.T, s hubSetup) *hubEnv {
	t.Helper()
	srvPriv, srvPub := mustKeypair(t)
	clPriv, clPub := mustKeypair(t)
	agPriv, agPub := mustKeypair(t)

	if s.agentTunnelIP == "" {
		s.agentTunnelIP = "10.77.0.101"
	}
	defaultRoutes := []RegistryRoute{{Real: "192.168.1.0/24", Virtual: "10.200.7.0/24"}}
	if len(s.agentRoutes) == 0 {
		s.agentRoutes = defaultRoutes
	}
	agentEnabled := true
	if s.agentEnabled != nil {
		agentEnabled = *s.agentEnabled
	}

	h := &hubEnv{srvPub: srvPub, clPub: clPub, agPub: agPub}
	t.Cleanup(h.stop)

	dir := t.TempDir()
	clientsFile := filepath.Join(dir, "clients.json")
	agentsFile := filepath.Join(dir, "agents.json")

	srvPeers := []PeerConfig{
		{
			Name: "mac", PublicKey: clPub, Role: RoleClient, Enabled: true,
			TunnelIP: netip.MustParseAddr("10.77.0.2"), AllowAgents: s.allow,
		},
	}
	if s.clientMFA {
		srvPeers[0].TOTPSecret = testClientSecret
	}
	if !s.agentsFile {
		pc := PeerConfig{
			Name: "home", ID: "home", PublicKey: agPub, Role: RoleAgent, Enabled: agentEnabled,
			TunnelIP: netip.MustParseAddr(s.agentTunnelIP), Routes: registryRoutes(t, s.agentRoutes),
		}
		if s.agentMFA {
			pc.TOTPSecret = testAgentSecret
		}
		srvPeers = append(srvPeers, pc)
	}
	var extraPrivKey []byte
	extraTunnel := ""
	if s.extraAgent != nil {
		enabled := true
		if s.extraAgent.enabled != nil {
			enabled = *s.extraAgent.enabled
		}
		tun := s.extraAgent.tunnel
		if tun == "" {
			tun = "10.77.0.102"
		}
		extraTunnel = tun
		extraPriv, extraPub := mustKeypair(t)
		extraPrivKey = extraPriv
		srvPeers = append(srvPeers, PeerConfig{
			Name: s.extraAgent.id, ID: s.extraAgent.id, PublicKey: extraPub,
			Role: RoleAgent, Enabled: enabled,
			TunnelIP: netip.MustParseAddr(tun), Routes: registryRoutes(t, s.extraAgent.routes),
		})
	}

	srvOpts := Options{
		Mode: ModeServer, PrivateKey: srvPriv, Listen: "127.0.0.1:0",
		TunnelCIDR: "10.77.0.1/24", Peers: srvPeers,
		SkipNetConfig: true, Logf: t.Logf,
	}
	if s.serverDead > 0 {
		srvOpts.DeadTimeout = s.serverDead
	}
	if s.keepalive > 0 {
		srvOpts.KeepaliveInterval = s.keepalive
	}
	if s.agentsFile {
		srvOpts.AgentsFile = agentsFile
		writeAgentsFile(t, agentsFile, []RegistryAgent{{
			ID: "home", Name: "home", PublicKey: base64.StdEncoding.EncodeToString(agPub),
			TunnelIP: s.agentTunnelIP, Routes: s.agentRoutes,
			TOTPSecret: mfaOrEmpty(s.agentMFA, testAgentSecret), Enabled: boolPtr(agentEnabled),
		}})
	} else {
		// Keep the file absent on purpose: static peers carry the config.
		_ = os.Remove(agentsFile)
	}
	// The clients file is always present so reloads never resurrect peers.
	writeClientsFile(t, clientsFile, nil)
	srvOpts.ClientsFile = clientsFile

	srv, err := New(srvOpts)
	if err != nil {
		t.Fatalf("server New: %v", err)
	}
	h.srv = srv

	// Agent: dials the hub, publishes 192.168.1.0/24 as 10.200.7.0/24.
	h.agDev = NewFakeDevice("ag0")
	agOpts := Options{
		Mode: ModeAgent, PrivateKey: agPriv, Server: srv.LocalAddr(), ServerPublic: srvPub,
		TunnelCIDR: s.agentTunnelIP + "/24", AgentID: "home",
		RouteMaps: registryRoutes(t, s.agentRoutes), Device: h.agDev,
		SkipNetConfig: true, Logf: t.Logf, Version: "test",
	}
	if s.agentMFA {
		agOpts.MFASecret = testAgentSecret
	}
	if s.keepalive > 0 {
		agOpts.KeepaliveInterval = s.keepalive
	}
	h.agOpts = agOpts
	ag, err := New(agOpts)
	if err != nil {
		t.Fatalf("agent New: %v", err)
	}
	h.ag = ag

	// Client: dials the hub, uses its tunnel address 10.77.0.2.
	h.clDev = NewFakeDevice("cl0")
	clOpts := Options{
		Mode: ModeClient, PrivateKey: clPriv, Server: srv.LocalAddr(), ServerPublic: srvPub,
		TunnelCIDR: "10.77.0.2/24", Device: h.clDev, SkipNetConfig: true, Logf: t.Logf,
	}
	if s.clientMFA {
		clOpts.AuthPrompt = func(attempt int) (string, bool) {
			code, err := totp.GenerateCode(testClientSecret, time.Now())
			if err != nil {
				return "", false
			}
			return code, true
		}
	}
	if s.keepalive > 0 {
		clOpts.KeepaliveInterval = s.keepalive
	}
	cl, err := New(clOpts)
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	h.cl = cl

	h.start(t, srv)
	h.cancelAg, h.doneAg = h.start(t, ag)
	h.start(t, cl)

	if s.extraAgent != nil {
		h.extraDev = NewFakeDevice("ag1")
		extraOpts := Options{
			Mode: ModeAgent, PrivateKey: extraPrivKey, Server: srv.LocalAddr(), ServerPublic: srvPub,
			TunnelCIDR: extraTunnel + "/24", AgentID: s.extraAgent.id,
			RouteMaps: registryRoutes(t, s.extraAgent.routes), Device: h.extraDev,
			SkipNetConfig: true, Logf: t.Logf, Version: "test",
		}
		extra, err := New(extraOpts)
		if err != nil {
			t.Fatalf("extra agent New: %v", err)
		}
		h.extra = extra
		h.start(t, extra)
	}
	return h
}

func boolPtr(b bool) *bool { return &b }

func mfaOrEmpty(on bool, secret string) string {
	if on {
		return secret
	}
	return ""
}

func writeAgentsFile(t *testing.T, path string, agents []RegistryAgent) {
	t.Helper()
	raw, err := json.MarshalIndent(AgentRegistryFile{Agents: agents}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func writeClientsFile(t *testing.T, path string, clients []RegistryClient) {
	t.Helper()
	raw, err := json.MarshalIndent(RegistryFile{Clients: clients}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// mustPubFromPriv is gone: every site gets a real keypair and its own engine.

func waitPeersAuthed(t *testing.T, srv *Engine, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n := 0
		for _, p := range srv.Stats() {
			if p.Connected && p.Authed {
				n++
			}
		}
		if n >= want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("server: expected %d authenticated peer(s), got %+v", want, srv.Stats())
}

func waitForwarding(t *testing.T, e *Engine, want bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if e.Forwarding() == want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("agent forwarding = %v, want %v", e.Forwarding(), want)
}

// waitFlow checks that client -> site packets flow (or stop flowing).
func waitFlow(t *testing.T, h *hubEnv, want bool, timeout time.Duration, dst string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		h.clDev.Inject(makeTCP(addr("10.77.0.2"), addr(dst), 1))
		_, err := h.agDev.Recv(120 * time.Millisecond)
		if (err == nil) == want {
			return
		}
		time.Sleep(80 * time.Millisecond)
	}
	t.Fatalf("client -> %s flow did not become %v within %v", dst, want, timeout)
}

// makeTCP builds a checksummed IPv4/TCP packet between two addresses.
func makeTCP(src, dst netip.Addr, payloadLen int) []byte {
	l4 := tcpSeg(51000, 445, bytes.Repeat([]byte{0x5A}, payloadLen))
	pkt := ipv4(src, dst, 6, l4, 0, false)
	setV4Checksum(pkt, src, dst, 6, 20, 16)
	return pkt
}

// ------------------------------------------------------------------- tests

func TestHubRelayEndToEnd(t *testing.T) {
	h := newHubEnv(t, hubSetup{clientMFA: true, agentMFA: true, allow: []string{"home"}})

	waitUp(t, h.cl, 5*time.Second, "client")
	waitUp(t, h.ag, 5*time.Second, "agent")
	waitPeersAuthed(t, h.srv, 2, 5*time.Second)

	// client -> site: the destination is rewritten virtual -> real at the agent.
	pkt := makeTCP(addr("10.77.0.2"), addr("10.200.7.50"), 16)
	h.clDev.Inject(pkt)
	got, err := h.agDev.Recv(3 * time.Second)
	if err != nil {
		t.Fatalf("agent did not receive the relayed packet: %v", err)
	}
	if d := netip.AddrFrom4([4]byte(got[16:20])); d != addr("192.168.1.50") {
		t.Errorf("agent saw dst %s, want 192.168.1.50 (virtual->real)", d)
	}
	if s := netip.AddrFrom4([4]byte(got[12:16])); s != addr("10.77.0.2") {
		t.Errorf("agent saw src %s, want the client tunnel address", s)
	}
	verifyV4(t, "client->site", got)

	// site -> client: the source is rewritten real -> virtual at the agent.
	reply := makeTCP(addr("192.168.1.50"), addr("10.77.0.2"), 24)
	h.agDev.Inject(reply)
	got, err = h.clDev.Recv(3 * time.Second)
	if err != nil {
		t.Fatalf("client did not receive the reply: %v", err)
	}
	if s := netip.AddrFrom4([4]byte(got[12:16])); s != addr("10.200.7.50") {
		t.Errorf("client saw src %s, want 10.200.7.50 (real->virtual)", s)
	}
	verifyV4(t, "site->client", got)

	// The hub itself answers pings on its tunnel address.
	ping := ipv4(addr("10.77.0.2"), addr("10.77.0.1"), 1, icmp4Echo(3, 1, []byte("ping")), 0, false)
	h.clDev.Inject(ping)
	pong, err := h.clDev.Recv(3 * time.Second)
	if err != nil {
		t.Fatalf("hub did not answer the ping: %v", err)
	}
	if pong[20] != 0 { // ICMP echo reply
		t.Errorf("hub reply type = %d, want 0 (echo reply)", pong[20])
	}
	if s := netip.AddrFrom4([4]byte(pong[12:16])); s != addr("10.77.0.1") {
		t.Errorf("hub reply src = %s, want 10.77.0.1", s)
	}
	if got := onesComplement(pong[:20]); got != 0 {
		t.Errorf("hub reply IP checksum invalid")
	}
	if got := onesComplement(pong[20 : 28+4]); got != 0 {
		t.Errorf("hub reply ICMP checksum invalid")
	}

	// The agent's own tunnel address is reachable (kernel answers it there).
	pingAgent := ipv4(addr("10.77.0.2"), addr("10.77.0.101"), 1, icmp4Echo(4, 1, []byte("p")), 0, false)
	h.clDev.Inject(pingAgent)
	if got, err := h.agDev.Recv(3 * time.Second); err != nil {
		t.Fatalf("packet for the agent tunnel address was not relayed: %v", err)
	} else if netip.AddrFrom4([4]byte(got[16:20])) != addr("10.77.0.101") {
		t.Errorf("agent tunnel address packet was rewritten to %s", netip.AddrFrom4([4]byte(got[16:20])))
	}

	// Relay counters moved.
	if st := h.srv.RelayStats(); st.Forwarded == 0 || st.ToAgents == 0 || st.ToClients == 0 {
		t.Errorf("relay counters not incremented: %+v", st)
	}
}

func TestHubAntiSpoofAndACL(t *testing.T) {
	h := newHubEnv(t, hubSetup{
		allow: []string{"home"},
		extraAgent: &hubExtraAgent{
			id:     "office",
			routes: []RegistryRoute{{Real: "192.168.1.0/24", Virtual: "10.200.8.0/24"}},
		},
	})
	waitUp(t, h.cl, 5*time.Second, "client")
	waitUp(t, h.ag, 5*time.Second, "agent")
	waitPeersAuthed(t, h.srv, 2, 5*time.Second)

	// Anti-spoof: a client packet whose source is not its tunnel address is
	// dropped, even though the destination is allowed.
	h.clDev.Inject(makeTCP(addr("10.77.0.9"), addr("10.200.7.50"), 8))
	if extra, err := h.agDev.Recv(400 * time.Millisecond); err == nil {
		t.Fatalf("spoofed packet was relayed: %x", extra)
	}

	// ACL: office is not in the client's allow list.
	h.clDev.Inject(makeTCP(addr("10.77.0.2"), addr("10.200.8.50"), 8))
	if extra, err := h.extraDev.Recv(400 * time.Millisecond); err == nil {
		t.Fatalf("packet to a non-granted site was relayed: %x", extra)
	}
	st := h.srv.RelayStats()
	if st.Spoofed == 0 {
		t.Errorf("expected spoofed counter to move: %+v", st)
	}
	if st.Denied == 0 {
		t.Errorf("expected denied counter to move: %+v", st)
	}

	// The granted site still works.
	h.clDev.Inject(makeTCP(addr("10.77.0.2"), addr("10.200.7.50"), 8))
	if _, err := h.agDev.Recv(2 * time.Second); err != nil {
		t.Fatalf("granted site unreachable after the drops: %v", err)
	}
}

func TestHubNoACLMeansNoSite(t *testing.T) {
	h := newHubEnv(t, hubSetup{}) // no allow list at all
	waitUp(t, h.cl, 5*time.Second, "client")
	waitPeersAuthed(t, h.srv, 2, 5*time.Second)

	h.clDev.Inject(makeTCP(addr("10.77.0.2"), addr("10.200.7.50"), 8))
	if extra, err := h.agDev.Recv(400 * time.Millisecond); err == nil {
		t.Fatalf("packet relayed without an ACL grant: %x", extra)
	}
}

func TestAgentDisableEnableViaRegistry(t *testing.T) {
	h := newHubEnv(t, hubSetup{
		allow: []string{"home"}, agentMFA: true, agentsFile: true,
	})
	waitUp(t, h.cl, 5*time.Second, "client")
	waitUp(t, h.ag, 5*time.Second, "agent")
	waitPeersAuthed(t, h.srv, 2, 5*time.Second)
	waitFlow(t, h, true, 3*time.Second, "10.200.7.50")

	// Disable: the registry flips, the hub tells the agent to stand down and
	// stops relaying to it.
	writeAgentsFile(t, h.srv.opts.AgentsFile, []RegistryAgent{{
		ID: "home", Name: "home", PublicKey: base64.StdEncoding.EncodeToString(h.agPub),
		TunnelIP: "10.77.0.101", Routes: []RegistryRoute{{Real: "192.168.1.0/24", Virtual: "10.200.7.0/24"}},
		TOTPSecret: testAgentSecret, Enabled: boolPtr(false),
	}})
	waitForwarding(t, h.ag, false, 3*time.Second)
	waitFlow(t, h, false, 3*time.Second, "10.200.7.50")
	if st := h.srv.RelayStats(); st.Offline == 0 && st.Denied == 0 {
		t.Errorf("expected the hub to refuse traffic to a disabled agent: %+v", st)
	}
	// The session may stay alive (soft disable keeps the control channel).
	if !h.ag.Status().Up {
		t.Errorf("a soft-disabled agent should keep its control session")
	}

	// Re-enable: traffic resumes without any manual agent action.
	writeAgentsFile(t, h.srv.opts.AgentsFile, []RegistryAgent{{
		ID: "home", Name: "home", PublicKey: base64.StdEncoding.EncodeToString(h.agPub),
		TunnelIP: "10.77.0.101", Routes: []RegistryRoute{{Real: "192.168.1.0/24", Virtual: "10.200.7.0/24"}},
		TOTPSecret: testAgentSecret, Enabled: boolPtr(true),
	}})
	waitForwarding(t, h.ag, true, 3*time.Second)
	waitFlow(t, h, true, 3*time.Second, "10.200.7.50")
}

func TestAgentRemovedFromRegistryIsRejected(t *testing.T) {
	h := newHubEnv(t, hubSetup{allow: []string{"home"}, agentMFA: true, agentsFile: true})
	waitUp(t, h.cl, 5*time.Second, "client")
	waitUp(t, h.ag, 5*time.Second, "agent")
	waitPeersAuthed(t, h.srv, 2, 5*time.Second)

	// Remove the agent: the hub drops the session and refuses new handshakes.
	writeAgentsFile(t, h.srv.opts.AgentsFile, nil)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		authed := 0
		for _, p := range h.srv.Stats() {
			if p.Role == "agent" && p.Connected && p.Authed {
				authed++
			}
		}
		if authed == 0 {
			// The agent must not be able to sneak back in: give it time to
			// retry handshakes and confirm it stays unauthorized.
			time.Sleep(1200 * time.Millisecond)
			for _, p := range h.srv.Stats() {
				if p.Role == "agent" && p.Connected {
					t.Fatalf("revoked agent reconnected: %+v", p)
				}
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("revoked agent session was not dropped: %+v", h.srv.Stats())
}

func TestHubKickAgentReconnects(t *testing.T) {
	h := newHubEnv(t, hubSetup{allow: []string{"home"}, agentMFA: true})
	waitUp(t, h.cl, 5*time.Second, "client")
	waitUp(t, h.ag, 5*time.Second, "agent")
	waitPeersAuthed(t, h.srv, 2, 5*time.Second)

	if !h.srv.KickAgent("home") {
		t.Fatal("KickAgent(home) returned false")
	}
	waitPeersAuthed(t, h.srv, 2, 6*time.Second)
	waitFlow(t, h, true, 4*time.Second, "10.200.7.50")
	if h.srv.KickAgent("nope") {
		t.Error("KickAgent(unknown) must return false")
	}
}

// peerByName returns the hub's view of one peer.
func peerByName(t *testing.T, srv *Engine, name string) PeerStats {
	t.Helper()
	for _, p := range srv.Stats() {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("peer %q not found in %+v", name, srv.Stats())
	return PeerStats{}
}

// waitPeerConnected waits for a peer's live-session flag to reach want.
func waitPeerConnected(t *testing.T, srv *Engine, name string, want bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, p := range srv.Stats() {
			if p.Name == name && p.Connected == want {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("peer %q: connected never became %v within %v (%+v)", name, want, timeout, srv.Stats())
}

// TestSiteStaysUsableAcrossAgentRestart guards the hub-side auth state: a site
// that needs no TOTP code must never be left gated after its session dies —
// otherwise the panel shows 「认证中」 and the relay refuses the site's traffic
// for good, and "delete the site and install it again" looks like the only fix
// (a fresh key re-registers the peer, which is what restores the flag).
func TestSiteStaysUsableAcrossAgentRestart(t *testing.T) {
	h := newHubEnv(t, hubSetup{
		allow:      []string{"home"}, // no MFA: the v0.4 site default
		keepalive:  300 * time.Millisecond,
		serverDead: 1500 * time.Millisecond,
	})
	waitUp(t, h.cl, 5*time.Second, "client")
	waitUp(t, h.ag, 5*time.Second, "agent")
	waitPeersAuthed(t, h.srv, 2, 5*time.Second)
	waitFlow(t, h, true, 3*time.Second, "10.200.7.50")

	// The site machine restarts: the session dies with no goodbye frame and
	// the hub reaps it after its dead-peer timeout.
	h.stopAg()
	waitPeerConnected(t, h.srv, "home", false, 5*time.Second)
	if p := peerByName(t, h.srv, "home"); !p.Authed {
		t.Fatalf("site left gated after its session died (panel would show 认证中): %+v", p)
	}

	// Same key, same config: it must be usable again without a reinstall.
	agOpts := h.agOpts
	agDev := NewFakeDevice("ag1")
	agOpts.Device = agDev
	ag2, err := New(agOpts)
	if err != nil {
		t.Fatalf("restart agent: %v", err)
	}
	h.agDev = agDev
	h.start(t, ag2)
	waitUp(t, ag2, 5*time.Second, "agent after restart")
	waitPeersAuthed(t, h.srv, 2, 6*time.Second)
	waitFlow(t, h, true, 4*time.Second, "10.200.7.50")
}

// TestMfaSiteGatedAgainAfterRestart is the counterpart: a site that really
// uses a code must prove itself again once its session is gone.
func TestMfaSiteGatedAgainAfterRestart(t *testing.T) {
	h := newHubEnv(t, hubSetup{
		allow: []string{"home"}, agentMFA: true,
		keepalive:  300 * time.Millisecond,
		serverDead: 1500 * time.Millisecond,
	})
	waitUp(t, h.cl, 5*time.Second, "client")
	waitUp(t, h.ag, 5*time.Second, "agent")
	waitPeersAuthed(t, h.srv, 2, 5*time.Second)
	waitFlow(t, h, true, 3*time.Second, "10.200.7.50")

	h.stopAg()
	waitPeerConnected(t, h.srv, "home", false, 5*time.Second)
	if p := peerByName(t, h.srv, "home"); p.Authed {
		t.Fatalf("an MFA site must not count as authenticated without a fresh code: %+v", p)
	}

	// The agent answers the challenge from its own secret, unattended.
	agOpts := h.agOpts
	agDev := NewFakeDevice("ag1")
	agOpts.Device = agDev
	ag2, err := New(agOpts)
	if err != nil {
		t.Fatalf("restart agent: %v", err)
	}
	h.agDev = agDev
	h.start(t, ag2)
	waitUp(t, ag2, 5*time.Second, "agent after restart")
	waitPeersAuthed(t, h.srv, 2, 6*time.Second)
	waitFlow(t, h, true, 4*time.Second, "10.200.7.50")
}

func TestHubMultipleSitesDisambiguated(t *testing.T) {
	// Two sites both running 192.168.1.0/24; the office one is presented as
	// 10.200.8.0/24 and translation keeps them apart.
	h := newHubEnv(t, hubSetup{
		allow: []string{"home", "office"},
		extraAgent: &hubExtraAgent{
			id:     "office",
			routes: []RegistryRoute{{Real: "192.168.1.0/24", Virtual: "10.200.8.0/24"}},
		},
	})
	waitUp(t, h.cl, 5*time.Second, "client")
	waitUp(t, h.ag, 5*time.Second, "agent")
	waitPeersAuthed(t, h.srv, 3, 5*time.Second)

	h.clDev.Inject(makeTCP(addr("10.77.0.2"), addr("10.200.7.50"), 8))
	if got, err := h.agDev.Recv(2 * time.Second); err != nil {
		t.Fatal(err)
	} else if netip.AddrFrom4([4]byte(got[16:20])) != addr("192.168.1.50") {
		t.Errorf("home agent saw dst %s", netip.AddrFrom4([4]byte(got[16:20])))
	}
	// Conflict detection: no duplicate prefix, so no conflict should be
	// reported for distinct virtual prefixes.
	if c := h.srv.Conflicts(); len(c) != 0 {
		t.Errorf("unexpected conflicts: %v", c)
	}
}

func TestRouteConflictDetected(t *testing.T) {
	h := newHubEnv(t, hubSetup{
		allow: []string{"home", "office"},
		extraAgent: &hubExtraAgent{
			id:     "office",
			routes: []RegistryRoute{{Real: "192.168.9.0/24", Virtual: "10.200.7.0/24"}}, // collides with home
		},
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.srv.Conflicts()) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("duplicate virtual prefix not reported: %+v", h.srv.Stats())
}

// ------------------------------------------------------------- registry unit

func TestParseAgentRegistry(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	key2 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	raw := `{"agents":[
	  {"id":"home","name":"家里","public_key":"` + key + `","tunnel_ip":"10.77.0.101",
	   "totp_secret":"JBSWY3DPEHPK3PXP","routes":[{"real":"192.168.1.0/24"},{"real":"10.1.0.0/16","virtual":"10.201.0.0/16"}]},
	  {"id":"off","public_key":"` + key2 + `","routes":[]}
	]}`
	m, err := ParseAgentRegistry([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(m))
	}
	home := m[hex.EncodeToString(bytes.Repeat([]byte{7}, 32))]
	if home.Role != RoleAgent {
		t.Errorf("role = %v, want agent", home.Role)
	}
	if !home.TunnelIP.IsValid() || home.TunnelIP.String() != "10.77.0.101" {
		t.Errorf("tunnel ip = %v", home.TunnelIP)
	}
	if !home.Enabled {
		t.Errorf("enabled default should be true")
	}
	pfx := home.VirtualPrefixes()
	if len(pfx) != 2 || pfx[0].String() != "192.168.1.0/24" || pfx[1].String() != "10.201.0.0/16" {
		t.Errorf("virtual prefixes = %v", pfx)
	}
	off := m[hex.EncodeToString(bytes.Repeat([]byte{8}, 32))]
	if off.Enabled != true || off.TunnelIP.IsValid() {
		t.Errorf("second agent: %+v", off)
	}

	// Errors.
	bad := []string{
		`{"agents":[{"id":"x","public_key":"short"}]}`,
		`{"agents":[{"public_key":"` + key + `"}]}`,                                                                  // no id
		`{"agents":[{"id":"x","public_key":"` + key + `","routes":[{"real":"1.2.3.0/24","virtual":"1.2.3.0/16"}]}]}`, // bad route
		`{"agents":[{"id":"x","public_key":"` + key + `","tunnel_ip":"nope"}]}`,
	}
	for i, b := range bad {
		if _, err := ParseAgentRegistry([]byte(b)); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestParseRegistryV03Fields(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	raw := `{"clients":[{"name":"mac","user":"zph","public_key":"` + key + `",
	   "totp_secret":"JBSWY3DPEHPK3PXP","tunnel_ip":"10.77.0.2","agents":["home","office"]}]}`
	m, err := ParseRegistry([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, pc := range m {
		if pc.Role != RoleClient {
			t.Errorf("role = %v", pc.Role)
		}
		if pc.TunnelIP.String() != "10.77.0.2" {
			t.Errorf("tunnel ip = %v", pc.TunnelIP)
		}
		if len(pc.AllowAgents) != 2 {
			t.Errorf("acl = %v", pc.AllowAgents)
		}
		if !pc.Enabled {
			t.Errorf("registry entries are enabled by default")
		}
	}
	// Disabled entries are skipped entirely.
	raw = `{"clients":[{"name":"old","public_key":"` + key + `","enabled":false}]}`
	if m, err = ParseRegistry([]byte(raw)); err != nil || len(m) != 0 {
		t.Errorf("disabled client must be skipped (err=%v, n=%d)", err, len(m))
	}
}
