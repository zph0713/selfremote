package tunnel

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// ---------------------------------------------------------------- builders

// v4Pkt builds a minimal IPv4 packet with an optional L4 header.
func v4Pkt(proto uint8, src, dst netip.Addr, l4 []byte, fragOff uint16) []byte {
	pkt := make([]byte, 20+len(l4))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = proto
	binary.BigEndian.PutUint16(pkt[6:8], fragOff)
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	copy(pkt[20:], l4)
	return pkt
}

// v6Pkt builds a minimal IPv6 packet with an L4 header.
func v6Pkt(proto uint8, src, dst netip.Addr, l4 []byte) []byte {
	pkt := make([]byte, 40+len(l4))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(l4)))
	pkt[6] = proto
	pkt[7] = 64
	copy(pkt[8:24], src.AsSlice())
	copy(pkt[24:40], dst.AsSlice())
	copy(pkt[40:], l4)
	return pkt
}

func tcpPorts(src, dst uint16) []byte {
	l4 := make([]byte, 20)
	binary.BigEndian.PutUint16(l4[0:2], src)
	binary.BigEndian.PutUint16(l4[2:4], dst)
	l4[12] = 0x50 // data offset
	return l4
}

func udpPorts(src, dst uint16) []byte {
	l4 := make([]byte, 8)
	binary.BigEndian.PutUint16(l4[0:2], src)
	binary.BigEndian.PutUint16(l4[2:4], dst)
	binary.BigEndian.PutUint16(l4[4:6], 8)
	return l4
}

func flowKeyOf(t *testing.T, pkt []byte, toSite bool) flowKey {
	t.Helper()
	h, err := parseIPHeader(pkt)
	if err != nil {
		t.Fatalf("parseIPHeader: %v", err)
	}
	ag := &peerState{uid: 7}
	cl := &peerState{uid: 9}
	return flowKeyFor(cl, ag, pkt, h, toSite)
}

// ------------------------------------------------------------------- tests

func TestFlowKeyForReadsTheSiteEndpoint(t *testing.T) {
	client := netip.MustParseAddr("10.77.0.2")
	server := netip.MustParseAddr("10.200.7.50")
	cases := []struct {
		name   string
		pkt    []byte
		toSite bool
		proto  uint8
		site   string
		port   uint16
	}{
		{
			name: "tcp towards the site uses the destination port",
			pkt:  v4Pkt(6, client, server, tcpPorts(51000, 445), 0), toSite: true,
			proto: 6, site: "10.200.7.50", port: 445,
		},
		{
			name: "tcp from the site uses the source port",
			pkt:  v4Pkt(6, server, client, tcpPorts(445, 51000), 0), toSite: false,
			proto: 6, site: "10.200.7.50", port: 445,
		},
		{
			name: "udp towards the site",
			pkt:  v4Pkt(17, client, server, udpPorts(5353, 53), 0), toSite: true,
			proto: 17, site: "10.200.7.50", port: 53,
		},
		{
			name: "icmp has no port",
			pkt:  v4Pkt(1, client, server, []byte{8, 0, 0, 0}, 0), toSite: true,
			proto: 1, site: "10.200.7.50", port: 0,
		},
		{
			name: "non-first fragment has no transport header",
			pkt:  v4Pkt(6, client, server, tcpPorts(51000, 445), 0x0100), toSite: true,
			proto: 6, site: "10.200.7.50", port: 0,
		},
		{
			name: "ipv6 tcp uses the same offsets",
			pkt: v6Pkt(6, netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::50"),
				tcpPorts(51000, 22)), toSite: true,
			proto: 6, site: "fd00::50", port: 22,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := flowKeyOf(t, c.pkt, c.toSite)
			if k.agent != 7 || k.client != 9 {
				t.Errorf("peer uids = (%d,%d), want (7,9)", k.agent, k.client)
			}
			if k.proto != c.proto {
				t.Errorf("proto = %d, want %d", k.proto, c.proto)
			}
			if k.site.String() != c.site {
				t.Errorf("site = %s, want %s", k.site, c.site)
			}
			if k.port != c.port {
				t.Errorf("port = %d, want %d", k.port, c.port)
			}
		})
	}
}

func TestFlowTableCountsBothDirectionsAndRates(t *testing.T) {
	tbl := newFlowTable(16)
	k := flowKey{agent: 1, client: 2, proto: 6, site: netip.MustParseAddr("10.200.7.5"), port: 445}
	tbl.observe(k, true, 100)
	tbl.observe(k, true, 140)
	tbl.observe(k, false, 60)

	s := tbl.sample(time.Now())
	if len(s) != 1 {
		t.Fatalf("sample returned %d flows, want 1", len(s))
	}
	if s[0].toBytes != 240 || s[0].fromBytes != 60 {
		t.Errorf("bytes = (%d,%d), want (240,60)", s[0].toBytes, s[0].fromBytes)
	}
	if s[0].toPkts != 2 || s[0].fromPkts != 1 {
		t.Errorf("packets = (%d,%d), want (2,1)", s[0].toPkts, s[0].fromPkts)
	}
	// First sample only primes the rate baseline.
	if s[0].bpsTo != 0 {
		t.Errorf("first sample bps = %d, want 0", s[0].bpsTo)
	}

	// After the minimum interval, a further packet must produce a non-zero rate.
	time.Sleep(600 * time.Millisecond)
	tbl.observe(k, true, 100)
	s = tbl.sample(time.Now())
	if s[0].bpsTo == 0 {
		t.Errorf("bps = 0 after traffic, want > 0")
	}
}

func TestFlowTableEvictsIdleFlows(t *testing.T) {
	tbl := newFlowTable(2)
	old := flowKey{agent: 1, client: 2, proto: 6, site: netip.MustParseAddr("10.200.7.5"), port: 1}
	tbl.observe(old, true, 10)
	// Backdate the entry so the next sweep considers it idle.
	tbl.mu.Lock()
	tbl.m[old].lastSeen.Store(time.Now().Add(-3 * flowIdleTTL).UnixNano())
	tbl.lastSweep = time.Time{}
	tbl.mu.Unlock()

	tbl.observe(flowKey{agent: 1, client: 2, proto: 6, site: netip.MustParseAddr("10.200.7.5"), port: 2}, true, 10)
	tbl.observe(flowKey{agent: 1, client: 2, proto: 6, site: netip.MustParseAddr("10.200.7.5"), port: 3}, true, 10)

	n, unaccounted := tbl.stats()
	if n != 2 {
		t.Errorf("flows = %d, want 2 (idle entry evicted)", n)
	}
	if unaccounted != 0 {
		t.Errorf("unaccounted = %d, want 0", unaccounted)
	}
	if _, ok := tbl.m[old]; ok {
		t.Errorf("idle flow survived the sweep")
	}
}

func TestFlowTableDegradesWhenFull(t *testing.T) {
	tbl := newFlowTable(2)
	tbl.lastSweep = time.Now() // suppress the sweep so the table stays full
	for i := 0; i < 5; i++ {
		tbl.observe(flowKey{agent: 1, client: 2, proto: 6,
			site: netip.MustParseAddr("10.200.7.5"), port: uint16(1000 + i)}, true, 10)
	}
	n, unaccounted := tbl.stats()
	if n != 2 {
		t.Fatalf("flows = %d, want the 2-entry cap", n)
	}
	if unaccounted == 0 {
		t.Errorf("unaccounted = 0, want the overflow recorded")
	}
}

func TestFlowSnapshotAndPeerPorts(t *testing.T) {
	_, agPub := mustKeypair(t)
	_, clPub := mustKeypair(t)
	srvPriv, _ := mustKeypair(t)

	e, err := New(Options{
		Mode: ModeServer, PrivateKey: srvPriv, Listen: "127.0.0.1:0",
		TunnelCIDR: "10.77.0.1/24", SkipNetConfig: true, Logf: t.Logf,
		ClientsFile: "", Peers: []PeerConfig{
			{Name: "home", ID: "home", PublicKey: agPub, Role: RoleAgent, Enabled: true,
				TunnelIP: netip.MustParseAddr("10.77.0.100")},
			{Name: "mac", PublicKey: clPub, Role: RoleClient,
				AllowAgents: []string{"home"}},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.conn.Close()

	var agent, client *peerState
	for _, p := range e.peers {
		if p.cfg.Role == RoleAgent {
			agent = p
		} else {
			client = p
		}
	}
	if agent == nil || client == nil {
		t.Fatalf("peers not installed")
	}
	if agent.uid == 0 || client.uid == 0 || agent.uid == client.uid {
		t.Fatalf("peer uids not assigned: agent=%d client=%d", agent.uid, client.uid)
	}

	// Two conversations: 445 towards one site host and 53 towards another.
	siteA := netip.MustParseAddr("10.200.7.50")
	siteB := netip.MustParseAddr("10.200.7.51")
	e.flows.observe(flowKey{agent: agent.uid, client: client.uid, proto: 6, site: siteA, port: 445}, true, 1000)
	e.flows.observe(flowKey{agent: agent.uid, client: client.uid, proto: 6, site: siteA, port: 445}, false, 2000)
	e.flows.observe(flowKey{agent: agent.uid, client: client.uid, proto: 17, site: siteB, port: 53}, true, 100)

	flows := e.FlowSnapshot(10)
	if len(flows) != 2 {
		t.Fatalf("flows = %d, want 2", len(flows))
	}
	if flows[0].ProtoName != "tcp" || flows[0].Port != 445 || flows[0].SiteIP != siteA.String() {
		t.Errorf("top flow = %+v, want tcp/445 on %s", flows[0], siteA)
	}
	if flows[0].AgentID != "home" || flows[0].ClientName != "mac" {
		t.Errorf("flow identity = (%q,%q), want (home,mac)", flows[0].AgentID, flows[0].ClientName)
	}
	if flows[0].BytesToSite != 1000 || flows[0].BytesFrom != 2000 {
		t.Errorf("flow bytes = (%d,%d), want (1000,2000)", flows[0].BytesToSite, flows[0].BytesFrom)
	}

	ports := e.PeerPorts("home", 10)
	if len(ports) != 2 {
		t.Fatalf("agent ports = %d, want 2", len(ports))
	}
	if ports[0].Port != 445 || ports[0].Clients != 1 {
		t.Errorf("top port row = %+v, want port 445 seen by 1 client", ports[0])
	}
	if got := e.PeerPorts("mac", 10); len(got) != 2 {
		t.Errorf("client ports = %d, want 2", len(got))
	}
	if got := e.PeerPorts("nope", 10); got != nil {
		t.Errorf("unknown peer returned %d rows, want nil", len(got))
	}
}

// TestHubRecordsPortFlows exercises the real relay path: packets injected on
// the client device must show up as a flow on the server.
func TestHubRecordsPortFlows(t *testing.T) {
	h := newHubEnv(t, hubSetup{allow: []string{"home"}})
	waitUp(t, h.cl, 5*time.Second, "client")
	waitUp(t, h.ag, 5*time.Second, "agent")
	waitPeersAuthed(t, h.srv, 2, 5*time.Second)

	// client -> site (TCP 445), then the reply (source port 445 — a real reply
	// would carry the service port back; makeTCP always uses 51000 as source).
	h.clDev.Inject(makeTCP(addr("10.77.0.2"), addr("10.200.7.50"), 40))
	if _, err := h.agDev.Recv(3 * time.Second); err != nil {
		t.Fatalf("agent did not receive the packet: %v", err)
	}
	reply := ipv4(addr("192.168.1.50"), addr("10.77.0.2"), 6,
		tcpSeg(445, 51000, bytes.Repeat([]byte{0x5A}, 80)), 0, false)
	setV4Checksum(reply, addr("192.168.1.50"), addr("10.77.0.2"), 6, 20, 16)
	h.agDev.Inject(reply)
	if _, err := h.clDev.Recv(3 * time.Second); err != nil {
		t.Fatalf("client did not receive the reply: %v", err)
	}

	flows := h.srv.FlowSnapshot(10)
	if len(flows) != 1 {
		t.Fatalf("flows = %d, want 1 (%+v)", len(flows), flows)
	}
	f := flows[0]
	// The hub sees the virtual prefix: that is what the client addressed.
	if f.ProtoName != "tcp" || f.Port != 445 || f.SiteIP != "10.200.7.50" {
		t.Errorf("flow = %+v, want tcp/445 -> 10.200.7.50", f)
	}
	if f.BytesToSite == 0 || f.BytesFrom == 0 {
		t.Errorf("flow bytes = (%d,%d), want both directions counted", f.BytesToSite, f.BytesFrom)
	}
	if f.AgentID != "home" || f.ClientName == "" {
		t.Errorf("flow identity = (%q,%q), want the site id and a client name", f.AgentID, f.ClientName)
	}
	if ports := h.srv.PeerPorts("home", 10); len(ports) != 1 || ports[0].Port != 445 {
		t.Errorf("PeerPorts(home) = %+v, want one 445 row", ports)
	}
}

// BenchmarkFlowObserve measures the per-packet cost added to the relay hot
// path. The budget: at 100 Mbps with 1360-byte packets (~9.2k pps) the flow
// table must stay well under 2% of one core.
func BenchmarkFlowObserve(b *testing.B) {
	tbl := newFlowTable(4096)
	k := flowKey{agent: 1, client: 2, proto: 6, site: netip.MustParseAddr("10.200.7.50"), port: 445}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.observe(k, i%2 == 0, 1360)
	}
}

// BenchmarkFlowObserveManyKeys covers the worst case where every packet opens
// a new flow (port scan / many short connections): insertion plus cold lookups.
func BenchmarkFlowObserveManyKeys(b *testing.B) {
	tbl := newFlowTable(4096)
	site := netip.MustParseAddr("10.200.7.50")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.observe(flowKey{agent: 1, client: 2, proto: 6, site: site, port: uint16(10000 + i%5000)}, true, 1360)
	}
}
