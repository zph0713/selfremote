package tunnel

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// ---------------------------------------------------------------- builders

func tcpSeg(sport, dport uint16, payload []byte) []byte {
	t := make([]byte, 20, 20+len(payload))
	binary.BigEndian.PutUint16(t[0:2], sport)
	binary.BigEndian.PutUint16(t[2:4], dport)
	binary.BigEndian.PutUint32(t[4:8], 0x11223344) // seq
	binary.BigEndian.PutUint32(t[8:12], 0x55667788)
	t[12] = 0x50                                 // data offset = 5 words
	binary.BigEndian.PutUint16(t[14:16], 0xffff) // window (nonzero)
	return append(t, payload...)
}

func udpSeg(sport, dport uint16, payload []byte) []byte {
	u := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:2], sport)
	binary.BigEndian.PutUint16(u[2:4], dport)
	binary.BigEndian.PutUint16(u[4:6], uint16(8+len(payload)))
	return append(u, payload...)
}

func setV4Checksum(pkt []byte, src, dst netip.Addr, proto uint8, l4Off, csumOff int) {
	field := pkt[l4Off+csumOff : l4Off+csumOff+2]
	field[0], field[1] = 0, 0
	pseudo := make([]byte, 0, 12+len(pkt)-l4Off)
	pseudo = append(pseudo, src.AsSlice()...)
	pseudo = append(pseudo, dst.AsSlice()...)
	pseudo = append(pseudo, 0, proto)
	l4 := pkt[l4Off:]
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(l4)))
	pseudo = append(pseudo, lb[:]...)
	pseudo = append(pseudo, l4...)
	binary.BigEndian.PutUint16(field, onesComplement(pseudo))
}

func setV6Checksum(pkt []byte, src, dst netip.Addr, proto uint8, l4Off, csumOff int) {
	field := pkt[l4Off+csumOff : l4Off+csumOff+2]
	field[0], field[1] = 0, 0
	l4 := pkt[l4Off:]
	pseudo := make([]byte, 0, 40+len(l4))
	pseudo = append(pseudo, src.AsSlice()...)
	pseudo = append(pseudo, dst.AsSlice()...)
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(l4)))
	pseudo = append(pseudo, lb[:]...)
	pseudo = append(pseudo, 0, 0, 0, proto)
	pseudo = append(pseudo, l4...)
	binary.BigEndian.PutUint16(field, onesComplement(pseudo))
}

// ipv4 wraps l4 in an IPv4 header (checksum filled in).
func ipv4(src, dst netip.Addr, proto uint8, l4 []byte, fragOffBytes uint16, moreFrags bool) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(20+len(l4)))
	h[8] = 64 // TTL
	h[9] = proto
	copy(h[12:16], src.AsSlice())
	copy(h[16:20], dst.AsSlice())
	fo := fragOffBytes / 8
	if moreFrags {
		fo |= 0x2000
	}
	binary.BigEndian.PutUint16(h[6:8], fo)
	binary.BigEndian.PutUint16(h[10:12], onesComplement(h))
	return append(h, l4...)
}

// ipv6 wraps l4 in an IPv6 header.
func ipv6(src, dst netip.Addr, proto uint8, l4 []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:6], uint16(len(l4)))
	h[6] = proto
	h[7] = 64
	copy(h[8:24], src.AsSlice())
	copy(h[24:40], dst.AsSlice())
	return append(h, l4...)
}

// ---------------------------------------------------------------- verifiers

func verifyV4(t *testing.T, name string, pkt []byte) {
	t.Helper()
	ihl := int(pkt[0]&0x0f) * 4
	if got := onesComplement(pkt[:ihl]); got != 0 {
		t.Errorf("%s: IPv4 header checksum invalid (sum=%#x)", name, got)
	}
	proto := pkt[9]
	l4 := pkt[ihl:]
	// A fragment carries only part of the transport segment, so its checksum
	// can only be verified after reassembly — check the IP header only.
	if fragField := binary.BigEndian.Uint16(pkt[6:8]); fragField&0x3fff != 0 {
		return
	}
	if len(l4) < 2 {
		return
	}
	switch proto {
	case 6, 17, 58:
		co := l4ChecksumOffset(proto)
		if len(l4) < co+2 {
			return // first fragment whose transport header is cut off: nothing to verify here
		}
		src := netip.AddrFrom4([4]byte(pkt[12:16]))
		dst := netip.AddrFrom4([4]byte(pkt[16:20]))
		field := l4[co : co+2]
		cur := binary.BigEndian.Uint16(field)
		field[0], field[1] = 0, 0
		pseudo := append(append(append([]byte{}, src.AsSlice()...), dst.AsSlice()...), 0, proto)
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(l4)))
		pseudo = append(pseudo, lb[:]...)
		pseudo = append(pseudo, l4...)
		want := onesComplement(pseudo)
		binary.BigEndian.PutUint16(field, cur)
		if want != cur {
			t.Errorf("%s: transport checksum invalid: got %#x want %#x", name, cur, want)
		}
	}
}

func verifyV6(t *testing.T, name string, pkt []byte) {
	t.Helper()
	proto := pkt[6]
	if proto == 58 || proto == 6 || proto == 17 {
		l4 := pkt[40:]
		co := l4ChecksumOffset(proto)
		src := netip.AddrFrom16([16]byte(pkt[8:24]))
		dst := netip.AddrFrom16([16]byte(pkt[24:40]))
		field := l4[co : co+2]
		cur := binary.BigEndian.Uint16(field)
		field[0], field[1] = 0, 0
		pseudo := append(append([]byte{}, src.AsSlice()...), dst.AsSlice()...)
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(l4)))
		pseudo = append(pseudo, lb[:]...)
		pseudo = append(pseudo, 0, 0, 0, proto)
		pseudo = append(pseudo, l4...)
		want := onesComplement(pseudo)
		binary.BigEndian.PutUint16(field, cur)
		if want != cur {
			t.Errorf("%s: ICMPv6/TCP checksum invalid: got %#x want %#x", name, cur, want)
		}
	}
}

func icmp4Echo(id, seq uint16, payload []byte) []byte {
	m := make([]byte, 8, 8+len(payload))
	m[0] = 8 // echo request
	binary.BigEndian.PutUint16(m[4:6], id)
	binary.BigEndian.PutUint16(m[6:8], seq)
	body := append(m, payload...)
	binary.BigEndian.PutUint16(body[2:4], onesComplement(body))
	return body
}

func icmp6Echo(id, seq uint16, payload []byte) []byte {
	m := make([]byte, 8, 8+len(payload))
	m[0] = 128 // echo request
	binary.BigEndian.PutUint16(m[4:6], id)
	binary.BigEndian.PutUint16(m[6:8], seq)
	return append(m, payload...)
}

func mustMap(t *testing.T, real, virt string) RouteMap {
	t.Helper()
	m, err := ParseRouteMap(real, virt)
	if err != nil {
		t.Fatalf("ParseRouteMap(%s, %s): %v", real, virt, err)
	}
	return m
}

func addr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

// ---------------------------------------------------------------- tests

func TestParseRouteMap(t *testing.T) {
	if m := mustMap(t, "192.168.1.0/24", ""); !m.Identity() {
		t.Errorf("empty virtual must be identity, got %s", m)
	}
	m := mustMap(t, "192.168.1.0/24", "10.200.7.0/24")
	if m.Identity() {
		t.Errorf("expected non-identity")
	}
	for _, tc := range []struct{ real, virt string }{
		{"192.168.1.0/24", "10.200.7.0/16"},  // length mismatch
		{"192.168.1.0/24", "2001:db8::/64"},  // family mismatch
		{"192.168.1.0/24", "10.200.7.0/24x"}, // parse error
		{"192.168.1.0/33", ""},               // parse error
	} {
		if _, err := ParseRouteMap(tc.real, tc.virt); err == nil {
			t.Errorf("ParseRouteMap(%s, %s): expected error", tc.real, tc.virt)
		}
	}
}

func TestTranslatorIdentity(t *testing.T) {
	tr, err := NewTranslator([]RouteMap{mustMap(t, "192.168.1.0/24", "")})
	if err != nil {
		t.Fatal(err)
	}
	if !tr.Empty() {
		t.Errorf("identity map should report Empty()")
	}
	pkt := ipv4(addr("10.77.0.2"), addr("192.168.1.50"), 6, tcpSeg(1234, 445, []byte("hi")), 0, false)
	orig := append([]byte(nil), pkt...)
	out, ok := tr.ToLocal(pkt)
	if !ok || !bytes.Equal(out, orig) {
		t.Errorf("identity translation must not modify the packet")
	}
}

func TestTranslatorToLocalIPv4TCP(t *testing.T) {
	tr, _ := NewTranslator([]RouteMap{mustMap(t, "192.168.1.0/24", "10.200.7.0/24")})
	src, dst := addr("10.77.0.2"), addr("10.200.7.50")
	l4 := tcpSeg(51000, 445, []byte("hello world"))
	pkt := ipv4(src, dst, 6, l4, 0, false)
	setV4Checksum(pkt, src, dst, 6, 20, 16)

	out, ok := tr.ToLocal(pkt)
	if !ok {
		t.Fatal("ToLocal dropped a routable packet")
	}
	if got := netip.AddrFrom4([4]byte(out[16:20])); got != addr("192.168.1.50") {
		t.Errorf("dst = %s, want 192.168.1.50", got)
	}
	if got := netip.AddrFrom4([4]byte(out[12:16])); got != src {
		t.Errorf("src must be untouched, got %s", got)
	}
	verifyV4(t, "ToLocal TCP", out)
}

func TestTranslatorToTunnelIPv4TCP(t *testing.T) {
	tr, _ := NewTranslator([]RouteMap{mustMap(t, "192.168.1.0/24", "10.200.7.0/24")})
	src, dst := addr("192.168.1.50"), addr("10.77.0.2")
	l4 := tcpSeg(445, 51000, []byte("response payload"))
	pkt := ipv4(src, dst, 6, l4, 0, false)
	setV4Checksum(pkt, src, dst, 6, 20, 16)

	out, ok := tr.ToTunnel(pkt)
	if !ok {
		t.Fatal("ToTunnel dropped a routable packet")
	}
	if got := netip.AddrFrom4([4]byte(out[12:16])); got != addr("10.200.7.50") {
		t.Errorf("src = %s, want 10.200.7.50", got)
	}
	verifyV4(t, "ToTunnel TCP", out)
}

func TestTranslatorUDPAndICMPv4(t *testing.T) {
	tr, _ := NewTranslator([]RouteMap{mustMap(t, "192.168.0.0/16", "10.201.0.0/16")})

	// UDP
	src, dst := addr("10.77.0.3"), addr("10.201.9.4")
	pkt := ipv4(src, dst, 17, udpSeg(5353, 53, []byte("dns query")), 0, false)
	setV4Checksum(pkt, src, dst, 17, 20, 6)
	if out, ok := tr.ToLocal(pkt); !ok {
		t.Fatal("UDP: dropped")
	} else {
		if got := netip.AddrFrom4([4]byte(out[16:20])); got != addr("192.168.9.4") {
			t.Errorf("UDP dst = %s, want 192.168.9.4", got)
		}
		verifyV4(t, "UDP", out)
	}

	// ICMPv4 echo: addresses change but the ICMP checksum must stay valid
	// (it does not cover the IP pseudo-header).
	src2, dst2 := addr("10.77.0.3"), addr("10.201.9.9")
	icmp := ipv4(src2, dst2, 1, icmp4Echo(7, 1, []byte("ping")), 0, false)
	before := binary.BigEndian.Uint16(icmp[22:24])
	out, ok := tr.ToLocal(icmp)
	if !ok {
		t.Fatal("ICMP: dropped")
	}
	if got := netip.AddrFrom4([4]byte(out[16:20])); got != addr("192.168.9.9") {
		t.Errorf("ICMP dst = %s, want 192.168.9.9", got)
	}
	if after := binary.BigEndian.Uint16(out[22:24]); after != before {
		t.Errorf("ICMPv4 checksum must not change: %#x -> %#x", before, after)
	}
	if got := onesComplement(out[20:]); got != 0 {
		t.Errorf("ICMPv4 checksum invalid after rewrite (sum=%#x)", got)
	}
	if got := onesComplement(out[:20]); got != 0 {
		t.Errorf("IPv4 header checksum invalid after rewrite (sum=%#x)", got)
	}
}

func TestTranslatorIPv6TCPAndICMPv6(t *testing.T) {
	tr, _ := NewTranslator([]RouteMap{mustMap(t, "fd00:5::/64", "fd00:7::/64")})

	// TCP
	src, dst := addr("fd00:0:0:1::2"), addr("fd00:7::50")
	pkt := ipv6(src, dst, 6, tcpSeg(40000, 22, []byte("ssh handshake")))
	setV6Checksum(pkt, src, dst, 6, 40, 16)
	out, ok := tr.ToLocal(pkt)
	if !ok {
		t.Fatal("IPv6 TCP: dropped")
	}
	if got := netip.AddrFrom16([16]byte(out[24:40])); got != addr("fd00:5::50") {
		t.Errorf("IPv6 dst = %s, want fd00:5::50", got)
	}
	verifyV6(t, "IPv6 TCP", out)

	// ICMPv6 echo: its checksum DOES cover the pseudo-header, so it must be
	// updated together with the address.
	src2, dst2 := addr("fd00:0:0:1::2"), addr("fd00:7::9")
	icmp6 := ipv6(src2, dst2, 58, icmp6Echo(9, 2, []byte("ping6")))
	setV6Checksum(icmp6, src2, dst2, 58, 40, 2)
	out2, ok := tr.ToLocal(icmp6)
	if !ok {
		t.Fatal("ICMPv6: dropped")
	}
	verifyV6(t, "ICMPv6", out2)
	if got := netip.AddrFrom16([16]byte(out2[24:40])); got != addr("fd00:5::9") {
		t.Errorf("ICMPv6 dst = %s, want fd00:5::9", got)
	}
}

func TestTranslatorFragments(t *testing.T) {
	tr, _ := NewTranslator([]RouteMap{mustMap(t, "192.168.1.0/24", "10.200.7.0/24")})
	src, dst := addr("10.77.0.2"), addr("10.200.7.50")

	// Reference: the same datagram already translated, checksummed correctly.
	l4 := tcpSeg(51000, 445, bytes.Repeat([]byte{0xAB}, 40))
	refPkt := ipv4(src, dst, 6, append([]byte(nil), l4...), 0, false)
	setV4Checksum(refPkt, src, addr("192.168.1.50"), 6, 20, 16)
	wantCsum := binary.BigEndian.Uint16(refPkt[36:38])

	// Original (untranslated) datagram, then split into two fragments with the
	// TCP checksum (header offset 16) living in the first one.
	origPkt := ipv4(src, dst, 6, append([]byte(nil), l4...), 0, false)
	setV4Checksum(origPkt, src, dst, 6, 20, 16)
	const cut = 24
	frag1 := ipv4(src, dst, 6, append([]byte(nil), origPkt[20:20+cut]...), 0, true)
	frag2 := ipv4(src, dst, 6, append([]byte(nil), origPkt[20+cut:]...), cut, false)

	out1, ok1 := tr.ToLocal(frag1)
	out2, ok2 := tr.ToLocal(frag2)
	if !ok1 || !ok2 {
		t.Fatal("fragment dropped")
	}
	for i, f := range [][]byte{out1, out2} {
		if got := netip.AddrFrom4([4]byte(f[16:20])); got != addr("192.168.1.50") {
			t.Errorf("frag%d dst = %s, want 192.168.1.50", i+1, got)
		}
		verifyV4(t, "fragment", f)
	}
	if got := binary.BigEndian.Uint16(out1[36:38]); got != wantCsum {
		t.Errorf("first fragment TCP checksum = %#x, want %#x (translated reference)", got, wantCsum)
	}
	if !bytes.Equal(out2[20:], origPkt[20+cut:]) {
		t.Errorf("non-first fragment payload must be untouched")
	}
}

func TestTranslatorDropsAndPassthrough(t *testing.T) {
	tr, _ := NewTranslator(
		[]RouteMap{mustMap(t, "192.168.1.0/24", "10.200.7.0/24")},
		addr("10.77.0.101"),
	)
	// Destination outside every virtual prefix: dropped.
	if _, ok := tr.ToLocal(ipv4(addr("10.77.0.2"), addr("8.8.8.8"), 6, tcpSeg(1, 2, nil), 0, false)); ok {
		t.Errorf("out-of-map packet must be dropped")
	}
	// Our own tunnel address passes through untouched (kernel answers it).
	pkt := ipv4(addr("10.77.0.2"), addr("10.77.0.101"), 1, icmp4Echo(1, 1, []byte("p")), 0, false)
	orig := append([]byte(nil), pkt...)
	out, ok := tr.ToLocal(pkt)
	if !ok || !bytes.Equal(out, orig) {
		t.Errorf("packet to our own tunnel address must pass through")
	}
	// Source that matches no real prefix: dropped.
	if _, ok := tr.ToTunnel(ipv4(addr("203.0.113.5"), addr("10.77.0.2"), 6, tcpSeg(1, 2, nil), 0, false)); ok {
		t.Errorf("foreign source must be dropped (anti-spoof)")
	}
	// Our own tunnel address as a source passes through.
	if _, ok := tr.ToTunnel(ipv4(addr("10.77.0.101"), addr("10.77.0.2"), 1, icmp4Echo(1, 1, nil), 0, false)); !ok {
		t.Errorf("reply from our own tunnel address must pass through")
	}
}

func TestTranslatorRejectsBadMaps(t *testing.T) {
	if _, err := NewTranslator([]RouteMap{{Real: netip.MustParsePrefix("192.168.1.0/24"), Virtual: netip.MustParsePrefix("10.200.7.0/16")}}); err == nil {
		t.Errorf("prefix length mismatch must be rejected")
	}
}
