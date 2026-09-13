package tunnel

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// RouteMap describes how one real site prefix is presented inside the tunnel.
//
// Every site attached to a server gets its own "virtual" prefix; a client
// addresses the site by that virtual prefix. When a site's real LAN subnet is
// unique (the common case) the virtual prefix equals the real one and no
// rewriting happens. When two sites collide (both 192.168.1.0/24, say), one of
// them gets a distinct virtual prefix and the agent rewrites addresses at its
// edge.
//
// Real and Virtual must have the same prefix length: the rewrite then only
// swaps the network part and preserves the host bits, which makes translation
// stateless — no connection tracking, no port allocation, no per-flow state.
type RouteMap struct {
	Real    netip.Prefix
	Virtual netip.Prefix
}

// Identity reports whether the mapping is a no-op.
func (m RouteMap) Identity() bool { return m.Real == m.Virtual }

func (m RouteMap) String() string { return m.Real.String() + "=" + m.Virtual.String() }

// ParseRouteMap builds a RouteMap from config strings. An empty virtual prefix
// means identity (the real prefix is presented as-is).
func ParseRouteMap(real, virtual string) (RouteMap, error) {
	rp, err := netip.ParsePrefix(real)
	if err != nil {
		return RouteMap{}, fmt.Errorf("real prefix %q: %w", real, err)
	}
	rp = rp.Masked()
	if virtual == "" {
		return RouteMap{Real: rp, Virtual: rp}, nil
	}
	vp, err := netip.ParsePrefix(virtual)
	if err != nil {
		return RouteMap{}, fmt.Errorf("virtual prefix %q: %w", virtual, err)
	}
	vp = vp.Masked()
	if rp.Addr().Is4() != vp.Addr().Is4() {
		return RouteMap{}, fmt.Errorf("route %s: real and virtual must be the same address family", real)
	}
	if rp.Bits() != vp.Bits() {
		return RouteMap{}, fmt.Errorf("route %s=%s: real and virtual must have the same prefix length (otherwise translation needs per-flow state)", real, virtual)
	}
	return RouteMap{Real: rp, Virtual: vp}, nil
}

// Translator rewrites packet addresses at a site edge (agent):
//
//	tunnel -> LAN   (ToLocal):  dst virtual prefix -> real prefix
//	LAN -> tunnel   (ToTunnel): src real prefix    -> virtual prefix
//
// Packets whose addresses fall outside every mapping are dropped (false),
// except traffic to/from our own tunnel address, which passes through.
type Translator struct {
	maps  []RouteMap
	local []netip.Addr // our own tunnel addresses (pass through untouched)
}

// NewTranslator validates the maps; local addresses always pass through.
func NewTranslator(maps []RouteMap, local ...netip.Addr) (*Translator, error) {
	t := &Translator{local: local}
	for _, m := range maps {
		if m.Real.Addr().Is4() != m.Virtual.Addr().Is4() {
			return nil, fmt.Errorf("route %s: address family mismatch", m)
		}
		if m.Real.Bits() != m.Virtual.Bits() {
			return nil, fmt.Errorf("route %s: prefix lengths differ", m)
		}
		t.maps = append(t.maps, m)
	}
	return t, nil
}

// Empty reports whether no translation is needed at all.
func (t *Translator) Empty() bool {
	if t == nil {
		return true
	}
	for _, m := range t.maps {
		if !m.Identity() {
			return false
		}
	}
	return true
}

func (t *Translator) isLocal(a netip.Addr) bool {
	for _, l := range t.local {
		if l == a {
			return true
		}
	}
	return false
}

// ToLocal rewrites a decrypted packet's destination address from the virtual
// prefix to the real one, ready to be written to the TUN device. It returns
// ok=false when the packet must be dropped.
func (t *Translator) ToLocal(pkt []byte) ([]byte, bool) {
	return t.rewrite(pkt, true)
}

// ToTunnel rewrites a packet's source address from the real prefix to the
// virtual one, ready to be sealed and sent to the server.
func (t *Translator) ToTunnel(pkt []byte) ([]byte, bool) {
	return t.rewrite(pkt, false)
}

func (t *Translator) rewrite(pkt []byte, toLocal bool) ([]byte, bool) {
	h, err := parseIPHeader(pkt)
	if err != nil {
		return nil, false
	}
	addr := h.dst
	if !toLocal {
		addr = h.src
	}
	if t == nil || len(t.maps) == 0 {
		return pkt, false
	}
	var match *RouteMap
	for i := range t.maps {
		m := &t.maps[i]
		if toLocal {
			if m.Virtual.Contains(addr) {
				match = m
				break
			}
		} else if m.Real.Contains(addr) {
			match = m
			break
		}
	}
	if match == nil {
		// Our own tunnel address (e.g. a client pinging the agent's tunnel IP)
		// passes through so the kernel can answer it locally.
		if t.isLocal(addr) {
			return pkt, true
		}
		return nil, false
	}
	var newAddr netip.Addr
	if toLocal {
		newAddr = remapAddr(addr, match.Virtual, match.Real)
	} else {
		newAddr = remapAddr(addr, match.Real, match.Virtual)
	}
	if newAddr == addr {
		return pkt, true // identity mapping
	}
	if !h.rewriteAddr(pkt, toLocal, newAddr) {
		return nil, false
	}
	return pkt, true
}

// remapAddr keeps the host bits of addr (relative to from) and replaces the
// network part with to's.
func remapAddr(addr netip.Addr, from, to netip.Prefix) netip.Addr {
	bits := from.Bits()
	if addr.Is4() {
		a, o := addr.As4(), to.Masked().Addr().As4()
		out := o
		for i := 0; i < 4; i++ {
			lo := bits - 8*i
			switch {
			case lo >= 8:
				out[i] = o[i]
			case lo <= 0:
				out[i] = a[i]
			default:
				mask := uint8(0xFF) << uint(8-lo)
				out[i] = (o[i] & mask) | (a[i] & ^mask)
			}
		}
		return netip.AddrFrom4(out)
	}
	a, o := addr.As16(), to.Masked().Addr().As16()
	out := o
	for i := 0; i < 16; i++ {
		lo := bits - 8*i
		switch {
		case lo >= 8:
			out[i] = o[i]
		case lo <= 0:
			out[i] = a[i]
		default:
			mask := uint8(0xFF) << uint(8-lo)
			out[i] = (o[i] & mask) | (a[i] & ^mask)
		}
	}
	return netip.AddrFrom16(out)
}

// ------------------------------------------------------------------ IP layer

// ipHeaderView is a parsed view of one IPv4/IPv6 packet.
type ipHeaderView struct {
	v4     bool
	src    netip.Addr
	dst    netip.Addr
	srcOff int
	dstOff int

	// l4Off is where the transport header starts, or -1 when this packet does
	// not carry one (non-first fragment, truncated, encrypted...).
	l4Off   int
	l4Proto uint8
}

func parseIPHeader(pkt []byte) (*ipHeaderView, error) {
	if len(pkt) < 20 {
		return nil, fmt.Errorf("short packet")
	}
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return nil, fmt.Errorf("bad IHL")
		}
		h := &ipHeaderView{
			v4:      true,
			srcOff:  12,
			dstOff:  16,
			l4Proto: pkt[9],
			l4Off:   -1,
		}
		h.src = netip.AddrFrom4([4]byte(pkt[12:16]))
		h.dst = netip.AddrFrom4([4]byte(pkt[16:20]))
		fragOff := binary.BigEndian.Uint16(pkt[6:8]) & 0x1fff
		if fragOff == 0 {
			h.l4Off = ihl
		}
		return h, nil
	case 6:
		if len(pkt) < 40 {
			return nil, fmt.Errorf("short IPv6 packet")
		}
		h := &ipHeaderView{
			srcOff: 8,
			dstOff: 24,
			l4Off:  -1,
		}
		h.src = netip.AddrFrom16([16]byte(pkt[8:24]))
		h.dst = netip.AddrFrom16([16]byte(pkt[24:40]))
		// Walk the extension header chain to find the transport header.
		nh := pkt[6]
		off := 40
		for {
			switch nh {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if len(pkt) < off+2 {
					return nil, fmt.Errorf("truncated IPv6 extension header")
				}
				nh, off = pkt[off], off+int(pkt[off+1]+1)*8
			case 44: // fragment
				if len(pkt) < off+8 {
					return nil, fmt.Errorf("truncated IPv6 fragment header")
				}
				fragOff := (binary.BigEndian.Uint16(pkt[off+2:off+4]) & 0xfff8) >> 3
				nh, off = pkt[off], off+8
				if fragOff != 0 {
					return h, nil // no transport header in this packet
				}
			default:
				h.l4Proto = nh
				if len(pkt) >= off {
					h.l4Off = off
				}
				return h, nil
			}
			if off >= len(pkt) {
				return nil, fmt.Errorf("bad IPv6 extension chain")
			}
		}
	default:
		return nil, fmt.Errorf("not an IP packet")
	}
}

// l4ChecksumOffset returns the offset of the transport checksum relative to
// the start of the transport header, or -1 when the protocol has no
// pseudo-header checksum to fix up.
func l4ChecksumOffset(proto uint8) int {
	switch proto {
	case 6: // TCP
		return 16
	case 17: // UDP
		return 6
	case 58: // ICMPv6
		return 2
	}
	return -1 // ICMPv4 and everything else: checksum does not cover addresses
}

// rewriteAddr writes newAddr into the packet at the src or dst position and
// fixes up both the IP header checksum (IPv4) and, when the transport header
// is present, the transport checksum's pseudo-header contribution.
func (h *ipHeaderView) rewriteAddr(pkt []byte, toDst bool, newAddr netip.Addr) bool {
	off, old := h.srcOff, h.src
	if toDst {
		off, old = h.dstOff, h.dst
	}
	if h.v4 {
		if len(pkt) < off+4 {
			return false
		}
		b := newAddr.As4()
		copy(pkt[off:off+4], b[:])
		// IPv4 header checksum: full recompute (20..60 bytes, cheap).
		ihl := int(pkt[0]&0x0f) * 4
		pkt[10], pkt[11] = 0, 0
		binary.BigEndian.PutUint16(pkt[10:12], onesComplement(pkt[:ihl]))
	} else {
		if len(pkt) < off+16 {
			return false
		}
		b := newAddr.As16()
		copy(pkt[off:off+16], b[:])
	}
	// Transport checksum: incremental update over the pseudo-header change.
	if h.l4Off >= 0 {
		co := l4ChecksumOffset(h.l4Proto)
		if co >= 0 && len(pkt) >= h.l4Off+co+2 {
			field := pkt[h.l4Off+co : h.l4Off+co+2]
			cur := binary.BigEndian.Uint16(field)
			var oldB, newB [16]byte
			if h.v4 {
				o, n := old.As4(), newAddr.As4()
				copy(oldB[:4], o[:])
				copy(newB[:4], n[:])
			} else {
				oldB, newB = old.As16(), newAddr.As16()
			}
			n := len(oldB)
			if h.v4 {
				n = 4
			}
			binary.BigEndian.PutUint16(field, checksumDelta(cur, oldB[:n], newB[:n]))
		}
	}
	return true
}

// onesComplement computes the standard Internet checksum (RFC 1071).
func onesComplement(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// checksumDelta applies RFC 1624's incremental update for replacing the
// 16-bit-aligned byte strings oldB with newB inside a checksum-protected area.
func checksumDelta(cur uint16, oldB, newB []byte) uint16 {
	sum := uint32(^cur) & 0xffff
	for i := 0; i+1 < len(oldB); i += 2 {
		sum += uint32(^binary.BigEndian.Uint16(oldB[i:])) & 0xffff
		sum += uint32(binary.BigEndian.Uint16(newB[i:]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
