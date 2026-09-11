// Package tunnel implements the selfremote tunnel: a self-hosted, Noise-based
// L3 tunnel that lets a remote client reach its home LAN through a gateway.
//
// The engine is deliberately decoupled from the outside world at both edges:
// a Device for IP packets on one side, a UDP socket on the other. Tests
// substitute fake devices and exercise real sockets over loopback.
package tunnel

import "time"

// Wire format.
const (
	frameVersion = 0x01

	frameHandshakeInit = 0x01
	frameHandshakeResp = 0x02
	frameData          = 0x03
	frameKeepalive     = 0x04
	frameCtrl          = 0x05 // reserved: relay / endpoint updates

	frameHeaderLen = 2  // handshake frames: version + type
	dataHeaderLen  = 10 // data frames: version + type + 8-byte nonce
	dataNonceLen   = 8
	aeadTagLen     = 16

	// prologue binds the Noise handshake to this protocol and version.
	prologue = "selfremote/1"

	// DefaultMTU keeps a datagram under 1500 bytes:
	// 40 (IPv6) + 8 (UDP) + 2 (frame) + 16 (AEAD tag) = 66 bytes overhead.
	DefaultMTU = 1360

	// DefaultPort is the default UDP port of the gateway.
	DefaultPort = 28333

	// maxDatagram is the largest packet buffer we handle: big enough for any
	// UDP datagram and for GSO-segmented reads from the Linux tun device.
	maxDatagram = 65535

	// tickInterval is the engine's timer granularity.
	tickInterval = 250 * time.Millisecond
)

// Mode selects the role of an Engine.
type Mode int

const (
	// ModeGateway runs at home (NAS) and accepts clients.
	ModeGateway Mode = iota
	// ModeClient runs on the Mac and connects out to the gateway.
	ModeClient
)

// PeerConfig describes an authorized client (gateway side).
type PeerConfig struct {
	Name      string
	PublicKey []byte // X25519 static public key, 32 bytes
}

// Options configures an Engine.
type Options struct {
	Mode Mode

	// PrivateKey is our X25519 static private key (32 bytes).
	// PublicKey is derived from it when omitted.
	PrivateKey []byte
	PublicKey  []byte

	// Gateway only.
	Listen string // e.g. "[::]:28333"
	Peers  []PeerConfig

	// Client only.
	Server       string // "host:port" of the gateway
	ServerPublic []byte // gateway static public key (32 bytes)

	// Common.
	TunnelCIDR string   // our address on the tunnel, e.g. "10.77.0.1/24" (gateway) or "10.77.0.2/32" (client)
	Routes     []string // extra routes pointed at the tunnel (client: home LAN subnets)
	MTU        int

	// Tuning; defaults applied when zero.
	HandshakeRetry    time.Duration // 2s   — handshake resend / timeout interval
	HandshakeBackoff  time.Duration // 10s  — retry interval after HandshakeAttempts
	HandshakeAttempts int           // 5
	KeepaliveInterval time.Duration // 10s
	DeadTimeout       time.Duration // 25s
	RekeyInterval     time.Duration // 120s
	RekeyPackets      uint64        // 1<<20
	SessionGrace      time.Duration // 30s — how long a superseded session still decrypts

	// Test hooks.
	Device        Device // when set, used instead of creating a real TUN device
	SkipNetConfig bool   // when true, addresses/routes are not configured on the system
	Logf          func(format string, args ...any)
}

func (o *Options) applyDefaults() {
	if o.MTU <= 0 {
		o.MTU = DefaultMTU
	}
	if o.HandshakeRetry <= 0 {
		o.HandshakeRetry = 2 * time.Second
	}
	if o.HandshakeBackoff <= 0 {
		o.HandshakeBackoff = 10 * time.Second
	}
	if o.HandshakeAttempts <= 0 {
		o.HandshakeAttempts = 5
	}
	if o.KeepaliveInterval <= 0 {
		o.KeepaliveInterval = 10 * time.Second
	}
	if o.DeadTimeout <= 0 {
		o.DeadTimeout = 25 * time.Second
	}
	if o.RekeyInterval <= 0 {
		o.RekeyInterval = 120 * time.Second
	}
	if o.RekeyPackets == 0 {
		o.RekeyPackets = 1 << 20
	}
	if o.SessionGrace <= 0 {
		o.SessionGrace = 30 * time.Second
	}
}
