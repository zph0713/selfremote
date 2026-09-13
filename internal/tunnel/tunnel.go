// Package tunnel implements the selfremote tunnel: a self-hosted, Noise-based
// L3 tunnel that lets a remote client reach its home LAN through a gateway.
//
// The engine is deliberately decoupled from the outside world at both edges:
// a Device for IP packets on one side, a UDP socket on the other. Tests
// substitute fake devices and exercise real sockets over loopback.
package tunnel

import (
	"net/netip"
	"time"
)

// Wire format.
const (
	frameVersion = 0x01

	frameHandshakeInit = 0x01
	frameHandshakeResp = 0x02
	frameData          = 0x03
	frameKeepalive     = 0x04
	frameCtrl          = 0x05 // reserved: relay / endpoint updates

	// Sealed control frames (inside an established session).
	frameAuthChallenge = 0x06 // gateway -> client: {"required":bool}
	frameAuthResp      = 0x07 // client -> gateway: {"code":"123456"}
	frameAuthResult    = 0x08 // gateway -> client: {"ok":bool,"msg":"…"}
	frameInfo          = 0x09 // gateway -> client: ServerInfo JSON
	frameBye           = 0x0A // client -> gateway: clean disconnect
	frameAgentInfo     = 0x0B // agent -> server: AgentInfo JSON (announce + heartbeat)
	frameAgentCmd      = 0x0C // server -> agent: {"cmd":"disable|enable|kick|stat"}

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

	// announceInterval is how often an agent republishes its info to the
	// server (hostname, uptime, prefixes) — its heartbeat.
	announceInterval = 30 * time.Second
)

// Mode selects the role of an Engine.
type Mode int

const (
	// ModeGateway runs at home (NAS) and accepts clients directly. This is
	// the v0.2 standalone mode (no central server); it stays supported.
	ModeGateway Mode = iota
	// ModeClient runs on the Mac and connects out to a server or gateway.
	ModeClient
	// ModeAgent runs at a site edge: it dials the server, publishes its LAN
	// prefixes and translates addresses at the tunnel boundary.
	ModeAgent
	// ModeServer is the hub: it accepts clients and agents on one socket and
	// relays packets between them in user space (no TUN device).
	ModeServer
)

// responder reports whether this mode accepts handshakes (listens).
func (m Mode) responder() bool { return m == ModeGateway || m == ModeServer }

// dials reports whether this mode connects out to a remote endpoint.
func (m Mode) dials() bool { return m == ModeClient || m == ModeAgent }

func (m Mode) String() string {
	switch m {
	case ModeGateway:
		return "gateway"
	case ModeClient:
		return "client"
	case ModeAgent:
		return "agent"
	case ModeServer:
		return "server"
	}
	return "unknown"
}

// PeerConfig describes a peer as we know it from configuration or registry.
type PeerConfig struct {
	Name      string
	User      string // owning user (web-managed registry); optional
	PublicKey []byte // X25519 static public key, 32 bytes

	// TOTPSecret, when set, makes this peer require an in-tunnel MFA code
	// (Google Authenticator style) before any data is forwarded.
	TOTPSecret string

	// ID is the stable identifier used for ACLs and control operations
	// (agent id). Defaults to Name for legacy entries.
	ID string
	// Role is what this peer is from our point of view. Server mode sees both
	// roles; other modes only ever have the zero value (client semantics).
	Role PeerRole
	// TunnelIP is the peer's address on the tunnel network (10.77.0.0/24).
	// The server uses it to route return traffic to a client; for an agent it
	// is its own tunnel address (reachable for diagnostics).
	TunnelIP netip.Addr
	// Routes (agents) maps the real LAN prefixes this agent serves onto the
	// prefixes presented inside the tunnel.
	Routes []RouteMap
	// AllowAgents (clients) is the ACL: agent ids this client may reach.
	// Empty means "no site" — access is denied unless granted.
	AllowAgents []string
	// Enabled is the operator switch for agents (registry `enabled`).
	Enabled bool
}

func (pc PeerConfig) id() string {
	if pc.ID != "" {
		return pc.ID
	}
	return pc.Name
}

// ServerInfo is reported by the gateway/server to clients (info frame) and
// shown in connection status displays.
type ServerInfo struct {
	Hostname   string   `json:"hostname"`
	Listen     string   `json:"listen"`
	TunnelCIDR string   `json:"tunnel_cidr"`
	MFA        bool     `json:"mfa"`
	Role       string   `json:"role,omitempty"`  // "gateway" | "server"
	Sites      []string `json:"sites,omitempty"` // server: published site prefixes
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

	// ClientsFile, when set (gateway/server), is a hot-reloaded JSON registry
	// of authorized clients (written by the web control plane). Peers from this
	// file carry per-device MFA secrets; static Peers may then be empty.
	ClientsFile string

	// AgentsFile, when set (server), is a hot-reloaded JSON registry of site
	// agents (agents.json, written by the web control plane).
	AgentsFile string

	// Client only.
	Server       string // "host:port" of the gateway/server
	ServerPublic []byte // remote static public key (32 bytes)

	// Agent mode: identity published to the server, the LAN prefixes this
	// agent serves (real↔virtual) and the TOTP secret used to answer the
	// server's MFA challenge without a human.
	AgentID   string
	RouteMaps []RouteMap
	MFASecret string
	Version   string // reported to the server in announce frames

	// Client only: called when the gateway requires an MFA code. attempt is
	// 1-based. Returning ok=false aborts the connection.
	AuthPrompt func(attempt int) (code string, ok bool)

	// Client only: called once the session is ready for use (auth decided).
	OnReady func()

	// Client only: called when the gateway reports its server info.
	OnInfo func(ServerInfo)

	// Common.
	TunnelCIDR string   // our address on the tunnel, e.g. "10.77.0.1/24" (gateway) or "10.77.0.2/24" (client)
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
