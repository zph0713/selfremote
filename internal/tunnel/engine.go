package tunnel

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
)

// recvWindow is a 64-packet sliding replay window over explicit nonces.
// A nonce is acceptable if it is new (greater than everything seen) or falls
// inside the window and was not seen before.
type recvWindow struct {
	init    bool
	highest uint64
	bitmap  uint64 // bit i: nonce (highest - i) was received
}

func (w *recvWindow) acceptable(n uint64) bool {
	if !w.init {
		return true
	}
	if n > w.highest {
		return true
	}
	age := w.highest - n
	if age >= 64 {
		return false
	}
	return w.bitmap&(uint64(1)<<age) == 0
}

func (w *recvWindow) commit(n uint64) {
	if !w.init {
		w.init = true
		w.highest = n
		w.bitmap = 1
		return
	}
	if n > w.highest {
		shift := n - w.highest
		if shift >= 64 {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.highest = n
		return
	}
	w.bitmap |= uint64(1) << (w.highest - n)
}

// session is one established Noise transport session with a peer.
type session struct {
	send, recv  *noise.CipherState
	established time.Time

	sendNonce  uint64 // next nonce to use when sending
	recvCount  uint64 // accepted packets (rekey threshold & stats)
	recvWindow recvWindow
}

// peerState tracks everything the engine knows about one remote peer.
type peerState struct {
	cfg PeerConfig

	addr *net.UDPAddr // gateway: learned from traffic; client: the server address

	cur, prev    *session
	prevDeadline time.Time

	// Client only: pending handshake.
	hs          *noise.HandshakeState
	hsSent      time.Time
	attempt     int
	nextAttempt time.Time

	lastRecv time.Time
	lastSend time.Time

	// Server mode: role, relay addressing and reporting.
	role       PeerRole
	tunnelIP   netip.Addr
	routes     []RouteMap // agents: real↔virtual prefixes
	info       *AgentInfo // agents: latest announce frame
	announceAt time.Time  // server: when the last announce arrived
	mismatch   bool       // server: announce disagrees with the registry
	cmdAt      time.Time  // agents: when the last CMD was sent
	dropAt     time.Time  // relay: last rate-limited drop log

	// MFA state. Gateway: whether this peer passed the in-tunnel auth check.
	// Client: whether the session is ready for use.
	authed          bool
	authAttempts    int
	lastAuthStep    int64     // last accepted TOTP time step (anti-replay)
	challengeAt     time.Time // gateway: last challenge (re)sent
	authDeadline    time.Time // gateway: give up after this instant
	authLockedUntil time.Time // gateway: temporary block after 3 failures
	authPrompting   bool      // client: a prompt is in flight
	authSentAt      time.Time // client: last AUTH_RESP sent

	// Stats.
	bytesIn  uint64
	bytesOut uint64

	// static marks peers from the static config (never touched by the
	// registry reloader).
	static bool
}

func (p *peerState) requiresMFA() bool { return p.cfg.TOTPSecret != "" }

// Status is a snapshot of an Engine's state (used by tests and reporting).
type Status struct {
	Up          bool
	Handshakes  uint64
	ActivePeers int
}

// Engine is a tunnel endpoint: a gateway (NAS) or a client (Mac).
//
// Locking: e.mu guards peers, sessions, the connection and the counters.
// Decryption/encryption of sessions happens under e.mu; tun and socket I/O
// happen outside it.
type Engine struct {
	opts Options
	logf func(string, ...any)

	priv []byte
	pub  []byte
	dev  Device

	mu         sync.Mutex
	conn       *net.UDPConn
	serverAddr *net.UDPAddr
	peers      map[string]*peerState // keyed by hex(static public key)
	addr2peer  map[string]*peerState // gateway: source address -> peer
	handshakes uint64
	redialing  bool

	// Registry state (clients.json / agents.json).
	regMod     time.Time
	regInit    bool
	regMissing bool

	aregMod     time.Time
	aregInit    bool
	aregMissing bool

	// Server mode: routing table (virtual prefix -> agent) and relay counters.
	routes      []routeEntry
	clientsByIP map[netip.Addr]*peerState
	agentsByIP  map[netip.Addr]*peerState
	localAddr   netip.Addr // our own address on the tunnel network
	conflicts   []string
	relay       relayCounters

	// Agent mode: address translation, forwarding gate and announce timer.
	translator    *Translator
	forwarding    atomic.Bool
	announceAt    time.Time
	agentStarted  time.Time
	agentDrops    atomic.Uint64
	agentDropLog  time.Time
	lastAgentInfo *AgentInfo // our own last announce (for status)

	// Client: ready callback fired once per run.
	clientReady bool

	// Fatal client error (auth aborted) and the run's cancel func.
	fatal     error
	cancelRun context.CancelFunc
}

// New validates options, creates the TUN device and (for gateways) binds the
// UDP socket. It does not start any goroutines.
func New(opts Options) (*Engine, error) {
	if len(opts.PrivateKey) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(opts.PrivateKey))
	}
	opts.applyDefaults()

	e := &Engine{
		opts:      opts,
		logf:      opts.Logf,
		peers:     make(map[string]*peerState),
		addr2peer: make(map[string]*peerState),
	}
	if e.logf == nil {
		e.logf = log.Printf
	}
	e.priv = append([]byte(nil), opts.PrivateKey...)
	pub := opts.PublicKey
	if len(pub) == 0 {
		var err error
		pub, err = publicFromPrivate(e.priv)
		if err != nil {
			return nil, err
		}
	}
	e.pub = append([]byte(nil), pub...)

	switch opts.Mode {
	case ModeGateway, ModeServer:
		if opts.Listen == "" {
			return nil, errors.New("gateway/server: listen address required")
		}
		if len(opts.Peers) == 0 && opts.ClientsFile == "" && opts.AgentsFile == "" {
			return nil, errors.New("gateway/server: at least one peer or a registry file required")
		}
		for _, pc := range opts.Peers {
			if len(pc.PublicKey) != 32 {
				return nil, fmt.Errorf("peer %q: public key must be 32 bytes", pc.Name)
			}
			e.addPeerLocked(pc, true)
		}
	case ModeClient:
		if opts.Server == "" {
			return nil, errors.New("client: server address required")
		}
		if len(opts.ServerPublic) != 32 {
			return nil, errors.New("client: server public key must be 32 bytes")
		}
		e.peers[hex.EncodeToString(opts.ServerPublic)] = &peerState{
			cfg: PeerConfig{Name: "gateway", PublicKey: opts.ServerPublic},
		}
	case ModeAgent:
		if opts.Server == "" {
			return nil, errors.New("agent: server address required")
		}
		if len(opts.ServerPublic) != 32 {
			return nil, errors.New("agent: server public key must be 32 bytes")
		}
		name := "server"
		if opts.AgentID != "" {
			name = "server (agent " + opts.AgentID + ")"
		}
		e.peers[hex.EncodeToString(opts.ServerPublic)] = &peerState{
			cfg: PeerConfig{Name: name, PublicKey: opts.ServerPublic},
		}
		tr, err := NewTranslator(opts.RouteMaps, tunnelAddr(opts.TunnelCIDR))
		if err != nil {
			return nil, fmt.Errorf("agent: routes: %w", err)
		}
		e.translator = tr
		e.forwarding.Store(true)
	default:
		return nil, fmt.Errorf("unknown mode %d", opts.Mode)
	}

	if opts.Mode != ModeServer {
		if opts.Device != nil {
			e.dev = opts.Device
		} else {
			dev, err := CreateTUN(opts.MTU)
			if err != nil {
				return nil, err
			}
			e.dev = dev
		}
	}

	if opts.Mode.responder() {
		laddr, err := net.ResolveUDPAddr("udp", opts.Listen)
		if err != nil {
			return nil, fmt.Errorf("listen address %q: %w", opts.Listen, err)
		}
		conn, err := net.ListenUDP("udp", laddr)
		if err != nil {
			return nil, err
		}
		e.conn = conn
	}
	if opts.Mode == ModeAgent {
		e.agentStarted = time.Now()
	}
	e.localAddr = tunnelAddr(opts.TunnelCIDR)
	return e, nil
}

// tunnelAddr extracts the address part of a tunnel CIDR ("10.77.0.1/24" ->
// 10.77.0.1). An unparsable value yields the zero address.
func tunnelAddr(cidr string) netip.Addr {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Addr{}
	}
	return p.Addr()
}

// PublicKey returns our static public key.
func (e *Engine) PublicKey() []byte {
	return append([]byte(nil), e.pub...)
}

// LocalAddr returns the local UDP address (gateway: listen address;
// client: the socket's local address once connected).
func (e *Engine) LocalAddr() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn == nil {
		return ""
	}
	return e.conn.LocalAddr().String()
}

// TunnelCIDR returns our address on the tunnel network (as configured).
func (e *Engine) TunnelCIDR() string { return e.opts.TunnelCIDR }

// Mode returns the engine's role.
func (e *Engine) Mode() Mode { return e.opts.Mode }

// Status returns a snapshot of the engine state.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{Handshakes: e.handshakes}
	for _, p := range e.peers {
		if p.cur != nil {
			st.ActivePeers++
		}
	}
	st.Up = st.ActivePeers > 0
	return st
}

// Run starts the engine and blocks until ctx is cancelled (returns nil) or a
// fatal setup error occurs.
func (e *Engine) Run(ctx context.Context) error {
	if e.opts.Mode.dials() {
		if err := e.dialWithRetry(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
	}
	if !e.opts.SkipNetConfig && e.opts.Mode != ModeServer {
		if err := configureInterface(e.dev, e.opts.TunnelCIDR, e.opts.Routes); err != nil {
			return fmt.Errorf("configure interface: %w", err)
		}
		defer teardownInterface(e.dev, e.opts.TunnelCIDR, e.opts.Routes)
	}
	if e.opts.Mode == ModeServer {
		// Pick up registry peers before the first packet arrives.
		e.reloadRegistry()
		e.mu.Lock()
		e.rebuildTablesLocked() // covers static peers too (tests, single-site setups)
		routes := len(e.routes)
		e.mu.Unlock()
		e.logf("server: running (tunnel %s, %d route(s), relays in user space, no TUN)",
			e.opts.TunnelCIDR, routes)
	} else {
		e.logf("%s: running (tunnel %s, mtu %d)", e.opts.Mode, e.opts.TunnelCIDR, e.opts.MTU)
	}

	runCtx, cancel := context.WithCancel(ctx)
	e.mu.Lock()
	e.cancelRun = cancel
	e.mu.Unlock()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.readLoop(runCtx)
	}()
	if e.dev != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.writeLoop(runCtx)
		}()
	}
	e.timerLoop(runCtx)
	e.sendBye()
	cancel()

	e.mu.Lock()
	conn := e.conn
	e.conn = nil
	e.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	if e.dev != nil {
		e.dev.Close()
	}
	wg.Wait()
	e.mu.Lock()
	fatal := e.fatal
	e.mu.Unlock()
	if fatal != nil {
		return fatal
	}
	return nil
}

// ---------------------------------------------------------------- I/O loops

func (e *Engine) readLoop(ctx context.Context) {
	buf := make([]byte, maxDatagram)
	for {
		if ctx.Err() != nil {
			return
		}
		e.mu.Lock()
		conn := e.conn
		e.mu.Unlock()
		if conn == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}

		var n int
		var addr *net.UDPAddr
		var err error
		if e.opts.Mode.dials() {
			n, err = conn.Read(buf)
		} else {
			n, addr, err = conn.ReadFromUDP(buf)
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isClosedErr(err) {
				e.mu.Lock()
				cur := e.conn
				e.mu.Unlock()
				if cur == conn {
					return // socket closed for good
				}
				continue // socket was swapped (re-dial); retry with the new one
			}
			e.logf("udp read: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		if n >= frameHeaderLen {
			e.handlePacket(addr, buf[:n])
		}
	}
}

func (e *Engine) writeLoop(ctx context.Context) {
	buf := make([]byte, maxDatagram)
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := e.dev.Read(buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isClosedErr(err) {
				return
			}
			e.logf("tun read: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		if n > 0 {
			e.sendFromTun(buf[:n])
		}
	}
}

func (e *Engine) timerLoop(ctx context.Context) {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	e.tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.tick()
		}
	}
}

// tick drives handshakes, keepalives, dead-peer detection and rekeying.
func (e *Engine) tick() {
	now := time.Now()
	e.reloadRegistry()
	type pending struct {
		p     *peerState
		frame []byte
	}
	var sends []pending
	var onReady bool
	var repromptPeer *peerState

	e.mu.Lock()
	for _, p := range e.peers {
		// Expire superseded sessions.
		if p.prev != nil && now.After(p.prevDeadline) {
			p.prev = nil
		}

		// Dead peer: no valid traffic within DeadTimeout.
		if p.cur != nil && now.Sub(p.lastRecv) > e.opts.DeadTimeout {
			e.logf("peer %s: no traffic for %v, dropping session", p.cfg.Name, now.Sub(p.lastRecv).Round(time.Second))
			p.cur, p.prev = nil, nil
			p.authed = false
			p.authSentAt = time.Time{}
			p.nextAttempt = now
			if e.opts.Mode.dials() {
				e.redialAsyncLocked()
			}
		}

		// Gateway/server: MFA session management — (re)send the challenge and
		// give up if no valid code arrives in time.
		if e.opts.Mode.responder() && p.requiresMFA() && p.cur != nil && !p.authed {
			switch {
			case !now.Before(p.authDeadline):
				e.logf("peer %s: MFA timeout, dropping session", p.cfg.Name)
				p.cur, p.prev = nil, nil
			case now.Sub(p.challengeAt) > 5*time.Second:
				if frame, err := sealDataFrame(p.cur.send, frameAuthChallenge, p.cur.sendNonce, authChallengePayload(true)); err == nil {
					p.cur.sendNonce++
					p.lastSend = now
					p.challengeAt = now
					sends = append(sends, pending{p, frame})
				}
			}
		}

		// Client/agent: if the remote end never asks for a code (older build),
		// proceed after a short grace period.
		if e.opts.Mode.dials() && p.cur != nil && !p.authed && !p.authPrompting &&
			p.authSentAt.IsZero() && now.Sub(p.cur.established) > authGrace {
			p.authed = true
			if !e.clientReady {
				e.clientReady = true
				onReady = true
			}
		}

		// Client/agent: a submitted code (or its result) can be lost on the
		// wire; ask for a fresh one instead of hanging forever.
		if e.opts.Mode.dials() && p.cur != nil && !p.authed && !p.authPrompting &&
			!p.authSentAt.IsZero() && now.Sub(p.authSentAt) > 8*time.Second {
			p.authSentAt = time.Time{}
			repromptPeer = p
		}

		if e.opts.Mode == ModeAgent {
			// Announce ourselves (identity, prefixes, liveness) right after
			// authentication and then on a fixed interval.
			if p.cur != nil && p.authed && now.Sub(e.announceAt) > announceInterval {
				e.announceAt = now
				if frame, err := sealDataFrame(p.cur.send, frameAgentInfo, p.cur.sendNonce, e.agentInfoJSONLocked()); err == nil {
					p.cur.sendNonce++
					p.lastSend = now
					sends = append(sends, pending{p, frame})
				}
			}
		}

		if e.opts.Mode.dials() {
			// Retry timeout for a pending handshake.
			if p.hs != nil && now.Sub(p.hsSent) > e.opts.HandshakeRetry {
				p.hs = nil
				p.attempt++
				p.nextAttempt = now.Add(e.retryDelay(p.attempt))
			}
			rekey := p.cur != nil && (now.Sub(p.cur.established) > e.opts.RekeyInterval ||
				p.cur.sendNonce+p.cur.recvCount >= e.opts.RekeyPackets)
			if p.hs == nil && !now.Before(p.nextAttempt) && (p.cur == nil || rekey) {
				if frame := e.startClientHandshakeLocked(p, now); frame != nil {
					sends = append(sends, pending{p, frame})
				} else {
					p.attempt++
					p.nextAttempt = now.Add(e.retryDelay(p.attempt))
				}
			}
		}

		// Server: keep telling a disabled agent to stand down (idempotent —
		// also covers agents that reconnect while disabled).
		if e.opts.Mode == ModeServer && p.cfg.Role == RoleAgent && p.cur != nil && p.authed && !p.cfg.Enabled &&
			now.Sub(p.cmdAt) > 30*time.Second {
			p.cmdAt = now
			if frame, err := sealDataFrame(p.cur.send, frameAgentCmd, p.cur.sendNonce,
				mustJSON(agentCmdMsg{Cmd: "disable", Reason: "管理员已在网页端停用该节点"})); err == nil {
				p.cur.sendNonce++
				p.lastSend = now
				sends = append(sends, pending{p, frame})
			}
		}

		// Keepalives keep both directions' dead-detection honest.
		if p.cur != nil && p.hs == nil && now.Sub(p.lastSend) > e.opts.KeepaliveInterval {
			if frame, err := sealDataFrame(p.cur.send, frameKeepalive, p.cur.sendNonce, nil); err == nil {
				p.cur.sendNonce++
				p.lastSend = now
				sends = append(sends, pending{p, frame})
			}
		}
	}
	e.mu.Unlock()

	if onReady && e.opts.OnReady != nil {
		e.opts.OnReady()
	}
	if repromptPeer != nil {
		e.handleAuthChallenge(repromptPeer, authChallengePayload(true))
	}

	for _, s := range sends {
		e.writeWire(s.p, s.frame)
	}
}

// ------------------------------------------------------------- packet handling

func (e *Engine) handlePacket(addr *net.UDPAddr, frame []byte) {
	typ, payload, err := parseFrame(frame)
	if err != nil {
		return
	}
	switch typ {
	case frameHandshakeInit:
		if e.opts.Mode.responder() {
			e.handleHandshakeInit(addr, payload)
		}
	case frameHandshakeResp:
		if e.opts.Mode.dials() {
			e.handleHandshakeResp(payload)
		}
	case frameData, frameKeepalive, frameAuthChallenge, frameAuthResp, frameAuthResult, frameInfo, frameBye,
		frameAgentInfo, frameAgentCmd:
		nonce, err := dataNonce(payload)
		if err != nil {
			return
		}
		e.handleData(addr, frame, nonce)
	case frameCtrl:
		// Reserved for future extensions (relay, endpoint updates).
	}
}

func (e *Engine) handleHandshakeInit(addr *net.UDPAddr, payload []byte) {
	hs, err := newResponder(e.priv, e.pub)
	if err != nil {
		e.logf("handshake responder: %v", err)
		return
	}
	if _, _, _, err := hs.ReadMessage(nil, payload); err != nil {
		e.logf("%s: rejecting handshake from %s: %v", e.opts.Mode, addr, err)
		return
	}
	p := e.peerByPub(hs.PeerStatic())
	if p == nil {
		e.logf("%s: unauthorized peer %s from %s (不在任何注册表里)", e.opts.Mode, shortKey(hs.PeerStatic()), addr)
		return
	}

	// Locked-out peers (too many bad MFA codes) are ignored for a while.
	e.mu.Lock()
	locked := p.requiresMFA() && time.Now().Before(p.authLockedUntil)
	e.mu.Unlock()
	if locked {
		e.logf("%s: peer %s temporarily locked (MFA failures)", e.opts.Mode, p.cfg.Name)
		return
	}
	msg2, cs1, cs2, err := hs.WriteMessage(frameHeader(frameHandshakeResp), nil)
	if err != nil {
		e.logf("%s: handshake write: %v", e.opts.Mode, err)
		return
	}

	e.mu.Lock()
	p.addr = addr
	e.addr2peer[addr.String()] = p
	e.mu.Unlock()

	// Responder side: (cs1, cs2) = (recv, send) per the Noise spec ordering.
	e.installSession(p, cs2, cs1)
	e.writeWire(p, msg2)
	e.logf("%s: session established with %s [%s] (%s)", e.opts.Mode, p.cfg.Name, p.cfg.Role, addr)

	// MFA gating + server info (v0.2 frames; older clients ignore them).
	e.mu.Lock()
	required := p.requiresMFA() && !p.authed
	if required {
		p.authAttempts = 0
		p.authDeadline = time.Now().Add(mfaAuthWindow)
		p.challengeAt = time.Now()
	}
	e.mu.Unlock()
	e.sendSealed(p, frameAuthChallenge, authChallengePayload(required))
	e.sendSealed(p, frameInfo, e.serverInfoJSON(p))
}

func (e *Engine) handleHandshakeResp(payload []byte) {
	p := e.clientPeer()
	if p == nil {
		return
	}
	e.mu.Lock()
	hs := p.hs
	e.mu.Unlock()
	if hs == nil {
		return // unsolicited or already handled
	}

	_, cs1, cs2, err := hs.ReadMessage(nil, payload)
	if err != nil {
		e.logf("handshake response rejected: %v", err)
		e.mu.Lock()
		if p.hs == hs {
			p.hs = nil
			p.attempt++
			p.nextAttempt = time.Now().Add(e.retryDelay(p.attempt))
		}
		e.mu.Unlock()
		return
	}
	// Initiator side: (cs1, cs2) = (send, recv) per the Noise spec ordering.
	e.installSession(p, cs1, cs2)
	e.logf("%s: session established (%s)", e.opts.Mode, p.cfg.Name)
	e.mu.Lock()
	// A new session starts out unauthenticated on the wire; the gateway
	// decides (challenge frame) whether a fresh code is required.
	p.authed = false
	p.authSentAt = time.Time{}
	e.mu.Unlock()
}

func (e *Engine) handleData(addr *net.UDPAddr, frame []byte, nonce uint64) {
	ad := frame[:dataHeaderLen]
	ct := frame[dataHeaderLen:]
	now := time.Now()

	var pt []byte
	var p *peerState

	e.mu.Lock()
	if addr != nil {
		p = e.addr2peer[addr.String()]
	}
	if p == nil && e.opts.Mode.dials() {
		p = e.anyPeerLocked()
	}

	// trySession attempts to open one data frame with one session, honouring
	// the replay window. Failed transactions leave the cipher state untouched
	// (decrypt failure does not advance the nonce).
	trySession := func(s *session) ([]byte, bool) {
		if s == nil || !s.recvWindow.acceptable(nonce) {
			return nil, false
		}
		s.recv.SetNonce(nonce)
		b, err := s.recv.Decrypt(nil, ad, ct)
		if err != nil {
			return nil, false
		}
		s.recvWindow.commit(nonce)
		s.recvCount++
		return b, true
	}
	tryPeer := func(cand *peerState) (*session, []byte, bool) {
		if cand == nil {
			return nil, nil, false
		}
		if b, ok := trySession(cand.cur); ok {
			return cand.cur, b, true
		}
		if cand.prev != nil && now.Before(cand.prevDeadline) {
			if b, ok := trySession(cand.prev); ok {
				return cand.prev, b, true
			}
		}
		return nil, nil, false
	}

	_, pt, ok := tryPeer(p)
	if !ok && e.opts.Mode.responder() {
		// Unknown source address, or a client whose address changed:
		// try every configured peer.
		for _, cand := range e.peers {
			if cand == p {
				continue
			}
			if _, b, ok2 := tryPeer(cand); ok2 {
				p, pt, ok = cand, b, true
				break
			}
		}
	}
	if !ok {
		e.mu.Unlock()
		return // undecryptable: drop
	}
	p.lastRecv = now
	p.bytesIn += uint64(len(frame))
	if addr != nil {
		if p.addr == nil || p.addr.String() != addr.String() {
			e.logf("peer %s: endpoint updated to %s", p.cfg.Name, addr)
			p.addr = addr
		}
		e.addr2peer[addr.String()] = p
	}
	gate := e.opts.Mode.responder() && p.requiresMFA() && !p.authed
	e.mu.Unlock()

	switch frame[1] {
	case frameKeepalive:
		// liveness only
	case frameBye:
		if e.opts.Mode.responder() {
			e.logf("peer %s: disconnected (bye)", p.cfg.Name)
			e.mu.Lock()
			p.cur, p.prev = nil, nil
			p.authed = false
			e.mu.Unlock()
		}
	case frameAuthResp:
		if e.opts.Mode.responder() {
			e.handleAuthResp(p, pt)
		}
	case frameAuthChallenge:
		if e.opts.Mode.dials() {
			e.handleAuthChallenge(p, pt)
		}
	case frameAuthResult:
		if e.opts.Mode.dials() {
			e.handleAuthResult(p, pt)
		}
	case frameInfo:
		if e.opts.Mode.dials() {
			e.handleInfo(p, pt)
		}
	case frameAgentInfo:
		if e.opts.Mode == ModeServer {
			e.handleAgentInfo(p, pt)
		}
	case frameAgentCmd:
		if e.opts.Mode == ModeAgent {
			e.handleAgentCmd(p, pt)
		}
	default: // frameData
		if gate {
			break // unauthenticated MFA peer: drop data until the code passes
		}
		e.deliverData(p, pt)
	}
}

// deliverData routes one decrypted DATA payload: user-space relay on a
// server, TUN device elsewhere (agents translate addresses first).
func (e *Engine) deliverData(p *peerState, pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	switch e.opts.Mode {
	case ModeServer:
		e.relayFromPeer(p, pkt)
	case ModeAgent:
		out, ok := e.translator.ToLocal(pkt)
		if !ok {
			e.dropAt("地址翻译（隧道→内网）", pkt)
			return
		}
		if _, err := e.dev.Write(out, 0); err != nil {
			e.logf("tun write: %v", err)
		}
	default:
		if _, err := e.dev.Write(pkt, 0); err != nil {
			e.logf("tun write: %v", err)
		}
	}
}

// sendFromTun is the TUN -> wire path: agents translate the source address
// back into the virtual prefix and honour the forwarding gate.
func (e *Engine) sendFromTun(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	if e.opts.Mode == ModeAgent {
		if !e.forwarding.Load() {
			return
		}
		out, ok := e.translator.ToTunnel(pkt)
		if !ok {
			e.dropAt("地址翻译（内网→隧道）", pkt)
			return
		}
		pkt = out
	}
	e.sendData(pkt)
}

// ---------------------------------------------------------------- send paths

// sendData encrypts one IP packet and sends it to every peer with a session.
func (e *Engine) sendData(pkt []byte) {
	now := time.Now()
	type out struct {
		p     *peerState
		frame []byte
	}
	var outs []out

	e.mu.Lock()
	for _, p := range e.peers {
		if p.cur == nil || !p.authed {
			continue
		}
		frame, err := sealDataFrame(p.cur.send, frameData, p.cur.sendNonce, pkt)
		if err != nil {
			e.logf("seal: %v", err)
			continue
		}
		p.cur.sendNonce++
		p.lastSend = now
		outs = append(outs, out{p, frame})
	}
	e.mu.Unlock()

	for _, o := range outs {
		e.writeWire(o.p, o.frame)
	}
}

// sendTo encrypts one IP packet for a single peer; used by the server relay.
func (e *Engine) sendTo(p *peerState, pkt []byte) bool {
	e.mu.Lock()
	if p.cur == nil || !p.authed {
		e.mu.Unlock()
		return false
	}
	frame, err := sealDataFrame(p.cur.send, frameData, p.cur.sendNonce, pkt)
	if err == nil {
		p.cur.sendNonce++
		p.lastSend = time.Now()
	}
	e.mu.Unlock()
	if err != nil {
		e.logf("seal: %v", err)
		return false
	}
	e.writeWire(p, frame)
	return true
}

// writeWire sends an already sealed frame to the peer.
func (e *Engine) writeWire(p *peerState, frame []byte) {
	e.mu.Lock()
	conn := e.conn
	addr := p.addr
	p.bytesOut += uint64(len(frame))
	e.mu.Unlock()
	if conn == nil || len(frame) == 0 {
		return
	}
	var err error
	if e.opts.Mode.dials() {
		_, err = conn.Write(frame)
	} else {
		if addr == nil {
			return
		}
		_, err = conn.WriteToUDP(frame, addr)
	}
	if err != nil {
		e.logf("send to %s: %v", p.cfg.Name, err)
	}
}

// --------------------------------------------------------------- handshakes

// startClientHandshakeLocked creates the client handshake, stores it on the
// peer and returns the framed msg1 to send. Caller holds e.mu.
func (e *Engine) startClientHandshakeLocked(p *peerState, now time.Time) []byte {
	hs, err := newInitiator(e.priv, e.pub, p.cfg.PublicKey)
	if err != nil {
		e.logf("handshake init: %v", err)
		return nil
	}
	msg, _, _, err := hs.WriteMessage(frameHeader(frameHandshakeInit), nil)
	if err != nil {
		e.logf("handshake write: %v", err)
		return nil
	}
	p.hs = hs
	p.hsSent = now
	p.lastSend = now
	return msg
}

// installSession makes (send, recv) the peer's current session, keeping the
// previous one around for a grace period so in-flight packets still decrypt.
func (e *Engine) installSession(p *peerState, send, recv *noise.CipherState) {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.cur != nil {
		p.prev = p.cur
		p.prevDeadline = now.Add(e.opts.SessionGrace)
	}
	p.cur = &session{send: send, recv: recv, established: now}
	p.hs = nil
	p.attempt = 0
	p.nextAttempt = time.Time{}
	p.lastRecv = now
	p.lastSend = now
	e.handshakes++
}

// ------------------------------------------------------------------ helpers

func (e *Engine) retryDelay(attempt int) time.Duration {
	if attempt < e.opts.HandshakeAttempts {
		return e.opts.HandshakeRetry
	}
	return e.opts.HandshakeBackoff
}

func (e *Engine) peerByPub(pub []byte) *peerState {
	if len(pub) != 32 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.peers[hex.EncodeToString(pub)]
}

// clientPeer returns the client's single peer.
func (e *Engine) clientPeer() *peerState {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.anyPeerLocked()
}

// anyPeerLocked returns the first peer; caller holds e.mu.
func (e *Engine) anyPeerLocked() *peerState {
	for _, p := range e.peers {
		return p
	}
	return nil
}

func (e *Engine) dial() (*net.UDPConn, *net.UDPAddr, error) {
	raddr, err := net.ResolveUDPAddr("udp", e.opts.Server)
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, nil, err
	}
	return conn, raddr, nil
}

func (e *Engine) dialWithRetry(ctx context.Context) error {
	for {
		conn, raddr, err := e.dial()
		if err == nil {
			e.mu.Lock()
			old := e.conn
			e.conn = conn
			e.serverAddr = raddr
			e.mu.Unlock()
			if old != nil {
				old.Close()
			}
			e.logf("client: connected to %s", raddr)
			return nil
		}
		e.logf("client: resolve/dial %s: %v", e.opts.Server, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// redialAsyncLocked schedules a DNS re-resolution and re-dial in the
// background. Caller holds e.mu.
func (e *Engine) redialAsyncLocked() {
	if e.redialing {
		return
	}
	e.redialing = true
	go func() {
		defer func() {
			e.mu.Lock()
			e.redialing = false
			e.mu.Unlock()
		}()
		conn, raddr, err := e.dial()
		if err != nil {
			e.logf("client: redial %s: %v", e.opts.Server, err)
			return
		}
		e.mu.Lock()
		old := e.conn
		e.conn = conn
		e.serverAddr = raddr
		e.mu.Unlock()
		if old != nil {
			old.Close()
		}
		e.logf("client: endpoint re-resolved (%s)", raddr)
	}()
}

func isClosedErr(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed)
}

func shortKey(k []byte) string {
	if len(k) > 8 {
		k = k[:8]
	}
	return hex.EncodeToString(k)
}

func modeName(m Mode) string {
	if m == ModeGateway {
		return "gateway"
	}
	return "client"
}
