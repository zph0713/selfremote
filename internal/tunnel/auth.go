package tunnel

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

const (
	// mfaAuthWindow is how long a gateway waits for a valid code after a
	// session is established before dropping it.
	mfaAuthWindow = 2 * time.Minute
	// authGrace lets a new client proceed against a gateway that never sends
	// an auth challenge (older builds); MFA gateways always send one.
	authGrace = 3 * time.Second
)

type authChallengeMsg struct {
	Required bool `json:"required"`
}

func authChallengePayload(required bool) []byte {
	return mustJSON(authChallengeMsg{Required: required})
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// sendSealed seals payload as typ and sends it to p (best effort).
func (e *Engine) sendSealed(p *peerState, typ byte, payload []byte) {
	e.mu.Lock()
	if p.cur == nil {
		e.mu.Unlock()
		return
	}
	frame, err := sealDataFrame(p.cur.send, typ, p.cur.sendNonce, payload)
	if err == nil {
		p.cur.sendNonce++
		p.lastSend = time.Now()
	}
	e.mu.Unlock()
	if err == nil {
		e.writeWire(p, frame)
	}
}

// serverInfoJSON builds the info frame payload shown by clients.
func (e *Engine) serverInfoJSON(p *peerState) []byte {
	host, _ := os.Hostname()
	return mustJSON(ServerInfo{
		Hostname:   host,
		Listen:     e.LocalAddr(),
		TunnelCIDR: e.opts.TunnelCIDR,
		MFA:        p.requiresMFA(),
	})
}

// checkTOTP validates a 6-digit Google Authenticator code against secret with
// a ±1 step (30 s) drift window and returns the matched time step.
func checkTOTP(secret, code string, now time.Time) (bool, int64) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false, 0
	}
	step := now.Unix() / 30
	for _, s := range []int64{step - 1, step, step + 1} {
		want, err := totp.GenerateCode(secret, time.Unix(s*30, 0))
		if err != nil {
			return false, 0
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true, s
		}
	}
	return false, 0
}

// handleAuthResp (gateway): verify a submitted code.
func (e *Engine) handleAuthResp(p *peerState, pt []byte) {
	var m struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(pt, &m); err != nil {
		return
	}
	if !p.requiresMFA() {
		return
	}

	e.mu.Lock()
	already := p.authed
	locked := time.Now().Before(p.authLockedUntil)
	e.mu.Unlock()
	if already {
		// Duplicate submission (e.g. our result datagram was lost):
		// confirm again instead of counting a failure.
		e.sendSealed(p, frameAuthResult, mustJSON(map[string]any{"ok": true}))
		return
	}
	if locked {
		e.sendSealed(p, frameAuthResult, mustJSON(map[string]any{"ok": false, "msg": "尝试次数过多，请稍候重试"}))
		return
	}

	ok, step := checkTOTP(p.cfg.TOTPSecret, m.Code, time.Now())

	e.mu.Lock()
	pass := ok && step > p.lastAuthStep
	if pass {
		p.authed = true
		p.lastAuthStep = step
		p.authAttempts = 0
	} else {
		p.authAttempts++
		if p.authAttempts >= 3 {
			p.authLockedUntil = time.Now().Add(30 * time.Second)
		}
	}
	attempts := p.authAttempts
	e.mu.Unlock()

	if pass {
		e.logf("gateway: peer %s (%s): MFA passed", p.cfg.Name, p.cfg.User)
		e.sendSealed(p, frameAuthResult, mustJSON(map[string]any{"ok": true}))
		e.sendSealed(p, frameInfo, e.serverInfoJSON(p))
		return
	}

	e.logf("gateway: peer %s: MFA attempt %d failed", p.cfg.Name, attempts)
	e.sendSealed(p, frameAuthResult, mustJSON(map[string]any{"ok": false, "msg": "验证码错误，请重试"}))
	if attempts >= 3 {
		e.logf("gateway: peer %s: too many MFA failures, dropping session", p.cfg.Name)
		e.mu.Lock()
		p.cur, p.prev = nil, nil
		p.authed = false
		e.mu.Unlock()
	}
}

// handleAuthChallenge (client): the gateway asks for a code (or signals that
// none is needed).
func (e *Engine) handleAuthChallenge(p *peerState, pt []byte) {
	var m authChallengeMsg
	if err := json.Unmarshal(pt, &m); err != nil {
		return
	}
	if !m.Required {
		e.clientMarkReady(p)
		return
	}

	e.mu.Lock()
	if p.authPrompting {
		e.mu.Unlock()
		return // a prompt is already in flight
	}
	p.authPrompting = true
	attempt := p.authAttempts + 1
	e.mu.Unlock()

	prompt := e.opts.AuthPrompt
	if prompt == nil {
		e.fail(errors.New("网关要求 MFA 动态码，但当前客户端没有可用的输入方式"))
		return
	}
	go func() {
		code, ok := prompt(attempt)
		e.mu.Lock()
		p.authPrompting = false
		e.mu.Unlock()
		if !ok {
			e.fail(errors.New("已取消输入 MFA 动态码"))
			return
		}
		e.mu.Lock()
		p.authSentAt = time.Now()
		e.mu.Unlock()
		e.sendSealed(p, frameAuthResp, mustJSON(map[string]any{"code": strings.TrimSpace(code)}))
	}()
}

// handleAuthResult (client): outcome of a submitted code.
func (e *Engine) handleAuthResult(p *peerState, pt []byte) {
	var m struct {
		OK  bool   `json:"ok"`
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(pt, &m); err != nil {
		return
	}
	if m.OK {
		e.logf("client: MFA 验证通过")
		e.clientMarkReady(p)
		return
	}
	e.mu.Lock()
	p.authAttempts++
	attempts := p.authAttempts
	p.authSentAt = time.Time{}
	e.mu.Unlock()
	if m.Msg != "" {
		e.logf("client: %s", m.Msg)
	}
	if attempts >= 3 {
		e.fail(errors.New("MFA 验证失败次数过多，已退出"))
		return
	}
	// Prompt again right away.
	e.handleAuthChallenge(p, authChallengePayload(true))
}

// handleInfo (client): server info for the status display.
func (e *Engine) handleInfo(p *peerState, pt []byte) {
	var info ServerInfo
	if err := json.Unmarshal(pt, &info); err != nil {
		return
	}
	if e.opts.OnInfo != nil {
		e.opts.OnInfo(info)
	}
}

// clientMarkReady marks the session usable and fires OnReady once per run.
func (e *Engine) clientMarkReady(p *peerState) {
	e.mu.Lock()
	p.authed = true
	first := !e.clientReady
	e.clientReady = true
	e.mu.Unlock()
	if first && e.opts.OnReady != nil {
		e.opts.OnReady()
	}
}

// fail aborts the engine run with err (client-side fatal conditions).
func (e *Engine) fail(err error) {
	e.mu.Lock()
	if e.fatal == nil {
		e.fatal = err
		if e.cancelRun != nil {
			e.cancelRun()
		}
	}
	e.mu.Unlock()
}

// sendBye tells the gateway that we are leaving, so it drops the session
// immediately instead of waiting for the dead-peer timeout.
func (e *Engine) sendBye() {
	if e.opts.Mode != ModeClient {
		return
	}
	p := e.clientPeer()
	if p == nil {
		return
	}
	e.sendSealed(p, frameBye, nil)
	time.Sleep(60 * time.Millisecond) // give the datagram a chance to leave
}
