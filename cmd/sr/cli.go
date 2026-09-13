package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"selfremote/internal/config"
	"selfremote/internal/keyfile"
	"selfremote/internal/tunnel"
)

// stdinReader is shared across prompts so buffered input is never lost
// between reads (a fresh bufio.Reader per prompt would over-read).
var stdinReader = bufio.NewReader(os.Stdin)

// readSecret reads a line without echo when stdin is a terminal.
func readSecret() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	line, err := stdinReader.ReadString('\n')
	return strings.TrimSpace(line), err
}

// readLine reads one visible line from stdin.
func readLine() (string, error) {
	line, err := stdinReader.ReadString('\n')
	return strings.TrimSpace(line), err
}

// unlockKeyfile decrypts an encrypted key file. When pass comes from a flag or
// the environment (automation) a wrong passphrase fails immediately; when it
// was not supplied, the user gets up to 3 interactive attempts.
func unlockKeyfile(raw []byte, pass string) ([]byte, error) {
	interactive := pass == ""
	for i := 1; ; i++ {
		if pass == "" {
			fmt.Fprint(os.Stderr, "该密钥文件已加密，请输入文件密码（回车取消）: ")
			p, err := readSecret()
			if err != nil || p == "" {
				return nil, errors.New("未输入密钥文件密码")
			}
			pass = p
		}
		plain, err := keyfile.Open(raw, pass)
		if err == nil {
			return plain, nil
		}
		if !errors.Is(err, keyfile.ErrWrongPassphrase) || !interactive {
			return nil, err
		}
		if i >= 3 {
			return nil, errors.New("密钥文件密码错误次数过多")
		}
		fmt.Fprintf(os.Stderr, "密码错误，请重试（%d/3）\n", i)
		pass = ""
	}
}

// clientState carries display state updated from engine callbacks (which run
// on engine goroutines, hence the mutex).
type clientState struct {
	mu      sync.Mutex
	ready   bool
	info    *tunnel.ServerInfo
	mfaUsed bool
}

func (cs *clientState) setMFAUsed() {
	cs.mu.Lock()
	cs.mfaUsed = true
	cs.mu.Unlock()
}

func (cs *clientState) onReady(cfg *config.Client) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.ready = true
	printReadyBlock(cfg, cs.info, cs.mfaUsed)
}

func (cs *clientState) onInfo(i tunnel.ServerInfo) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.info = &i
	if cs.ready {
		printHostInfo(i)
	}
}

func (cs *clientState) isReady() bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.ready
}

func printReadyBlock(cfg *config.Client, info *tunnel.ServerInfo, mfaUsed bool) {
	fmt.Println()
	fmt.Println("═══════════════ selfremote 已连接 ═══════════════")
	fmt.Printf("  服务端:  %s\n", cfg.Server)
	if info != nil {
		printHostInfo(*info)
	}
	fmt.Printf("  隧道:    %s\n", cfg.TunnelCIDR)
	fmt.Printf("  路由:    %v\n", cfg.Routes)
	if mfaUsed {
		fmt.Println("  MFA:     ✓ 动态验证码已通过")
	} else {
		fmt.Println("  MFA:     服务端未要求动态码")
	}
	fmt.Println("  退出:    Control + C（自动断开并清理路由）")
	fmt.Println("═══════════════════════════════════════════════")
}

func printHostInfo(i tunnel.ServerInfo) {
	fmt.Printf("  服务器:  %s（监听 %s）\n", i.Hostname, i.Listen)
}

// statusLoop prints a one-line status every 30 s while connected.
func statusLoop(ctx context.Context, eng *tunnel.Engine, isReady func() bool) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !isReady() {
				continue
			}
			for _, st := range eng.Stats() {
				if st.Connected && st.Authed {
					fmt.Printf("[状态] 已连接 %s · ↑%s ↓%s · 对端 %s\n",
						sinceDur(st.Since), humanBytes(st.BytesOut), humanBytes(st.BytesIn), st.Remote)
				}
			}
		}
	}
}

// sinceDur renders one of the engine's RFC3339 timestamps as elapsed time.
func sinceDur(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "—"
	}
	return humanDur(time.Since(t))
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func humanDur(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
