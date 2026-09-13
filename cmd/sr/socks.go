// sr socks — 本地 SOCKS5/HTTP 代理，流量经隧道送往站点。
//
// 为什么不需要 root：这里不建 tun、不动路由表。TCP 在进程内由用户态网络栈
// （wireguard-go 自带的 netstack）终结，产出的 IP 包直接喂给隧道引擎；对端
// agent 照常把包转发进站点网络，所以整条链路的语义和「整段路由模式」完全一致，
// 只是生效范围仅限使用这个代理的程序。
//
// 用法：
//
//	sr socks -c client.srkey -l 127.0.0.1:1080 [-dns 192.168.2.1]
//
//	curl --socks5-hostname 127.0.0.1:1080 http://192.168.2.5:5000/
//	ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@192.168.2.5
//	浏览器：SOCKS5 代理 127.0.0.1:1080（勾选「远程 DNS」）
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"selfremote/internal/config"
	"selfremote/internal/keyfile"
	"selfremote/internal/tunnel"
)

const (
	socks5Version = 0x05
	dialTimeout   = 20 * time.Second
	hsTimeout     = 30 * time.Second

	// SOCKS5 应答码
	repSuccess       = 0x00
	repHostUnreach   = 0x04
	repConnRefused   = 0x05
	repCmdNotSupport = 0x07
	repAddrNotSupprt = 0x08
)

// ---------------------------------------------------------------------------
// 用户态设备：把 netstack 的 tun 接到隧道引擎（netstack 不认 virtio-net 头）

type nsDevice struct{ d tun.Device }

func (n nsDevice) Read(buf []byte, offset int) (int, error) {
	sizes := []int{0}
	cnt, err := n.d.Read([][]byte{buf}, sizes, offset)
	if err != nil {
		return 0, err
	}
	if cnt == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

func (n nsDevice) Write(buf []byte, offset int) (int, error) {
	if _, err := n.d.Write([][]byte{buf}, offset); err != nil {
		return 0, err
	}
	return len(buf) - offset, nil
}

func (n nsDevice) Name() (string, error) { return "userspace(socks)", nil }
func (n nsDevice) Close() error          { return n.d.Close() }

// ---------------------------------------------------------------------------
// 代理服务

type proxy struct {
	dial   func(ctx context.Context, ap netip.AddrPort) (io.ReadWriteCloser, error)
	lookup func(ctx context.Context, host string) (netip.Addr, error)
	logf   func(format string, args ...any)
}

func (p *proxy) serve(ctx context.Context, ln net.Listener) {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	var lastErr time.Time
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// 避免 accept 持续失败时刷屏
			if time.Since(lastErr) > 30*time.Second {
				lastErr = time.Now()
				p.logf("accept: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go p.handle(ctx, c)
	}
}

func (p *proxy) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(hsTimeout))
	br := bufio.NewReader(c)
	head, err := br.Peek(1)
	if err != nil || len(head) == 0 {
		return
	}
	var herr error
	if head[0] == socks5Version {
		herr = p.handleSOCKS5(ctx, c, br)
	} else {
		herr = p.handleHTTP(ctx, c, br)
	}
	if herr != nil {
		p.logf("失败: %v", herr)
	}
}

func (p *proxy) handleSOCKS5(ctx context.Context, c net.Conn, br *bufio.Reader) error {
	hdr, err := br.Peek(2)
	if err != nil {
		return err
	}
	nm := int(hdr[1])
	greet := make([]byte, 2+nm)
	if _, err := io.ReadFull(br, greet); err != nil {
		return err
	}
	// 只提供「无认证」：代理只监听本机（或用户自己选的地址），
	// 再叠一层口令没有意义，反而挡住不想配口令的工具。
	if _, err := c.Write([]byte{socks5Version, 0x00}); err != nil {
		return err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return err
	}
	if req[0] != socks5Version {
		return fmt.Errorf("版本不对: %d", req[0])
	}
	if req[1] != 0x01 { // CONNECT
		writeSocksReply(c, repCmdNotSupport)
		return fmt.Errorf("不支持的命令 0x%02x（只支持 CONNECT）", req[1])
	}

	var (
		ap   netip.AddrPort
		disp string
	)
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 6)
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		ip, _ := netip.AddrFromSlice(b[:4])
		ap = netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[4:]))
		disp = ap.String()
	case 0x04: // IPv6
		b := make([]byte, 18)
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		ip, _ := netip.AddrFromSlice(b[:16])
		ap = netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[16:]))
		disp = ap.String()
	case 0x03: // 域名（curl --socks5-hostname / 浏览器远程 DNS）
		l, err := br.ReadByte()
		if err != nil {
			return err
		}
		b := make([]byte, int(l)+2)
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		name := string(b[:l])
		port := binary.BigEndian.Uint16(b[l:])
		disp = net.JoinHostPort(name, strconv.Itoa(int(port)))
		ip, err := p.lookup(ctx, name)
		if err != nil {
			writeSocksReply(c, repHostUnreach)
			return fmt.Errorf("解析 %s: %w", name, err)
		}
		ap = netip.AddrPortFrom(ip, port)
	default:
		writeSocksReply(c, repAddrNotSupprt)
		return fmt.Errorf("不支持的地址类型 0x%02x", req[3])
	}

	rc, err := p.dialTarget(ctx, ap, disp)
	if err != nil {
		writeSocksReply(c, errReplyCode(err))
		return err
	}
	defer rc.Close()
	if _, err := c.Write([]byte{socks5Version, repSuccess, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	_ = c.SetDeadline(time.Time{})
	p.logf("→ %s", disp)
	return pipe(c, br, rc)
}

func (p *proxy) handleHTTP(ctx context.Context, c net.Conn, br *bufio.Reader) error {
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}
	if req.Method != http.MethodConnect {
		fmt.Fprintf(c, "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"+
			"selfremote socks 只支持 CONNECT（HTTPS/任意 TCP），不支持明文 GET 代理请求\r\n")
		return fmt.Errorf("只支持 CONNECT（收到 %s）", req.Method)
	}
	host, portStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		host, portStr = req.Host, "443"
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		httpFail(c, 400)
		return fmt.Errorf("端口不对: %q", portStr)
	}
	disp := net.JoinHostPort(host, portStr)

	var ap netip.AddrPort
	if ip, err := netip.ParseAddr(host); err == nil {
		ap = netip.AddrPortFrom(ip, uint16(port))
	} else {
		rip, err := p.lookup(ctx, host)
		if err != nil {
			httpFail(c, 502)
			return fmt.Errorf("解析 %s: %w", host, err)
		}
		ap = netip.AddrPortFrom(rip, uint16(port))
	}

	rc, err := p.dialTarget(ctx, ap, disp)
	if err != nil {
		httpFail(c, 502)
		return err
	}
	defer rc.Close()
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	_ = c.SetDeadline(time.Time{})
	p.logf("→ %s (CONNECT)", disp)
	return pipe(c, br, rc)
}

func (p *proxy) dialTarget(ctx context.Context, ap netip.AddrPort, disp string) (io.ReadWriteCloser, error) {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	rc, err := p.dial(dctx, ap)
	if err != nil {
		return nil, fmt.Errorf("连接 %s: %w", disp, err)
	}
	return rc, nil
}

// pipe 双向搬运；任一方向 EOF 就关掉远端，唤醒另一侧。
func pipe(local net.Conn, localBuf *bufio.Reader, remote io.ReadWriteCloser) error {
	var once sync.Once
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remote, localBuf) // localBuf 里可能还有握手后残留的数据
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			once.Do(func() { _ = remote.Close() })
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(local, remote)
		once.Do(func() { _ = remote.Close() })
		done <- struct{}{}
	}()
	<-done
	<-done
	return nil
}

func writeSocksReply(c net.Conn, code byte) {
	_, _ = c.Write([]byte{socks5Version, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func httpFail(c net.Conn, status int) {
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		status, http.StatusText(status))
}

func errReplyCode(err error) byte {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "refused"):
		return repConnRefused
	case strings.Contains(msg, "no route"), strings.Contains(msg, "unreachable"),
		strings.Contains(msg, "timeout"), strings.Contains(msg, "timed out"):
		return repHostUnreach
	default:
		return repHostUnreach
	}
}

// ---------------------------------------------------------------------------
// 域名解析：只有 -dns 指定了站点内 DNS 时才启用（查询本身也走隧道）。
// 没有指定时，域名直接返回错误，提示改用 IP —— 免得解析跑到公网 DNS 上，
// 泄露你要访问的内网名字。

type tunnelDNS struct {
	tnet   *netstack.Net
	laddr  netip.Addr
	server netip.Addr

	mu    sync.Mutex
	cache map[string]dnsEntry
}

type dnsEntry struct {
	ip  netip.Addr
	exp time.Time
}

func (d *tunnelDNS) lookup(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip, nil
	}
	if d == nil || !d.server.IsValid() {
		return netip.Addr{}, fmt.Errorf("没有配置 -dns，无法解析 %q（请直接用 IP，或用 -dns <站点内 DNS>）", host)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	d.mu.Lock()
	if e, ok := d.cache[host]; ok && time.Now().Before(e.exp) {
		d.mu.Unlock()
		return e.ip, nil
	}
	d.mu.Unlock()

	ip, ttl, err := d.query(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	if ttl < time.Minute {
		ttl = time.Minute
	}
	d.mu.Lock()
	if d.cache == nil {
		d.cache = map[string]dnsEntry{}
	}
	d.cache[host] = dnsEntry{ip: ip, exp: time.Now().Add(ttl)}
	d.mu.Unlock()
	return ip, nil
}

func (d *tunnelDNS) query(ctx context.Context, host string) (netip.Addr, time.Duration, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("域名不合法: %w", err)
	}
	var idBytes [2]byte
	_, _ = rand.Read(idBytes[:])
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               binary.BigEndian.Uint16(idBytes[:]),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return netip.Addr{}, 0, err
	}

	conn, err := d.tnet.DialUDPAddrPort(netip.AddrPortFrom(d.laddr, 0), netip.AddrPortFrom(d.server, 53))
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("DNS 通道: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(packed); err != nil {
		return netip.Addr{}, 0, fmt.Errorf("DNS 查询: %w", err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("DNS %s 无响应: %w", d.server, err)
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		return netip.Addr{}, 0, fmt.Errorf("DNS 应答无法解析: %w", err)
	}
	if resp.RCode != dnsmessage.RCodeSuccess {
		return netip.Addr{}, 0, fmt.Errorf("DNS 返回 %s", resp.RCode)
	}
	for _, ans := range resp.Answers {
		if a, ok := ans.Body.(*dnsmessage.AResource); ok {
			return netip.AddrFrom4(a.A), time.Duration(ans.Header.TTL) * time.Second, nil
		}
	}
	return netip.Addr{}, 0, fmt.Errorf("DNS 里没有 %s 的 A 记录", host)
}

// ---------------------------------------------------------------------------
// sr socks

func cmdSocks(args []string) error {
	fs := flag.NewFlagSet("socks", flag.ContinueOnError)
	cfgPath := fs.String("c", "", "客户端配置文件（.srkey 或明文 JSON）")
	kpass := fs.String("kpass", "", "密钥文件口令（或环境变量 SR_KEYPASS）")
	mfaCode := fs.String("mfa", "", "首次动态码（或环境变量 SR_MFA）；不填则交互式询问")
	listen := fs.String("l", "127.0.0.1:1080", "本地监听地址（SOCKS5 + HTTP CONNECT）")
	dnsSrv := fs.String("dns", "", "走隧道解析域名用的 DNS（站点内地址，如 192.168.2.1）；不填则只能访问 IP")
	serverOverride := fs.String("server", "", "覆盖配置里的服务端地址（调试用，如 127.0.0.1:28333）")
	mtu := fs.Int("mtu", 1360, "隧道 MTU")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("需要 -c <配置文件>")
	}

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		return err
	}
	if keyfile.IsEnvelope(raw) {
		pass := *kpass
		if pass == "" {
			pass = os.Getenv("SR_KEYPASS")
		}
		plain, err := unlockKeyfile(raw, pass)
		if err != nil {
			return err
		}
		raw = plain
		fmt.Println("密钥文件已解密（仅保存在内存中）")
	}

	cfg, err := config.LoadClientBytes(raw, *cfgPath)
	if err != nil {
		return err
	}
	if *serverOverride != "" {
		cfg.Server = *serverOverride
	}
	var dnsSrvAddr netip.Addr
	if *dnsSrv != "" {
		ds, err := netip.ParseAddr(*dnsSrv)
		if err != nil {
			return fmt.Errorf("-dns %q 不是合法地址", *dnsSrv)
		}
		dnsSrvAddr = ds
	}

	// 隧道地址：netstack 用它作为源地址（服务端按归属校验源地址，必须一致）
	ip, _, err := net.ParseCIDR(cfg.TunnelCIDR)
	if err != nil {
		return fmt.Errorf("tunnel_cidr %q: %w", cfg.TunnelCIDR, err)
	}
	localAddr, ok := netip.AddrFromSlice(ip.To4())
	if !ok {
		return fmt.Errorf("tunnel_cidr %q 不是 IPv4", cfg.TunnelCIDR)
	}

	// 用户态网络栈：TCP/IP 在进程内跑，IP 包直接进出隧道（默认路由全指向隧道）
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{localAddr}, nil, *mtu)
	if err != nil {
		return fmt.Errorf("用户态网络栈: %w", err)
	}
	defer dev.Close()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("监听 %s: %w", *listen, err)
	}
	defer ln.Close()

	ready := make(chan struct{})
	var readyOnce sync.Once

	// MFA prompt. A code passed via -mfa / SR_MFA is used for the first
	// attempt only; interactive retries always go through the prompt.
	var (
		mfaMu    sync.Mutex
		mfaTaken bool
	)
	authPrompt := func(attempt int) (string, bool) {
		if *mfaCode != "" {
			mfaMu.Lock()
			take := !mfaTaken
			mfaTaken = true
			mfaMu.Unlock()
			if take {
				return *mfaCode, true
			}
		}
		fmt.Fprintf(os.Stderr, "请输入 Google Authenticator 动态验证码（6 位，直接回车取消）: ")
		line, err := readLine()
		if err != nil || line == "" {
			return "", false
		}
		return line, true
	}

	eng, err := tunnel.New(tunnel.Options{
		Mode:          tunnel.ModeClient,
		PrivateKey:    cfg.Private[:],
		Server:        cfg.Server,
		ServerPublic:  cfg.ServerPublic[:],
		TunnelCIDR:    cfg.TunnelCIDR,
		Routes:        cfg.Routes,
		MTU:           *mtu,
		Device:        nsDevice{dev}, // 注入用户态设备：不建 tun、不动路由表
		SkipNetConfig: true,
		AuthPrompt:    authPrompt,
		OnReady:       func() { readyOnce.Do(func() { close(ready) }) },
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[tunnel] "+format+"\n", args...)
		},
	})
	if err != nil {
		return err
	}

	// Local listeners immediately.

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("selfremote socks %s\n", version)
	fmt.Printf("  server:   %s\n", cfg.Server)
	fmt.Printf("  tunnel:   %s (userspace stack, no root)\n", cfg.TunnelCIDR)
	fmt.Printf("  routes:   %v\n", cfg.Routes)
	fmt.Printf("  listen:   %s (SOCKS5 + HTTP CONNECT)\n", *listen)

	// Engine runs in background; socks listener starts right away and packets
	// queue inside the netstack device until the tunnel is ready.
	go func() {
		if err := eng.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[tunnel] stopped: %v\n", err)
			stop()
		}
	}()

	select {
	case <-ready:
		fmt.Println("隧道已就绪（MFA 通过）。")
	case <-ctx.Done():
		return nil
	case <-time.After(5 * time.Minute):
		return errors.New("等待隧道就绪超时")
	}

	srv := &proxy{
		dial: func(ctx context.Context, ap netip.AddrPort) (io.ReadWriteCloser, error) {
			c, err := netstackDial(ctx, tnet, ap)
			if err != nil {
				return nil, err
			}
			return c, nil
		},
		lookup: (&tunnelDNS{tnet: tnet, laddr: localAddr, server: dnsSrvAddr}).lookup,
		logf:   func(format string, args ...any) { fmt.Fprintf(os.Stderr, "[socks] "+format+"\n", args...) },
	}
	srv.serve(ctx, ln)

	fmt.Println("socks: stopped.")
	return nil
}

func netstackDial(ctx context.Context, tnet *netstack.Net, ap netip.AddrPort) (io.ReadWriteCloser, error) {
	c, err := tnet.DialContextTCPAddrPort(ctx, ap)
	if err != nil {
		return nil, err
	}
	return c, nil
}
