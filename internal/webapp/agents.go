package webapp

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/flynn/noise"
	"github.com/pquerna/otp/totp"

	"selfremote/internal/keyfile"
)

// Site agents (v0.3): what the hub relays to. The control plane owns the
// registry (agents.json), the agent's deployment package and the operator
// switches; the hub owns the live state, which it reports over its API.

// tunnelNet is the subnet the hub itself lives on; site prefixes must not
// overlap it.
const tunnelNet = "10.77.0.0/24"

type agentRow struct {
	Agent
	Live   liveAgentStatus
	Routes []string // effective prefixes (what clients address)
}

// agentPlatRow is one downloadable platform in the agent detail view.
type agentPlatRow struct {
	Key    string
	Label  string
	OK     bool
	Binary string
}

// handleAgents lists the sites.
func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	var (
		agents []Agent
		err    error
	)
	if u.IsAdmin {
		agents, err = s.allAgents(ctx)
	} else {
		agents, err = s.agentsByUser(ctx, u.ID)
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	view := s.hubView(ctx)
	rows := make([]agentRow, 0, len(agents))
	for i := range agents {
		a := agents[i]
		live := view.AgentByID[a.AgentID]
		routes := make([]string, 0, len(a.Routes))
		for _, rt := range a.Routes {
			routes = append(routes, rt.Effective())
		}
		rows = append(rows, agentRow{Agent: a, Live: agentState(&a, live, view.Reachable, a.Enabled), Routes: routes})
	}
	var conflicts []string
	if view.Status != nil {
		conflicts = view.Status.Conflicts
	}
	s.render(w, r, "agents.html", pageData{
		Title:       "站点 Agent",
		AutoRefresh: true,
		Data: map[string]any{
			"Agents":       rows,
			"HubReachable": view.Reachable,
			"IsAdmin":      u.IsAdmin,
			"Conflicts":    conflicts,
		},
	})
}

// handleAgentNew renders the creation form.
func (s *Server) handleAgentNew(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	agents, err := s.allAgents(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var problems []string
	if _, err := s.hubPubKey(); err != nil {
		problems = append(problems, err.Error())
	}
	if s.serverAddr() == "" {
		problems = append(problems, "无法确定服务端地址：请等中转服务端运行几秒生成 netinfo.json，或在配置里显式设置 SERVER_ADDR")
	}
	used := make([]string, 0, len(agents))
	for _, a := range agents {
		used = append(used, a.AgentID)
	}
	s.render(w, r, "agent_new.html", pageData{
		Title: "添加站点 Agent",
		Data: map[string]any{
			"Problems":   problems,
			"UsedIDs":    used,
			"Existing":   agents,
			"TunnelNet":  tunnelNet,
			"UsedRoutes": existingEffectivePrefixes(agents),
		},
	})
}

// existingEffectivePrefixes returns every prefix already published (so the
// form can warn about collisions).
func existingEffectivePrefixes(agents []Agent) []string {
	var out []string
	for _, a := range agents {
		for _, rt := range a.Routes {
			out = append(out, rt.Effective())
		}
	}
	sort.Strings(out)
	return out
}

// handleAgentCreate registers a new site and returns to the detail page.
func (s *Server) handleAgentCreate(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/agents/new", "", "表单校验失败，请重试")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	agentID := strings.ToLower(strings.TrimSpace(r.FormValue("agent_id")))
	if err := validAgentID(agentID); err != nil {
		redirectMsg(w, r, "/agents/new", "", err.Error())
		return
	}
	if name == "" {
		name = agentID
	}
	routes, err := parseAgentRoutes(r.FormValue("routes"))
	if err != nil {
		redirectMsg(w, r, "/agents/new", "", err.Error())
		return
	}
	if len(routes) == 0 {
		redirectMsg(w, r, "/agents/new", "", "至少填写一个站点网段")
		return
	}
	if existing, err := s.agentByAgentID(ctx, agentID); err == nil && existing != nil {
		redirectMsg(w, r, "/agents/new", "", "该 Agent ID 已存在")
		return
	}
	agents, err := s.allAgents(ctx)
	if err != nil {
		redirectMsg(w, r, "/agents/new", "", "内部错误")
		return
	}
	if err := validateRouteSet(routes, agents, nil); err != nil {
		redirectMsg(w, r, "/agents/new", "", err.Error())
		return
	}

	// Keypair + per-agent MFA secret (auto-answered by the agent itself).
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	kp, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		redirectMsg(w, r, "/agents/new", "", "生成密钥失败")
		return
	}
	secret, err := newTOTPSecret()
	if err != nil {
		redirectMsg(w, r, "/agents/new", "", "生成动态码密钥失败")
		return
	}
	tunnelIP, err := s.allocAgentIP(ctx)
	if err != nil {
		redirectMsg(w, r, "/agents/new", "", err.Error())
		return
	}
	a := &Agent{
		UserID:     u.ID,
		AgentID:    agentID,
		Name:       name,
		PublicKey:  base64.StdEncoding.EncodeToString(kp.Public),
		TunnelIP:   tunnelIP,
		TOTPSecret: secret,
		Enabled:    true,
		Routes:     routes,
	}
	if err := s.addAgent(ctx, a); err != nil {
		log.Printf("addAgent %s: %v", agentID, err)
		redirectMsg(w, r, "/agents/new", "", "保存失败（Agent ID 或公钥重复）")
		return
	}
	if err := s.syncRegistries(ctx); err != nil {
		log.Printf("sync registries: %v", err)
	}
	log.Printf("user %s: agent %q created (site %s, tunnel %s)", u.Username, agentID, routesText(routes), tunnelIP)
	redirectMsg(w, r, "/agents/"+agentID, "站点已创建：下载部署包并在一台机器上运行，它就会拨号接入", "")
}

// handleAgentShow renders one site: live state, routes, deployment and the
// operator actions.
func (s *Server) handleAgentShow(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	a, err := s.agentByAgentID(ctx, r.PathValue("id"))
	if err != nil || a == nil {
		http.Error(w, "站点不存在", http.StatusNotFound)
		return
	}
	if a.UserID != u.ID && !u.IsAdmin {
		http.Error(w, "无权查看他人站点", http.StatusForbidden)
		return
	}
	view := s.hubView(ctx)
	live := agentState(a, view.AgentByID[a.AgentID], view.Reachable, a.Enabled)

	// Deployment package availability: which platform binaries are present.
	var plats []agentPlatRow
	for _, p := range agentPlatforms() {
		_, err := os.Stat(filepath.Join(s.cfg.AgentDistDir, p.Binary))
		plats = append(plats, agentPlatRow{Key: p.Key, Label: p.Label, OK: err == nil, Binary: p.Binary})
	}
	_, srvErr := s.hubPubKey()
	s.render(w, r, "agent_show.html", pageData{
		Title: "站点 " + a.Name,
		Data: map[string]any{
			"Agent":        a,
			"Live":         live,
			"HubReachable": view.Reachable,
			"Routes":       a.Routes,
			"Server":       s.serverAddr(),
			"Platforms":    plats,
			"DistReady":    anyPlatformReady(plats),
			"KeyProblem":   errText(srvErr),
		},
	})
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func anyPlatformReady(ps []agentPlatRow) bool {
	for _, p := range ps {
		if p.OK {
			return true
		}
	}
	return false
}

// handleAgentState enables or disables a site.
func (s *Server) handleAgentState(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/agents", "", "表单校验失败，请重试")
		return
	}
	a, err := s.agentByAgentID(ctx, r.PathValue("id"))
	if err != nil || a == nil {
		http.Error(w, "站点不存在", http.StatusNotFound)
		return
	}
	if a.UserID != u.ID && !u.IsAdmin {
		http.Error(w, "无权操作他人站点", http.StatusForbidden)
		return
	}
	enable := r.FormValue("enabled") == "1"
	if err := s.setAgentEnabled(ctx, a.ID, enable); err != nil {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "更新失败")
		return
	}
	if err := s.syncRegistries(ctx); err != nil {
		log.Printf("sync registries: %v", err)
	}
	verb := "停用"
	if enable {
		verb = "启用"
	}
	log.Printf("user %s: agent %q -> enabled=%v", u.Username, a.AgentID, enable)
	redirectMsg(w, r, "/agents/"+a.AgentID, "已"+verb+"站点 "+a.Name+"（中转服务端会在 1 秒内生效，无需重启 agent）", "")
}

// handleAgentKick forces a reconnect of a connected site.
func (s *Server) handleAgentKick(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/agents", "", "表单校验失败，请重试")
		return
	}
	a, err := s.agentByAgentID(ctx, r.PathValue("id"))
	if err != nil || a == nil {
		http.Error(w, "站点不存在", http.StatusNotFound)
		return
	}
	if a.UserID != u.ID && !u.IsAdmin {
		http.Error(w, "无权操作他人站点", http.StatusForbidden)
		return
	}
	if err := s.hubKick(ctx, a.AgentID); err != nil {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "踢线失败："+err.Error())
		return
	}
	log.Printf("user %s: agent %q kicked", u.Username, a.AgentID)
	redirectMsg(w, r, "/agents/"+a.AgentID, "已要求 "+a.Name+" 重新连接（数秒内自动恢复）", "")
}

// handleAgentRotateMFA issues a fresh MFA secret for a site. The running
// agent keeps the old secret until it is redeployed with the new package.
func (s *Server) handleAgentRotateMFA(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/agents", "", "表单校验失败，请重试")
		return
	}
	a, err := s.agentByAgentID(ctx, r.PathValue("id"))
	if err != nil || a == nil {
		http.Error(w, "站点不存在", http.StatusNotFound)
		return
	}
	if a.UserID != u.ID && !u.IsAdmin {
		http.Error(w, "无权操作他人站点", http.StatusForbidden)
		return
	}
	secret, err := newTOTPSecret()
	if err != nil {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "生成失败")
		return
	}
	if err := s.setAgentTOTP(ctx, a.ID, secret); err != nil {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "更新失败")
		return
	}
	if err := s.syncRegistries(ctx); err != nil {
		log.Printf("sync registries: %v", err)
	}
	log.Printf("user %s: agent %q MFA rotated", u.Username, a.AgentID)
	redirectMsg(w, r, "/agents/"+a.AgentID,
		"已轮换动态码密钥：站点当前会话会在下次重连时失效，请重新下载部署包并替换站点上的配置文件", "")
}

// handleAgentRevoke removes a site for good (its sessions are dropped and its
// handshakes rejected within a second).
func (s *Server) handleAgentRevoke(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/agents", "", "表单校验失败，请重试")
		return
	}
	a, err := s.agentByAgentID(ctx, r.PathValue("id"))
	if err != nil || a == nil {
		http.Error(w, "站点不存在", http.StatusNotFound)
		return
	}
	if a.UserID != u.ID && !u.IsAdmin {
		http.Error(w, "无权操作他人站点", http.StatusForbidden)
		return
	}
	if err := s.deleteAgent(ctx, a.ID); err != nil {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "删除失败")
		return
	}
	if err := s.syncRegistries(ctx); err != nil {
		log.Printf("sync registries: %v", err)
	}
	log.Printf("user %s: agent %q revoked", u.Username, a.AgentID)
	redirectMsg(w, r, "/agents", "已删除站点 "+a.Name+"（在线会话会在数秒内断开，站点上的 agent 将无法再连入）", "")
}

// ------------------------------------------------------------ deployment pkg

type agentPlatform struct {
	Key    string
	Label  string
	Binary string
	GOOS   string
	GOARCH string
}

func agentPlatforms() []agentPlatform {
	return []agentPlatform{
		{Key: "linux-amd64", Label: "Linux x86_64（群晖/服务器/软路由）", Binary: "agent-linux-amd64", GOOS: "linux", GOARCH: "amd64"},
		{Key: "linux-arm64", Label: "Linux arm64（ARM 服务器/树莓派）", Binary: "agent-linux-arm64", GOOS: "linux", GOARCH: "arm64"},
		{Key: "darwin-arm64", Label: "macOS Apple Silicon", Binary: "agent-darwin-arm64", GOOS: "darwin", GOARCH: "arm64"},
		{Key: "darwin-amd64", Label: "macOS Intel", Binary: "agent-darwin-amd64", GOOS: "darwin", GOARCH: "amd64"},
		{Key: "windows-amd64", Label: "Windows x86_64", Binary: "agent-windows-amd64.exe", GOOS: "windows", GOARCH: "amd64"},
	}
}

func platformByKey(key string) (agentPlatform, bool) {
	for _, p := range agentPlatforms() {
		if p.Key == key {
			return p, true
		}
	}
	return agentPlatform{}, false
}

// handleAgentPackage builds and streams the deployment package: the agent
// binary (when the web image carries it), the encrypted configuration and
// platform-specific instructions.
func (s *Server) handleAgentPackage(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/agents", "", "表单校验失败，请重试")
		return
	}
	a, err := s.agentByAgentID(ctx, r.PathValue("id"))
	if err != nil || a == nil {
		http.Error(w, "站点不存在", http.StatusNotFound)
		return
	}
	if a.UserID != u.ID && !u.IsAdmin {
		http.Error(w, "无权操作他人站点", http.StatusForbidden)
		return
	}
	plat, ok := platformByKey(r.FormValue("platform"))
	if !ok {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "平台选择无效")
		return
	}
	pass := r.FormValue("passphrase")
	if len(pass) < 10 {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "配置文件密码至少 10 位")
		return
	}
	addr := s.serverAddr()
	if addr == "" {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "无法确定服务端地址")
		return
	}
	hubPub, err := s.hubPubKey()
	if err != nil {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", err.Error())
		return
	}

	// The agent's private key never leaves the package: it lives only here in
	// memory, inside the encrypted .srkey we are about to stream. Downloading
	// a package therefore mints a NEW keypair and updates the stored public
	// key — any previously deployed package for this site stops working,
	// which is the honest behaviour for a "deploy/replace" operation.
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	kp, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "生成密钥失败")
		return
	}
	pubB64 := base64.StdEncoding.EncodeToString(kp.Public)
	if err := s.updateAgentPublicKey(ctx, a.ID, pubB64); err != nil {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "更新站点公钥失败")
		return
	}
	if err := s.syncRegistries(ctx); err != nil {
		log.Printf("sync registries: %v", err)
	}

	cfgJSON, err := json.MarshalIndent(map[string]any{
		"id":                a.AgentID,
		"name":              a.Name,
		"server":            addr,
		"private_key":       base64.StdEncoding.EncodeToString(kp.Private),
		"server_public_key": hubPub,
		"tunnel_cidr":       a.TunnelIP + "/24",
		"mfa_secret":        a.TOTPSecret,
		"routes":            a.Routes,
	}, "", "  ")
	if err != nil {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "内部错误")
		return
	}
	env, err := keyfile.Seal(cfgJSON, pass)
	if err != nil {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "加密配置文件失败")
		return
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	base := "selfremote-agent-" + a.AgentID
	writeZip := func(name string, data []byte, mode os.FileMode) error {
		hdr := &zip.FileHeader{Name: base + "/" + name, Method: zip.Deflate}
		hdr.SetMode(mode)
		// Executable bits matter on Linux/macOS.
		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		_, err = fw.Write(data)
		return err
	}

	binPath := filepath.Join(s.cfg.AgentDistDir, plat.Binary)
	if raw, err := os.ReadFile(binPath); err == nil {
		if err := writeZip(plat.Binary, raw, 0o755); err != nil {
			redirectMsg(w, r, "/agents/"+a.AgentID, "", "打包失败")
			return
		}
	}
	if err := writeZip(a.AgentID+".srkey", env, 0o600); err != nil {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "打包失败")
		return
	}
	for name, content := range packageExtras(a, plat, addr) {
		if err := writeZip(name, []byte(content), 0o644); err != nil {
			redirectMsg(w, r, "/agents/"+a.AgentID, "", "打包失败")
			return
		}
	}
	if err := zw.Close(); err != nil {
		redirectMsg(w, r, "/agents/"+a.AgentID, "", "打包失败")
		return
	}

	log.Printf("user %s: agent %q package built (%s, %d bytes, binary=%v)",
		u.Username, a.AgentID, plat.Key, buf.Len(), fileExists(binPath))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", base+"-"+plat.Key+".zip"))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// packageExtras renders the instruction files shipped inside the zip.
func packageExtras(a *Agent, plat agentPlatform, serverAddr string) map[string]string {
	routes := routesText(a.Routes)
	var sb strings.Builder
	fmt.Fprintf(&sb, `selfremote 站点 Agent 部署说明
========================================

站点:      %s (%s)
服务端:    %s
隧道地址:  %s
站点网段:  %s

这个包里的文件
--------------
  %s        agent 二进制（本平台）
  %s.srkey  加密配置文件（含站点私钥与动态码密钥；文件密码由你刚才设定）
  README.txt        本说明
`, a.Name, a.AgentID, serverAddr, a.TunnelIP, routes, plat.Binary, a.AgentID)

	switch plat.GOOS {
	case "linux":
		sb.WriteString(`
在站点机器上安装（Linux）
-------------------------
  1) 复制整个目录到站点机器，例如 /opt/selfremote-agent/
  2) 安装并启动（需要 root；容器/虚拟机里跑也没问题）：

     sudo install -m 0755 ` + plat.Binary + ` /usr/local/bin/sr
     sudo mkdir -p /etc/selfremote
     sudo install -m 0600 ` + a.AgentID + `.srkey /etc/selfremote/agent.srkey
     sudo SR_KEYPASS='<文件密码>' /usr/local/bin/sr agent -c /etc/selfremote/agent.srkey

  3) 长期运行：把密码写进 systemd 单元（root 可读，注意权限）：

     sudo tee /etc/systemd/system/selfremote-agent.service >/dev/null <<'EOF'
     [Unit]
     Description=selfremote site agent
     After=network-online.target
     Wants=network-online.target

     [Service]
     Environment=SR_KEYPASS=<文件密码>
     ExecStart=/usr/local/bin/sr agent -c /etc/selfremote/agent.srkey
     Restart=always
     RestartSec=5
     # 站点需要转发与 SNAT（内核级）：
     ExecStartPre=-/bin/sh -c 'sysctl -w net.ipv4.ip_forward=1'
     ExecStartPre=-/bin/sh -c 'iptables -t nat -C POSTROUTING -s 10.77.0.0/24 ! -o sr0 -j MASQUERADE || iptables -t nat -A POSTROUTING -s 10.77.0.0/24 ! -o sr0 -j MASQUERADE'
     ExecStartPre=-/bin/sh -c 'iptables -C FORWARD -i sr0 ! -o sr0 -j ACCEPT || iptables -A FORWARD -i sr0 ! -o sr0 -j ACCEPT'

     [Install]
     WantedBy=multi-user.target
     EOF
     sudo systemctl daemon-reload && sudo systemctl enable --now selfremote-agent

  容器方式（推荐，镜像里已带转发/NAT 配置）：
     docker run -d --name selfremote-agent --restart unless-stopped \
       --network host --cap-add NET_ADMIN --cap-add NET_RAW \
       --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
       -e SR_KEYPASS='<文件密码>' \
       -v /opt/selfremote-agent:/etc/selfremote \
       ghcr.io/zph0713/selfremote:latest agent -c /etc/selfremote/` + a.AgentID + `.srkey
`)
	case "darwin":
		sb.WriteString(`
在站点机器上安装（macOS）
-------------------------
  1) 双击包里的「双击启动.command」，或在终端里执行：
       chmod +x ` + plat.Binary + `
       xattr -d com.apple.quarantine ` + plat.Binary + ` 2>/dev/null
       sudo SR_KEYPASS='<文件密码>' ./` + plat.Binary + ` agent -c ` + a.AgentID + `.srkey
  2) macOS 需要 root 才能建 utun 与改路由，这是正常的。
  3) 长期运行：可用 launchd 或 nohup 常驻；注意 macOS 没有 ip_forward 的
     sysctl，站点若只是 mac 本机所在网段可直接工作。
`)
	case "windows":
		sb.WriteString(`
在站点机器上安装（Windows）
---------------------------
  Windows 不支持创建 TUN（需要 wintun.dll 且驱动签名），建议改用
  Linux 容器/虚拟机方式部署本 agent；本包里的 exe 仅用于实验。
`)
	}

	sb.WriteString(`
站点需要什么
------------
  * 能访问站点内网（就是站点所在的那台机器）
  * 出站 UDP 到服务端的 ` + serverAddr + `（不需要任何入站端口/端口映射）
  * 内核转发 + 源地址改写（容器镜像自动配置；手工部署见上面的命令）

安全说明
--------
  * 站点的私钥与动态码密钥都在 ` + a.AgentID + `.srkey 里，用你的文件密码加密。
    重新下载部署包会生成新密钥，旧包随即失效。
  * agent 每次连接都会用配置里的动态码密钥自动应答服务端的 MFA 挑战；
    停止/启用/踢线都在网页端操作，无需登录站点机器。
`)
	return map[string]string{
		"README.txt": sb.String(),
	}
}

// routesText renders routes for humans/logs.
func routesText(routes []AgentRoute) string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		if r.Virtual == "" || r.Virtual == r.Real {
			out = append(out, r.Real)
		} else {
			out = append(out, r.Real+" => "+r.Virtual)
		}
	}
	return strings.Join(out, ", ")
}

// --------------------------------------------------------------- validation

// validAgentID enforces a slug: lowercase letters, digits and dashes.
func validAgentID(id string) error {
	if id == "" {
		return fmt.Errorf("Agent ID 不能为空（用于标识站点，如 home / office）")
	}
	if len(id) > 32 {
		return fmt.Errorf("Agent ID 最长 32 个字符")
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return fmt.Errorf("Agent ID 只能用小写字母、数字和短横线（%q 不合法）", string(c))
		}
	}
	return nil
}

// parseAgentRoutes parses the routes textarea: one prefix per line, either
// "192.168.1.0/24" (presented as-is) or "192.168.1.0/24 => 10.200.7.0/24".
func parseAgentRoutes(raw string) ([]AgentRoute, error) {
	var out []AgentRoute
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		real, virtual := line, ""
		if idx := strings.Index(line, "=>"); idx >= 0 {
			real = strings.TrimSpace(line[:idx])
			virtual = strings.TrimSpace(line[idx+2:])
		} else if idx := strings.Index(line, "="); idx >= 0 {
			real = strings.TrimSpace(line[:idx])
			virtual = strings.TrimSpace(line[idx+1:])
		}
		rp, err := netip.ParsePrefix(real)
		if err != nil {
			return nil, fmt.Errorf("网段 %q 不是合法的 CIDR（示例 192.168.1.0/24）", real)
		}
		if rp.Addr().Is4() && rp.Bits() < 8 {
			return nil, fmt.Errorf("网段 %q 太大，请至少用 /8 更具体的前缀", real)
		}
		vp := ""
		if virtual != "" {
			p, err := netip.ParsePrefix(virtual)
			if err != nil {
				return nil, fmt.Errorf("虚拟网段 %q 不是合法的 CIDR", virtual)
			}
			if p.Addr().Is4() != rp.Addr().Is4() || p.Bits() != rp.Bits() {
				return nil, fmt.Errorf("虚拟网段 %q 必须与真实网段 %q 同族且前缀长度一致", virtual, real)
			}
			vp = p.Masked().String()
		}
		out = append(out, AgentRoute{Real: rp.Masked().String(), Virtual: vp})
	}
	return out, nil
}

// validateRouteSet rejects overlapping published prefixes: the hub needs every
// virtual prefix to identify exactly one site, and nothing may shadow the
// tunnel network itself.
func validateRouteSet(routes []AgentRoute, others []Agent, self *Agent) error {
	tn := netip.MustParsePrefix(tunnelNet)
	seen := map[string]bool{}
	for _, r := range routes {
		eff := netip.MustParsePrefix(r.Effective())
		if eff.Overlaps(tn) {
			return fmt.Errorf("网段 %s 与隧道网段 %s 冲突，请换一个虚拟网段（如 %s => 10.200.7.0/24）",
				r.Effective(), tunnelNet, r.Real)
		}
		if seen[eff.String()] {
			return fmt.Errorf("同一站点里重复声明了网段 %s", eff.String())
		}
		seen[eff.String()] = true
		for _, o := range others {
			if self != nil && o.AgentID == self.AgentID {
				continue
			}
			for _, ort := range o.Routes {
				oeff := netip.MustParsePrefix(ort.Effective())
				if eff.Overlaps(oeff) {
					return fmt.Errorf("网段 %s 与站点 %s 的 %s 冲突：请给本站点换一个虚拟网段（写法 %s => 10.200.7.0/24）",
						r.Effective(), o.AgentID, ort.Effective(), r.Real)
				}
			}
		}
	}
	return nil
}

// newTOTPSecret generates a fresh base32 secret (Google Authenticator style).
func newTOTPSecret() (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "selfremote-agent",
		AccountName: "site-agent",
	})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

// updateAgentPublicKey stores a freshly minted agent key (packages always
// carry a new keypair, so a re-download invalidates the old one).
func (s *Server) updateAgentPublicKey(ctx context.Context, id int64, pub string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET public_key = ? WHERE id = ?`, pub, id)
	return err
}

// sitesList renders a device's ACL for templates.
func sitesList(sites []string) string {
	if len(sites) == 0 {
		return "（无）"
	}
	return strings.Join(sites, ", ")
}
