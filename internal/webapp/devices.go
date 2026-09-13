package webapp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"

	"selfremote/internal/keyfile"
)

// registryClient mirrors tunnel.RegistryClient (kept in sync manually to keep
// the webapp independent of the tunnel package's internals).
type registryClient struct {
	Name       string   `json:"name"`
	User       string   `json:"user,omitempty"`
	PublicKey  string   `json:"public_key"`
	TOTPSecret string   `json:"totp_secret,omitempty"`
	TunnelIP   string   `json:"tunnel_ip,omitempty"`
	Agents     []string `json:"agents,omitempty"` // ACL: agent ids this client may reach
}

type registryFile struct {
	Clients []registryClient `json:"clients"`
}

// registryAgent mirrors tunnel.RegistryAgent.
type registryAgent struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	PublicKey  string               `json:"public_key"`
	Enabled    bool                 `json:"enabled"`
	TOTPSecret string               `json:"totp_secret,omitempty"`
	TunnelIP   string               `json:"tunnel_ip,omitempty"`
	Routes     []registryAgentRoute `json:"routes,omitempty"`
}

type registryAgentRoute struct {
	Real    string `json:"real"`
	Virtual string `json:"virtual,omitempty"`
}

type agentRegistryFile struct {
	Agents []registryAgent `json:"agents"`
}

// hubPubKey derives the hub's static public key from server.json in the shared
// data dir (the hub itself is the only writer of that file). A v0.2 install
// that still runs the standalone gateway keeps working through gateway.json.
func (s *Server) hubPubKey() (string, error) {
	for _, name := range []string{"server.json", "gateway.json"} {
		raw, err := os.ReadFile(filepath.Join(s.cfg.DataDir, name))
		if err != nil {
			continue
		}
		var cfg struct {
			PrivateKey string `json:"private_key"`
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return "", fmt.Errorf("%s 解析失败", name)
		}
		priv, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
		if err != nil || len(priv) != 32 {
			return "", fmt.Errorf("%s: private_key 无效", name)
		}
		var in, out [32]byte
		copy(in[:], priv)
		curve25519.ScalarBaseMult(&out, &in)
		return base64.StdEncoding.EncodeToString(out[:]), nil
	}
	return "", fmt.Errorf("读取服务端公钥失败（server.json 还没生成？）")
}

// serverAddr returns the address clients should dial: the configured value,
// or auto-detected from netinfo.json (first global IPv6, else first public
// IPv4) with the tunnel port appended.
func (s *Server) serverAddr() string {
	if s.cfg.ServerAddr != "" {
		return ensurePort(s.cfg.ServerAddr, s.cfg.TunnelPort)
	}
	var ni netInfoFile
	if _, err := s.readJSONFile("netinfo.json", &ni); err != nil {
		return ""
	}
	var v6, v4 string
	for _, ifc := range ni.Interfaces {
		for _, a := range ifc.Addresses {
			ip, _, err := net.ParseCIDR(a)
			if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
				continue
			}
			if ip.To4() == nil {
				if v6 == "" {
					v6 = ip.String()
				}
			} else if v4 == "" {
				v4 = ip.String()
			}
		}
	}
	host := v6
	if host == "" {
		host = v4
	}
	if host == "" {
		return ""
	}
	return ensurePort(host, s.cfg.TunnelPort)
}

func ensurePort(addr string, port int) string {
	if strings.HasPrefix(addr, "[") {
		if strings.Contains(addr, "]:") {
			return addr
		}
		return fmt.Sprintf("%s:%d", addr, port)
	}
	if strings.Contains(addr, ":") { // bare IPv6 or host:port
		if strings.Count(addr, ":") == 1 {
			return addr
		}
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

func safeFilename(name string) string {
	var b strings.Builder
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			b.WriteRune(c)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// ---------------------------------------------------------------- handlers

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	var (
		devs []Device
		err  error
	)
	if u.IsAdmin {
		devs, err = s.allDevices(ctx)
	} else {
		devs, err = s.devicesByUser(ctx, u.ID)
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Live overlay: prefer the hub's control API; fall back to the status file
	// published by a standalone gateway (v0.2 installs).
	online := map[string]bool{}
	hubReachable := false
	if view := s.hubView(ctx); view.Reachable {
		hubReachable = true
		for _, p := range view.Status.Peers {
			if p.Role == "client" && p.Connected && p.Authed {
				online[p.Name] = true
			}
		}
	} else {
		var st statusFile
		_, _ = s.readJSONFile("status.json", &st)
		for _, p := range st.Peers {
			if p.Connected && p.Authed {
				online[p.Name] = true
			}
		}
	}

	agents, err := s.allAgents(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "devices.html", pageData{
		Title: "客户端密钥",
		Data: map[string]any{
			"Devices":      devs,
			"Online":       online,
			"IsAdmin":      u.IsAdmin,
			"Agents":       agents,
			"HubReachable": hubReachable,
		},
	})
}

func (s *Server) handleDeviceNew(w http.ResponseWriter, r *http.Request, u *User) {
	// Pre-flight: report problems before the user fills the form.
	var problems []string
	if _, err := s.hubPubKey(); err != nil {
		problems = append(problems, err.Error())
	}
	if s.serverAddr() == "" {
		problems = append(problems, "无法确定服务端地址：请等服务端运行几秒生成 netinfo.json，或在配置里显式设置 SERVER_ADDR")
	}
	var agents []Agent
	if u.IsAdmin {
		agents, _ = s.allAgents(r.Context())
	} else {
		agents, _ = s.agentsByUser(r.Context(), u.ID)
	}
	enabled := make([]Agent, 0, len(agents))
	for _, a := range agents {
		if a.Enabled {
			enabled = append(enabled, a)
		}
	}
	if len(enabled) == 0 {
		problems = append(problems, "还没有可用的站点：先到「站点 Agent」页添加一个站点并下载部署包")
	}
	s.render(w, r, "device_new.html", pageData{
		Title: "生成客户端密钥",
		Data: map[string]any{
			"Problems": problems,
			"Server":   s.serverAddr(),
			"Agents":   enabled,
			"Routes":   s.cfg.LANCIDRs,
		},
	})
}

func (s *Server) handleDeviceCreate(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/devices/new", "", "表单校验失败，请重试")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	pass := r.FormValue("passphrase")
	confirm := r.FormValue("confirm")
	if err := validDeviceName(name); err != nil {
		redirectMsg(w, r, "/devices/new", "", err.Error())
		return
	}
	if len(pass) < 10 {
		redirectMsg(w, r, "/devices/new", "", "密钥文件密码至少 10 位")
		return
	}
	if pass != confirm {
		redirectMsg(w, r, "/devices/new", "", "两次输入的密钥文件密码不一致")
		return
	}

	hubPub, err := s.hubPubKey()
	if err != nil {
		redirectMsg(w, r, "/devices/new", "", err.Error())
		return
	}
	addr := s.serverAddr()
	if addr == "" {
		redirectMsg(w, r, "/devices/new", "", "无法确定服务端地址")
		return
	}

	// Which sites may this device reach? Their published prefixes become the
	// client's routes; the hubs enforces the same list as an ACL.
	selected := r.Form["sites"]
	agents, err := s.allAgents(ctx)
	if err != nil {
		redirectMsg(w, r, "/devices/new", "", "内部错误")
		return
	}
	var routes []string
	var acl []string
	for _, id := range selected {
		for _, a := range agents {
			if a.AgentID != id {
				continue
			}
			if !a.Enabled {
				continue
			}
			acl = append(acl, a.AgentID)
			for _, rt := range a.Routes {
				routes = append(routes, rt.Effective())
			}
		}
	}
	if len(acl) == 0 {
		redirectMsg(w, r, "/devices/new", "", "请至少勾选一个可访问站点")
		return
	}

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	kp, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		redirectMsg(w, r, "/devices/new", "", "生成密钥失败")
		return
	}
	privB64 := base64.StdEncoding.EncodeToString(kp.Private)
	pubB64 := base64.StdEncoding.EncodeToString(kp.Public)

	tunnelIP, err := s.allocClientIP(ctx)
	if err != nil {
		redirectMsg(w, r, "/devices/new", "", err.Error())
		return
	}

	cfgJSON, err := json.MarshalIndent(map[string]any{
		"server":            addr,
		"private_key":       privB64,
		"server_public_key": hubPub,
		"tunnel_cidr":       tunnelIP + "/24",
		"routes":            routes,
	}, "", "  ")
	if err != nil {
		redirectMsg(w, r, "/devices/new", "", "内部错误")
		return
	}

	// Record the device first: if this fails there is no stale download.
	if err := s.addDevice(ctx, u.ID, name, pubB64, tunnelIP, acl); err != nil {
		redirectMsg(w, r, "/devices/new", "", "保存设备失败（名称可能重复）")
		return
	}
	if err := s.syncRegistries(ctx); err != nil {
		log.Printf("sync registries: %v", err)
	}
	log.Printf("user %s: device %q created (tunnel %s, sites %v)", u.Username, name, tunnelIP, acl)

	env, err := keyfile.Seal(cfgJSON, pass)
	if err != nil {
		redirectMsg(w, r, "/devices", "", "加密密钥文件失败")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", "client-"+safeFilename(name)+".srkey"))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(env)
}

// handleDeviceSites updates which sites a device may reach. The change is
// enforced by the hub right away (ACL), but the client's routes are baked into
// its key file — if a newly granted site was not in the original routes, the
// device needs a freshly downloaded configuration.
func (s *Server) handleDeviceSites(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/devices", "", "表单校验失败，请重试")
		return
	}
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		redirectMsg(w, r, "/devices", "", "参数错误")
		return
	}
	dev, err := s.deviceByID(ctx, id)
	if err != nil || dev == nil {
		redirectMsg(w, r, "/devices", "", "设备不存在")
		return
	}
	if dev.UserID != u.ID && !u.IsAdmin {
		http.Error(w, "无权操作他人设备", http.StatusForbidden)
		return
	}
	agents, err := s.allAgents(ctx)
	if err != nil {
		redirectMsg(w, r, "/devices", "", "内部错误")
		return
	}
	selected := r.Form["sites"]
	var acl []string
	allowed := map[string]bool{}
	for _, a := range agents {
		allowed[a.AgentID] = true
	}
	for _, id := range selected {
		if allowed[id] {
			acl = append(acl, id)
		}
	}
	if len(acl) == 0 {
		redirectMsg(w, r, "/devices", "", "请至少保留一个可访问站点（要完全收回权限请直接吊销设备）")
		return
	}
	if err := s.setDeviceSites(ctx, id, acl); err != nil {
		redirectMsg(w, r, "/devices", "", "更新失败")
		return
	}
	if err := s.syncRegistries(ctx); err != nil {
		log.Printf("sync registries: %v", err)
	}
	log.Printf("user %s: device %q sites -> %v", u.Username, dev.Name, acl)
	redirectMsg(w, r, "/devices",
		fmt.Sprintf("已更新 %s 的站点权限（立即生效）；如果新增了站点，请为该设备重新生成密钥文件（旧文件里的路由不含新站点）", dev.Name), "")
}

func (s *Server) handleDeviceImport(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/devices/new", "", "表单校验失败，请重试")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	pub := strings.TrimSpace(r.FormValue("public_key"))
	if err := validDeviceName(name); err != nil {
		redirectMsg(w, r, "/devices/new", "", err.Error())
		return
	}
	key, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(key) != 32 {
		redirectMsg(w, r, "/devices/new", "", "公钥格式不正确：应为 sr genkey 输出的 public_key（32 字节 base64）")
		return
	}
	sites := r.Form["sites"]
	if len(sites) == 0 {
		redirectMsg(w, r, "/devices/new", "", "请至少勾选一个可访问站点")
		return
	}
	tunnelIP, err := s.allocClientIP(ctx)
	if err != nil {
		redirectMsg(w, r, "/devices/new", "", err.Error())
		return
	}
	if err := s.addDevice(ctx, u.ID, name, pub, tunnelIP, sites); err != nil {
		redirectMsg(w, r, "/devices/new", "", "保存设备失败（名称或公钥可能重复）")
		return
	}
	if err := s.syncRegistries(ctx); err != nil {
		log.Printf("sync registries: %v", err)
	}
	log.Printf("user %s: device %q imported (tunnel %s, sites %v)", u.Username, name, tunnelIP, sites)
	redirectMsg(w, r, "/devices", "已导入 "+name+"：用那台设备现有的密钥文件连接即可（若原文件里的路由不含新站点，请重新生成）", "")
}

func (s *Server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/devices", "", "表单校验失败，请重试")
		return
	}
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		redirectMsg(w, r, "/devices", "", "参数错误")
		return
	}
	dev, err := s.deviceByID(ctx, id)
	if err != nil || dev == nil {
		redirectMsg(w, r, "/devices", "", "设备不存在")
		return
	}
	if dev.UserID != u.ID && !u.IsAdmin {
		http.Error(w, "无权操作他人设备", http.StatusForbidden)
		return
	}
	if err := s.deleteDevice(ctx, id); err != nil {
		redirectMsg(w, r, "/devices", "", "吊销失败")
		return
	}
	if err := s.syncRegistries(ctx); err != nil {
		log.Printf("sync registries: %v", err)
	}
	log.Printf("user %s: device %q (%s) revoked", u.Username, dev.Name, dev.Username)
	redirectMsg(w, r, "/devices", "已吊销设备 "+dev.Name+"（在线会话会在数秒内被断开）", "")
}
