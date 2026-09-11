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
	Name       string `json:"name"`
	User       string `json:"user,omitempty"`
	PublicKey  string `json:"public_key"`
	TOTPSecret string `json:"totp_secret,omitempty"`
}

type registryFile struct {
	Clients []registryClient `json:"clients"`
}

// gatewayPubKey derives the gateway's static public key from gateway.json in
// the shared data dir (the gateway itself is the only writer of that file).
func (s *Server) gatewayPubKey() (string, error) {
	raw, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "gateway.json"))
	if err != nil {
		return "", fmt.Errorf("读取 gateway.json 失败（网关还没初始化？）")
	}
	var cfg struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", fmt.Errorf("gateway.json 解析失败")
	}
	priv, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil || len(priv) != 32 {
		return "", fmt.Errorf("gateway.json: private_key 无效")
	}
	var in, out [32]byte
	copy(in[:], priv)
	curve25519.ScalarBaseMult(&out, &in)
	return base64.StdEncoding.EncodeToString(out[:]), nil
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

	// Live overlay from the gateway's status file (match by device name).
	var st statusFile
	_, _ = s.readJSONFile("status.json", &st)
	online := map[string]bool{}
	for _, p := range st.Peers {
		if p.Connected && p.Authed {
			online[p.Name] = true
		}
	}

	s.render(w, r, "devices.html", pageData{
		Title: "客户端密钥",
		Data: map[string]any{
			"Devices": devs,
			"Online":  online,
			"IsAdmin": u.IsAdmin,
		},
	})
}

func (s *Server) handleDeviceNew(w http.ResponseWriter, r *http.Request, u *User) {
	// Pre-flight: report problems before the user fills the form.
	var problems []string
	if _, err := s.gatewayPubKey(); err != nil {
		problems = append(problems, err.Error())
	}
	if s.serverAddr() == "" {
		problems = append(problems, "无法确定服务端地址：请等网关运行几秒生成 netinfo.json，或在配置里显式设置 SERVER_ADDR")
	}
	s.render(w, r, "device_new.html", pageData{
		Title: "生成客户端密钥",
		Data: map[string]any{
			"Problems": problems,
			"Server":   s.serverAddr(),
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

	gwPub, err := s.gatewayPubKey()
	if err != nil {
		redirectMsg(w, r, "/devices/new", "", err.Error())
		return
	}
	addr := s.serverAddr()
	if addr == "" {
		redirectMsg(w, r, "/devices/new", "", "无法确定服务端地址")
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

	routes := s.cfg.LANCIDRs
	if len(routes) == 0 {
		routes = []string{"192.168.1.0/24"}
	}
	cfgJSON, err := json.MarshalIndent(map[string]any{
		"server":            addr,
		"private_key":       privB64,
		"server_public_key": gwPub,
		"tunnel_cidr":       "10.77.0.2/24",
		"routes":            routes,
	}, "", "  ")
	if err != nil {
		redirectMsg(w, r, "/devices/new", "", "内部错误")
		return
	}

	// Record the device first: if this fails there is no stale download.
	if err := s.addDevice(ctx, u.ID, name, pubB64); err != nil {
		redirectMsg(w, r, "/devices/new", "", "保存设备失败（名称可能重复）")
		return
	}
	if err := s.syncRegistry(ctx); err != nil {
		log.Printf("sync registry: %v", err)
	}
	log.Printf("user %s: device %q created", u.Username, name)

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
	if err := s.addDevice(ctx, u.ID, name, pub); err != nil {
		redirectMsg(w, r, "/devices/new", "", "保存设备失败（名称或公钥可能重复）")
		return
	}
	if err := s.syncRegistry(ctx); err != nil {
		log.Printf("sync registry: %v", err)
	}
	log.Printf("user %s: device %q imported", u.Username, name)
	redirectMsg(w, r, "/devices", "已导入 "+name+"：用那台设备现有的密钥文件连接即可（连接时仍需动态码）", "")
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
	if err := s.syncRegistry(ctx); err != nil {
		log.Printf("sync registry: %v", err)
	}
	log.Printf("user %s: device %q (%s) revoked", u.Username, dev.Name, dev.Username)
	redirectMsg(w, r, "/devices", "已吊销设备 "+dev.Name+"（在线会话会在数秒内被断开）", "")
}
