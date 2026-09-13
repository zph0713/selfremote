package webapp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 装机接入（enrollment）
//
// v0.3 的站点要先在网页上生成密钥、下载一个 zip 再手工搬到目标机器上，太绕。
// v0.4 改成：
//
//	网页建站点 → 得到一次性「安装码」+ 一行安装命令
//	目标机器执行命令 → 脚本下载 agent 二进制 → agent 现场生成自己的密钥对
//	                 → 调 /api/enroll 交安装码换注册（隧道地址 / 服务端公钥 / 网段映射）
//	                 → 写好配置、装成服务、连上
//
// 站点与 server 之间的长期凭据就是这把密钥（Noise IK 双向认证）；安装码只在装机
// 那一次用，可重复生成（换机/重置），有效期内一次性使用。
// ---------------------------------------------------------------------------

const (
	installCodeTTL = 60 * time.Minute
	routeModeKey   = "route_mode" // auto | real | virtual
)

// installCodeAlphabet 去掉了 0/O、1/I/L 这些念不清的字符。
const installCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// newInstallCode 生成 XXXX-XXXX（8 字符 ≈ 40 bit）。
func newInstallCode() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	var b strings.Builder
	for i, x := range buf {
		if i == 4 {
			b.WriteByte('-')
		}
		b.WriteByte(installCodeAlphabet[int(x)%len(installCodeAlphabet)])
	}
	return b.String(), nil
}

// normalizeInstallCode 让用户怎么念/怎么贴都能对上（大小写、空格、缺横线）。
func normalizeInstallCode(raw string) string {
	up := strings.ToUpper(strings.TrimSpace(raw))
	var b strings.Builder
	for _, r := range up {
		if strings.ContainsRune(installCodeAlphabet, r) {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) == 8 {
		return s[:4] + "-" + s[4:]
	}
	return s
}

// enrollLimiter 给公开的 /api/enroll 按 IP 限速（防爆破安装码）。
type enrollLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

const (
	enrollMaxPerWindow = 20
	enrollWindow       = time.Hour
)

func newEnrollLimiter() *enrollLimiter {
	return &enrollLimiter{hits: map[string][]time.Time{}}
}

func (l *enrollLimiter) allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := time.Now().Add(-enrollWindow)
	var keep []time.Time
	for _, t := range l.hits[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	l.hits[ip] = keep
	return len(keep) < enrollMaxPerWindow
}

func (l *enrollLimiter) record(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[ip] = append(l.hits[ip], time.Now())
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

type enrollRequest struct {
	Code      string   `json:"code"`
	PublicKey string   `json:"public_key"`
	Hostname  string   `json:"hostname"`
	Version   string   `json:"version"`
	Routes    []string `json:"routes,omitempty"` // 可选：装机时自报的真实网段
}

type enrollRoute struct {
	Real    string `json:"real"`
	Virtual string `json:"virtual,omitempty"`
}

type enrollResponse struct {
	SiteID          string        `json:"site_id"`
	Name            string        `json:"name"`
	TunnelIP        string        `json:"tunnel_ip"`
	Routes          []enrollRoute `json:"routes"`
	ServerAddr      string        `json:"server_addr"`
	ServerPublicKey string        `json:"server_public_key"`
}

// handleEnroll 是装机脚本唯一需要调用的接口（公开，凭一次性安装码）。
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.enrollLimiter.allowed(ip) {
		jsonError(w, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试")
		return
	}
	var req enrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	code := normalizeInstallCode(req.Code)
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PublicKey))
	if err != nil || len(pub) != 32 {
		jsonError(w, http.StatusBadRequest, "公钥格式错误（需要 base64 的 32 字节 Noise 公钥）")
		return
	}

	ctx := r.Context()
	a, err := s.agentByEnrollCode(ctx, code)
	if err != nil {
		log.Printf("enroll: %v", err)
		jsonError(w, http.StatusInternalServerError, "内部错误")
		return
	}
	if a == nil {
		s.enrollLimiter.record(ip)
		jsonError(w, http.StatusForbidden, "安装码无效或已使用，请在控制面重新生成")
		return
	}
	if !a.EnrollExpires.IsZero() && time.Now().After(a.EnrollExpires) {
		jsonError(w, http.StatusForbidden, "安装码已过期，请在控制面重新生成")
		return
	}

	// 站点网段：建站时填了就用它；没填则要求装机时自报。
	routes := a.Routes
	if len(routes) == 0 {
		parsed, err := parseAgentRoutes(strings.Join(req.Routes, "\n"))
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(parsed) == 0 {
			jsonError(w, http.StatusBadRequest, "该站点尚未配置网段，请在安装命令里加 --routes <CIDR,...>")
			return
		}
		routes, err = s.assignRoutes(ctx, parsed, a)
		if err != nil {
			jsonError(w, http.StatusConflict, err.Error())
			return
		}
		if err := s.setAgentRoutes(ctx, a.ID, routes); err != nil {
			log.Printf("enroll: setAgentRoutes: %v", err)
		}
	}

	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if err := s.bindAgentEnrollment(ctx, a.ID, pubB64); err != nil {
		jsonError(w, http.StatusConflict, "该站点已被接入；如需换机请在控制面重新生成安装码")
		return
	}
	if err := s.syncAgents(ctx); err != nil {
		log.Printf("enroll: syncAgents: %v", err)
	}

	hubPub, err := s.hubPubKey()
	if err != nil {
		log.Printf("enroll: %v", err)
		jsonError(w, http.StatusServiceUnavailable, "服务端公钥还不可用（netinfo/server.json 未就绪）")
		return
	}
	addr := s.serverAddr()
	if addr == "" {
		jsonError(w, http.StatusServiceUnavailable, "服务端地址还不可用，请稍后重试")
		return
	}
	out := enrollResponse{
		SiteID:          a.AgentID,
		Name:            a.Name,
		TunnelIP:        a.TunnelIP,
		ServerAddr:      addr,
		ServerPublicKey: hubPub,
	}
	for _, rt := range routes {
		out.Routes = append(out.Routes, enrollRoute{Real: rt.Real, Virtual: rt.Virtual})
	}
	log.Printf("enroll: 站点 %s 已接入（key %s…, tunnel %s, 来自 %s/%s）",
		a.AgentID, pubB64[:8], a.TunnelIP, req.Hostname, ip)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(out)
}

// handleInstallScript serves the one-line installer, with this server's public
// address baked in as the default.
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	raw, err := assets.ReadFile("assets/install.sh")
	if err != nil {
		http.Error(w, "installer missing", http.StatusInternalServerError)
		return
	}
	base := "http://" + r.Host
	body := strings.ReplaceAll(string(raw), "__SELFREMOTE_SERVER__", base)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(body))
}

// agentDistFiles is the allow-list the installer may fetch.
var agentDistFiles = map[string]bool{
	"agent-linux-amd64":       true,
	"agent-linux-arm64":       true,
	"agent-darwin-amd64":      true,
	"agent-darwin-arm64":      true,
	"agent-windows-amd64.exe": true,
}

// handleAgentDist serves the bundled agent binaries (public: they carry no
// secrets, and installations need them without reaching github).
func (s *Server) handleAgentDist(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("name"))
	if !agentDistFiles[name] {
		http.NotFound(w, r)
		return
	}
	if s.cfg.AgentDistDir == "" {
		http.Error(w, "该控制面镜像未内置 agent 二进制（请用官方镜像，或自行编译）", http.StatusNotFound)
		return
	}
	path := filepath.Join(s.cfg.AgentDistDir, name)
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "agent 二进制不存在", http.StatusNotFound)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.Error(w, "读取失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(st.Size()))
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	http.ServeContent(w, r, name, st.ModTime(), f)
}

// agentByEnrollCode resolves a pending install code to its site.
func (s *Server) agentByEnrollCode(ctx context.Context, code string) (*Agent, error) {
	if code == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+agentCols+` FROM agents a JOIN users u ON u.id = a.user_id WHERE a.enroll_code = ?`, code)
	if err != nil {
		return nil, err
	}
	as, err := scanAgents(rows)
	if err != nil || len(as) == 0 {
		return nil, err
	}
	return &as[0], nil
}
