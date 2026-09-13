package webapp

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed templates/*.html static/* assets/*
var assets embed.FS

// Version is the control-plane version (displayed in the UI).
const Version = "0.4.0"

// Config configures the control-plane server.
type Config struct {
	Listen     string   // e.g. ":8080"
	DSN        string   // MariaDB DSN
	DataDir    string   // dir shared with the hub (clients.json / agents.json / netinfo.json / server.json)
	ServerAddr string   // address embedded into generated client configs; "" = auto-detect
	LANCIDRs   []string // legacy: home LAN subnets used when no site is selected
	TunnelPort int      // hub UDP port (default 28333)

	// v0.3: the hub's control API (status, kick, refresh).
	ServerAPI    string // e.g. "http://server:8770"; empty = feature off
	ServerToken  string // bearer token shared with the hub
	AgentDistDir string // where agent binaries for deployment packages live
}

// Server is the web control plane.
type Server struct {
	cfg           Config
	db            *sql.DB
	pages         map[string]*template.Template
	limit         *loginLimiter
	enrollLimiter *enrollLimiter
}

// New opens the database, applies the schema and prepares templates.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.TunnelPort == 0 {
		cfg.TunnelPort = 28333
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "."
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.AgentDistDir == "" {
		cfg.AgentDistDir = "/agent-dist"
	}
	db, err := openDB(cfg.DSN)
	if err != nil {
		return nil, err
	}
	if err := migrate(ctx, db); err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	s := &Server{cfg: cfg, db: db, limit: newLoginLimiter(), enrollLimiter: newEnrollLimiter()}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	go s.janitor(ctx)
	return s, nil
}

func (s *Server) parseTemplates() error {
	pages := []string{
		"login.html", "register.html", "dashboard.html", "devices.html",
		"device_new.html", "settings.html", "recovery.html", "users.html", "error.html",
		"agents.html", "agent_new.html", "agent_show.html",
	}
	funcs := template.FuncMap{
		"human_bytes": humanBytes,
		"since":       humanSince,
		"ts":          func(t time.Time) string { return t.Format(time.RFC3339) },
		"v":           func() string { return Version },
		"hasSite":     hasSite,
	}
	s.pages = make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		t, err := template.New("base").Funcs(funcs).ParseFS(assets, "templates/base.html", "templates/"+p)
		if err != nil {
			return fmt.Errorf("template %s: %w", p, err)
		}
		s.pages[p] = t
	}
	return nil
}

// Handler builds the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	mux.HandleFunc("GET /register", s.handleRegisterPage)
	mux.HandleFunc("POST /register", s.handleRegisterPost)
	mux.HandleFunc("POST /logout", s.auth(s.handleLogout))

	// 装机接入（公开）：一次性安装码 + 安装脚本 + agent 二进制。
	mux.HandleFunc("POST /api/enroll", s.handleEnroll)
	mux.HandleFunc("GET /install.sh", s.handleInstallScript)
	mux.HandleFunc("GET /agent-dist/{name}", s.handleAgentDist)

	mux.HandleFunc("GET /{$}", s.auth(s.handleDashboard))
	mux.HandleFunc("GET /settings", s.auth(s.handleSettings))
	mux.HandleFunc("POST /settings/mfa/begin", s.auth(s.handleMFABegin))
	mux.HandleFunc("GET /settings/mfa/qr", s.auth(s.handleMFAQR))
	mux.HandleFunc("POST /settings/mfa/confirm", s.auth(s.handleMFAConfirm))

	mux.HandleFunc("GET /devices", s.authMFA(s.handleDevices))
	mux.HandleFunc("GET /devices/new", s.authMFA(s.handleDeviceNew))
	mux.HandleFunc("POST /devices/new", s.authMFA(s.handleDeviceCreate))
	mux.HandleFunc("POST /devices/import", s.authMFA(s.handleDeviceImport))
	mux.HandleFunc("POST /devices/revoke", s.authMFA(s.handleDeviceRevoke))
	mux.HandleFunc("POST /devices/sites", s.authMFA(s.handleDeviceSites))

	mux.HandleFunc("GET /agents", s.authMFA(s.handleAgents))
	mux.HandleFunc("GET /agents/new", s.authMFA(s.handleAgentNew))
	mux.HandleFunc("POST /agents/new", s.authMFA(s.handleAgentCreate))
	mux.HandleFunc("GET /agents/{id}", s.authMFA(s.handleAgentShow))
	mux.HandleFunc("POST /agents/{id}/state", s.authMFA(s.handleAgentState))
	mux.HandleFunc("POST /agents/{id}/kick", s.authMFA(s.handleAgentKick))
	mux.HandleFunc("POST /agents/{id}/rotate-mfa", s.authMFA(s.handleAgentRotateMFA))
	mux.HandleFunc("POST /agents/{id}/revoke", s.authMFA(s.handleAgentRevoke))
	mux.HandleFunc("POST /agents/{id}/package", s.authMFA(s.handleAgentPackage))
	mux.HandleFunc("POST /agents/{id}/code", s.authMFA(s.handleAgentNewCode))
	mux.HandleFunc("POST /agents/route-mode", s.authMFA(s.handleRouteMode))

	mux.HandleFunc("GET /users", s.authAdmin(s.handleUsers))
	mux.HandleFunc("POST /users/new", s.authAdmin(s.handleUserCreate))

	return logRequests(mux)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s (%v)", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

// janitor periodically removes expired sessions and expiring CSRF state.
func (s *Server) janitor(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.purgeExpiredSessions(ctx); err != nil {
				log.Printf("janitor: %v", err)
			}
		}
	}
}

// --------------------------------------------------------------- auth glue

type ctxKey int

const (
	userKey ctxKey = iota
	sessKey
)

func userFrom(r *http.Request) *User {
	u, _ := r.Context().Value(userKey).(*User)
	return u
}

func sessFrom(r *http.Request) *Session {
	s, _ := r.Context().Value(sessKey).(*Session)
	return s
}

type authedHandler func(http.ResponseWriter, *http.Request, *User)

func (s *Server) withSession(next authedHandler, requireMFA, requireAdmin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		sid := ""
		if err == nil {
			sid = cookie.Value
		}
		u, sess, err := s.sessionUser(r.Context(), sid)
		if err != nil {
			log.Printf("session lookup: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if u == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if requireAdmin && !u.IsAdmin {
			http.Error(w, "需要管理员权限", http.StatusForbidden)
			return
		}
		if requireMFA && !u.TOTPEnabled {
			http.Redirect(w, r, "/settings?enroll=1", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), userKey, u)
		ctx = context.WithValue(ctx, sessKey, sess)
		next(w, r.WithContext(ctx), u)
	}
}

func (s *Server) auth(next authedHandler) http.HandlerFunc { return s.withSession(next, false, false) }
func (s *Server) authMFA(next authedHandler) http.HandlerFunc {
	return s.withSession(next, true, false)
}
func (s *Server) authAdmin(next authedHandler) http.HandlerFunc {
	return s.withSession(next, false, true)
}

// checkCSRF compares the submitted token with the session's.
func checkCSRF(r *http.Request, sess *Session) bool {
	return sess != nil && r.FormValue("csrf") == sess.CSRF
}

// --------------------------------------------------------------- rendering

type pageData struct {
	Title       string
	User        *User
	CSRF        string
	Flash       string
	Error       string
	Version     string
	AutoRefresh bool
	Data        any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data pageData) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "template not found: "+page, http.StatusInternalServerError)
		return
	}
	if data.CSRF == "" {
		if sess := sessFrom(r); sess != nil {
			data.CSRF = sess.CSRF
		}
	}
	if data.User == nil {
		data.User = userFrom(r)
	}
	data.Version = Version
	if data.Flash == "" {
		data.Flash = r.URL.Query().Get("msg")
	}
	if data.Error == "" {
		data.Error = r.URL.Query().Get("err")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}

// redirectMsg redirects with a flash message (msg) or an error (err).
func redirectMsg(w http.ResponseWriter, r *http.Request, path, msg, errMsg string) {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	switch {
	case msg != "":
		path += sep + "msg=" + urlQueryEscape(msg)
	case errMsg != "":
		path += sep + "err=" + urlQueryEscape(errMsg)
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// --------------------------------------------------------------- data files

// readJSONFile loads one of the gateway-published JSON files, returning zero
// values when it does not exist yet.
func (s *Server) readJSONFile(name string, v any) (time.Time, error) {
	path := filepath.Join(s.cfg.DataDir, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", name, err)
	}
	return time.Now(), nil
}

// syncRegistries rewrites clients.json and agents.json from the database
// (atomic rename), so the hub picks changes up on its next poll.
func (s *Server) syncRegistries(ctx context.Context) error {
	if err := s.syncClients(ctx); err != nil {
		return err
	}
	return s.syncAgents(ctx)
}

// syncClients writes the client registry (what clients may connect, from
// where, and which sites they may reach).
func (s *Server) syncClients(ctx context.Context) error {
	s.backfillTunnelIPs(ctx)
	rows, err := s.registryRows(ctx)
	if err != nil {
		return err
	}
	clients := make([]registryClient, 0, len(rows))
	for _, r := range rows {
		clients = append(clients, registryClient{
			Name:       r.DeviceName,
			User:       r.Username,
			PublicKey:  r.PublicKey,
			TOTPSecret: r.TOTPSecret,
			TunnelIP:   r.TunnelIP,
			Agents:     r.Sites,
		})
	}
	raw, err := json.MarshalIndent(registryFile{Clients: clients}, "", "  ")
	if err != nil {
		return err
	}
	if err := s.writeDataFile("clients.json", raw); err != nil {
		return err
	}
	log.Printf("registry synced: %d client(s)", len(clients))
	return nil
}

// syncAgents writes the agent registry (which sites the hub serves, their
// prefixes, MFA secrets and enable switches).
func (s *Server) syncAgents(ctx context.Context) error {
	agents, err := s.allAgents(ctx)
	if err != nil {
		return err
	}
	out := agentRegistryFile{Agents: make([]registryAgent, 0, len(agents))}
	for _, a := range agents {
		if a.PublicKey == "" {
			continue // 还没接入（等待安装脚本 enroll）：不发布给 server
		}
		routes := make([]registryAgentRoute, 0, len(a.Routes))
		for _, r := range a.Routes {
			routes = append(routes, registryAgentRoute{Real: r.Real, Virtual: r.Virtual})
		}
		out.Agents = append(out.Agents, registryAgent{
			ID:         a.AgentID,
			Name:       a.Name,
			PublicKey:  a.PublicKey,
			Enabled:    a.Enabled,
			TOTPSecret: a.TOTPSecret,
			TunnelIP:   a.TunnelIP,
			Routes:     routes,
		})
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := s.writeDataFile("agents.json", raw); err != nil {
		return err
	}
	log.Printf("agent registry synced: %d site(s)", len(out.Agents))
	return nil
}

// writeDataFile writes one of the shared registries atomically.
func (s *Server) writeDataFile(name string, raw []byte) error {
	tmp := filepath.Join(s.cfg.DataDir, name+".tmp")
	final := filepath.Join(s.cfg.DataDir, name)
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// hasSite reports whether a device's ACL contains an agent id (templates).
func hasSite(sites []string, id string) bool {
	for _, s := range sites {
		if s == id {
			return true
		}
	}
	return false
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

func humanSince(ts string) string {
	if ts == "" {
		return "—"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d 秒前", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d 小时前", int(d.Hours()))
	}
	return fmt.Sprintf("%d 天前", int(d.Hours()/24))
}

// urlQueryEscape escapes a string for use in a query parameter.
func urlQueryEscape(s string) string {
	return strings.ReplaceAll(template.URLQueryEscaper(s), "+", "%20")
}
