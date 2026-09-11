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

//go:embed templates/*.html static/*
var assets embed.FS

// Version is the control-plane version (displayed in the UI).
const Version = "0.2.0"

// Config configures the control-plane server.
type Config struct {
	Listen     string   // e.g. ":8080"
	DSN        string   // MariaDB DSN
	DataDir    string   // dir shared with the gateway (clients.json / status.json / netinfo.json / gateway.json)
	ServerAddr string   // address embedded into generated client configs; "" = auto-detect
	LANCIDRs   []string // home LAN subnets for generated client configs
	TunnelPort int      // gateway UDP port (default 28333)
}

// Server is the web control plane.
type Server struct {
	cfg   Config
	db    *sql.DB
	pages map[string]*template.Template
	limit *loginLimiter
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
	db, err := openDB(cfg.DSN)
	if err != nil {
		return nil, err
	}
	if err := migrate(ctx, db); err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	s := &Server{cfg: cfg, db: db, limit: newLoginLimiter()}
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
	}
	funcs := template.FuncMap{
		"human_bytes": humanBytes,
		"since":       humanSince,
		"v":           func() string { return Version },
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

// syncRegistry rewrites clients.json from the database (atomic rename), so
// the gateway picks changes up on its next poll.
func (s *Server) syncRegistry(ctx context.Context) error {
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
		})
	}
	raw, err := json.MarshalIndent(registryFile{Clients: clients}, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.cfg.DataDir, "clients.json.tmp")
	final := filepath.Join(s.cfg.DataDir, "clients.json")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	log.Printf("registry synced: %d client(s)", len(clients))
	return nil
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
