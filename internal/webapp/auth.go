package webapp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const sessionCookie = "sr_session"
const sessionTTL = 7 * 24 * time.Hour

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is not recoverable
	}
	return hex.EncodeToString(b)
}

// hashPassword returns an encoded argon2id hash:
// argon2id$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := argon2.IDKey([]byte(pw), salt, 3, 64*1024, 4, 32)
	return fmt.Sprintf("argon2id$m=65536,t=3,p=4$%s$%s",
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(h)), nil
}

func verifyPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "argon2id" {
		return false
	}
	var m, t, p int
	if _, err := fmt.Sscanf(parts[1], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// loginLimiter throttles password guessing per username.
type loginLimiter struct {
	mu sync.Mutex
	m  map[string][]time.Time
}

const (
	loginWindow   = 5 * time.Minute
	loginMaxFails = 5
)

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{m: map[string][]time.Time{}}
}

func (l *loginLimiter) allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var kept []time.Time
	for _, ts := range l.m[key] {
		if now.Sub(ts) < loginWindow {
			kept = append(kept, ts)
		}
	}
	l.m[key] = kept
	return len(kept) < loginMaxFails
}

func (l *loginLimiter) record(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.m[key] = append(l.m[key], time.Now())
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, key)
}

func setSessionCookie(w http.ResponseWriter, sid string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sid, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Expires: expires, MaxAge: int(time.Until(expires).Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// validUsername allows 3-32 chars of [a-zA-Z0-9_-].
func validUsername(name string) error {
	if len(name) < 3 || len(name) > 32 {
		return fmt.Errorf("用户名需为 3-32 个字符")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return fmt.Errorf("用户名只能包含字母、数字、下划线、连字符")
		}
	}
	return nil
}

func validPassword(pw string) error {
	if len(pw) < 8 {
		return fmt.Errorf("密码至少 8 位")
	}
	return nil
}

func validDeviceName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("设备名称需为 1-64 个字符")
	}
	for _, c := range name {
		if c < 0x20 || c == '/' || c == '\\' || c == '"' {
			return fmt.Errorf("设备名称包含不允许的字符")
		}
	}
	return nil
}

// tryRecovery consumes a recovery code (single use).
func (s *Server) tryRecovery(ctx context.Context, u *User, code string) bool {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))))
	ok, err := s.useRecoveryCode(ctx, u.ID, hex.EncodeToString(sum[:]))
	if err != nil {
		log.Printf("recovery: %v", err)
		return false
	}
	if ok {
		log.Printf("user %s logged in with a recovery code", u.Username)
	}
	return ok
}

// ---------------------------------------------------------------- handlers

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		if u, _, _ := s.sessionUser(r.Context(), c.Value); u != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	n, _ := s.countUsers(r.Context())
	s.render(w, r, "login.html", pageData{
		Title: "登录",
		Data:  map[string]any{"NeedSetup": n == 0},
	})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	code := strings.TrimSpace(r.FormValue("code"))

	fail := func(msg string) {
		s.render(w, r, "login.html", pageData{Title: "登录", Error: msg, Data: map[string]any{}})
	}
	if !s.limit.allowed(username) {
		fail("尝试次数过多，请 5 分钟后再试")
		return
	}
	u, err := s.userByName(ctx, username)
	if err != nil {
		log.Printf("login: %v", err)
		fail("内部错误")
		return
	}
	if u == nil || !verifyPassword(u.PasswordHash, password) {
		s.limit.record(username)
		fail("用户名或密码错误")
		return
	}
	if u.TOTPEnabled {
		if code == "" {
			fail("此账号已启用两步验证，请输入 Google Authenticator 动态验证码")
			return
		}
		if !verifyTOTP(u.TOTPSecret, code) && !s.tryRecovery(ctx, u, code) {
			s.limit.record(username)
			fail("动态验证码错误")
			return
		}
	}
	s.limit.reset(username)

	sid, csrf := randomHex(16), randomHex(16)
	expires := time.Now().Add(sessionTTL)
	if err := s.createSession(ctx, u.ID, sid, csrf, expires); err != nil {
		log.Printf("create session: %v", err)
		fail("内部错误")
		return
	}
	setSessionCookie(w, sid, expires)
	log.Printf("user %s logged in", u.Username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, u *User) {
	if sess := sessFrom(r); sess != nil {
		_ = s.deleteSession(r.Context(), sess.ID)
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	n, err := s.countUsers(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, "register.html", pageData{Title: "创建管理员账号", Data: map[string]any{}})
}

func (s *Server) handleRegisterPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	n, err := s.countUsers(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	fail := func(msg string) {
		s.render(w, r, "register.html", pageData{Title: "创建管理员账号", Error: msg, Data: map[string]any{}})
	}
	if err := validUsername(username); err != nil {
		fail(err.Error())
		return
	}
	if err := validPassword(password); err != nil {
		fail(err.Error())
		return
	}
	if password != confirm {
		fail("两次输入的密码不一致")
		return
	}
	hash, err := hashPassword(password)
	if err != nil {
		fail("内部错误")
		return
	}
	uid, err := s.createUser(ctx, username, hash, true)
	if err != nil {
		fail("创建失败（用户名可能已存在）")
		return
	}

	// Auto-login, then send the admin straight to MFA enrollment.
	sid, csrf := randomHex(16), randomHex(16)
	expires := time.Now().Add(sessionTTL)
	if err := s.createSession(ctx, uid, sid, csrf, expires); err != nil {
		fail("内部错误")
		return
	}
	setSessionCookie(w, sid, expires)
	log.Printf("admin user %s created", username)
	// 首次部署：init.sh 预置的「本机站点」需要有个属主，管理员一出现就导入。
	if err := s.ImportPreprovision(ctx); err != nil {
		log.Printf("preprovision: %v", err)
	}
	redirectMsg(w, r, "/settings?enroll=1", "管理员账号已创建，请先绑定 Google Authenticator", "")
}

// handleUserCreate creates additional (non-admin) accounts; admin only.
func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request, u *User) {
	if !checkCSRF(r, sessFrom(r)) {
		redirectMsg(w, r, "/users", "", "表单校验失败，请重试")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if err := validUsername(username); err != nil {
		redirectMsg(w, r, "/users", "", err.Error())
		return
	}
	if err := validPassword(password); err != nil {
		redirectMsg(w, r, "/users", "", err.Error())
		return
	}
	hash, err := hashPassword(password)
	if err != nil {
		redirectMsg(w, r, "/users", "", "内部错误")
		return
	}
	if _, err := s.createUser(r.Context(), username, hash, false); err != nil {
		redirectMsg(w, r, "/users", "", "创建失败（用户名可能已存在）")
		return
	}
	log.Printf("user %s created by %s", username, u.Username)
	redirectMsg(w, r, "/users", "账号 "+username+" 已创建", "")
}
