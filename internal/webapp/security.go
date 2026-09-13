package webapp

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 安全辅助：跨站请求防护、按来源限速、初次部署令牌
// ---------------------------------------------------------------------------

// sameOriginGuard 拒绝跨站的「写」请求。
//
// 为什么需要：登录/注册这类 POST 在拿到会话之前就已经生效，会话 Cookie 的
// SameSite 帮不上忙（Cookie 是响应才种下的）。浏览器在跨站 POST 时一定会带
// Origin（旧浏览器至少带 Referer），所以：带了且与本机 Host 不符 → 拒绝；
// 两个头都没有 = 非浏览器客户端（curl / 脚本）→ 放行，保持可自动化。
func (s *Server) sameOriginGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" {
				origin = refererOrigin(r.Header.Get("Referer"))
			}
			if origin != "" && !sameOriginHost(origin, r.Host) {
				s.logf(r, "跨站 POST 被拒绝：origin=%s host=%s", origin, r.Host)
				http.Error(w, "跨站请求被拒绝", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func refererOrigin(ref string) string {
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// sameOriginHost 比较 origin 与请求 Host。
//
// 端口只在两边都写了的时候才比较：反向代理（nginx 的 $host）可能把端口丢掉，
// 而浏览器一定带端口 —— 只比主机名已经足够挡住跨站，少一层误伤。
func sameOriginHost(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	oh, op := splitHostPort(u.Host)
	rh, rp := splitHostPort(host)
	if oh != rh {
		return false
	}
	if op != "" && rp != "" && op != rp {
		return false
	}
	return true
}

func splitHostPort(h string) (host, port string) {
	if hp, p, err := net.SplitHostPort(h); err == nil {
		host, port = hp, p
	} else {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	// 80/443 视为「无端口」
	if port == "80" || port == "443" {
		port = ""
	}
	return host, port
}

func (s *Server) logf(r *http.Request, format string, args ...any) {
	prefix := ""
	if r != nil {
		prefix = clientIP(r) + " "
	}
	log.Printf("%s"+format, append([]any{prefix}, args...)...)
}

// ---------------------------------------------------------------------------
// 按来源的限速器（和按用户名的限速互补）
// ---------------------------------------------------------------------------

type ipLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	window time.Duration
	max    int
}

func newIPLimiter(limit int, window time.Duration) *ipLimiter {
	return &ipLimiter{hits: map[string][]time.Time{}, window: window, max: limit}
}

func (l *ipLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := time.Now().Add(-l.window)
	var kept []time.Time
	for _, t := range l.hits[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	l.hits[key] = kept
	return len(kept) < l.max
}

func (l *ipLimiter) record(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key] = append(l.hits[key], time.Now())
}

// ---------------------------------------------------------------------------
// 初次部署令牌：控制面在管理员出现之前不该被人抢先注册
// ---------------------------------------------------------------------------

func (s *Server) bootstrapTokenPath() string {
	return filepath.Join(s.cfg.DataDir, "bootstrap-token")
}

// loadBootstrapToken 读取 init.sh 生成的部署令牌（没有则返回空）。
func (s *Server) loadBootstrapToken() string {
	raw, err := os.ReadFile(s.bootstrapTokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// registrationAllowed 判断这次注册请求是否被允许：
//   - 已经有人注册过 → 走正常登录（注册页会直接跳转）
//   - 有部署令牌文件 → 必须带对令牌
//   - 没有令牌文件 → 只允许来自内网/本机的请求（开发与 e2e 场景）
func (s *Server) registrationAllowed(r *http.Request, submitted string) error {
	if s.bootstrapToken != "" {
		if strings.TrimSpace(submitted) == s.bootstrapToken {
			return nil
		}
		return fmt.Errorf("部署令牌不正确（在数据目录的 bootstrap-token 文件里，或部署脚本的输出里）")
	}
	if isPrivateIP(clientIP(r)) {
		return nil
	}
	return fmt.Errorf("为了让部署者本人注册第一个管理员，请带上部署令牌（数据目录 bootstrap-token）")
}

// isPrivateIP 判断来源是否为本机/内网地址。
func isPrivateIP(hostport string) bool {
	ip := net.ParseIP(strings.Trim(hostport, "[]"))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		}
		return false
	}
	// IPv6：fc00::/7 唯一本地地址 + fe80::/10 链路本地
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return ip.IsLinkLocalUnicast()
}
