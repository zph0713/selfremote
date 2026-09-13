// Command web runs the selfremote web control plane: registration + MFA +
// site agents + client key management + live dashboard. It talks to MariaDB,
// shares a data directory with the hub container (clients.json / agents.json /
// netinfo.json / server.json) and drives the hub over its control API.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"selfremote/internal/webapp"
)

func main() {
	listen := flag.String("listen", envOr("LISTEN", ":8080"), "HTTP listen address")
	dataDir := flag.String("data", envOr("DATA_DIR", "/data"), "shared data directory (clients.json etc.)")
	serverAddr := flag.String("server-addr", envOr("SERVER_ADDR", ""), "address embedded into client/agent configs (empty = auto-detect from netinfo)")
	lanCIDRs := flag.String("lan-cidrs", envOr("LAN_CIDRS", "192.168.1.0/24"), "legacy: comma-separated LAN subnets (used only when a v0.2 install has no sites)")
	tunnelPort := flag.Int("tunnel-port", envInt("TUNNEL_PORT", 28333), "hub UDP port")
	dsn := flag.String("dsn", envOr("DB_DSN", ""), "MariaDB DSN, e.g. sr:pass@tcp(db:3306)/selfremote?parseTime=true&charset=utf8mb4")
	srvAPI := flag.String("server-api", envOr("SRV_API_URL", ""), "hub control API base URL, e.g. http://server:8770")
	srvToken := flag.String("server-token", envOr("SRV_API_TOKEN", ""), "bearer token for the hub control API (or point SRV_API_TOKEN_FILE at the shared token file)")
	agentDist := flag.String("agent-dist", envOr("AGENT_DIST_DIR", "/agent-dist"), "directory with agent binaries for deployment packages")
	cookieSecure := flag.Bool("cookie-secure", envOr("COOKIE_SECURE", "") == "1", "mark session cookies Secure (enable when serving the console over HTTPS)")
	flag.Parse()

	if *dsn == "" {
		log.Fatal("DB_DSN is required")
	}
	var cidrs []string
	for _, c := range strings.Split(*lanCIDRs, ",") {
		if c = strings.TrimSpace(c); c != "" {
			cidrs = append(cidrs, c)
		}
	}

	// The hub's control API token may come from a shared file instead of an
	// environment variable (init.sh writes it next to the registries).
	token := *srvToken
	if token == "" {
		if p := envOr("SRV_API_TOKEN_FILE", ""); p != "" {
			if raw, err := os.ReadFile(p); err == nil {
				token = strings.TrimSpace(string(raw))
			} else {
				log.Printf("SRV_API_TOKEN_FILE %s: %v", p, err)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := webapp.New(ctx, webapp.Config{
		Listen:       *listen,
		DSN:          *dsn,
		DataDir:      *dataDir,
		ServerAddr:   *serverAddr,
		LANCIDRs:     cidrs,
		TunnelPort:   *tunnelPort,
		ServerAPI:    *srvAPI,
		ServerToken:  token,
		AgentDistDir: *agentDist,
		CookieSecure: *cookieSecure,
	})
	if err != nil {
		log.Fatalf("init: %v", err)
	}
	// 初次部署时 init.sh 会把「本机站点」预置在 data/preprovision/ 下；
	// 这里导入（此时可能还没有管理员账号，注册流程里会再试一次）。
	if err := srv.ImportPreprovision(ctx); err != nil {
		log.Printf("preprovision: %v", err)
	}
	if err := srv.ApplyV04Migrations(ctx); err != nil {
		log.Printf("v0.4 迁移: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	log.Printf("selfremote web control plane v%s listening on %s (data=%s)", webapp.Version, *listen, *dataDir)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return def
}
