// Command web runs the selfremote web control plane: registration + MFA +
// client key management + live dashboard. It talks to MariaDB and shares a
// data directory with the gateway container (clients.json / status.json /
// netinfo.json / gateway.json).
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
	serverAddr := flag.String("server-addr", envOr("SERVER_ADDR", ""), "address embedded into client configs (empty = auto-detect from netinfo)")
	lanCIDRs := flag.String("lan-cidrs", envOr("LAN_CIDRS", "192.168.1.0/24"), "comma-separated home LAN subnets written into client configs")
	tunnelPort := flag.Int("tunnel-port", envInt("TUNNEL_PORT", 28333), "gateway UDP port")
	dsn := flag.String("dsn", envOr("DB_DSN", ""), "MariaDB DSN, e.g. sr:pass@tcp(db:3306)/selfremote?parseTime=true&charset=utf8mb4")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := webapp.New(ctx, webapp.Config{
		Listen:     *listen,
		DSN:        *dsn,
		DataDir:    *dataDir,
		ServerAddr: *serverAddr,
		LANCIDRs:   cidrs,
		TunnelPort: *tunnelPort,
	})
	if err != nil {
		log.Fatalf("init: %v", err)
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
