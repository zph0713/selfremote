package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"selfremote/internal/config"
	"selfremote/internal/keyfile"
	"selfremote/internal/tunnel"
)

// cmdAgent runs a site edge: it dials the hub, publishes the LAN prefixes it
// serves and translates addresses at the tunnel boundary (so sites with
// colliding subnets can coexist). The configuration is normally an encrypted
// .srkey downloaded from the web control plane.
func cmdAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	cfgPath := fs.String("c", "", "path to agent config file (json, or an encrypted .srkey)")
	kpass := fs.String("kpass", "", "key-file passphrase (automation; prefer the interactive prompt)")
	mfaSecret := fs.String("mfa-secret", "", "override the TOTP secret (automation; normally inside the config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("missing -c <config file>")
	}

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		return err
	}
	if keyfile.IsEnvelope(raw) {
		pass := *kpass
		if pass == "" {
			pass = os.Getenv("SR_KEYPASS")
		}
		plain, err := unlockKeyfile(raw, pass)
		if err != nil {
			return err
		}
		raw = plain
		fmt.Println("配置文件已解密（仅保存在内存中）")
	}
	cfg, err := config.LoadAgentBytes(raw, *cfgPath)
	if err != nil {
		return err
	}

	secret := *mfaSecret
	if secret == "" {
		secret = os.Getenv("SR_MFA_SECRET")
	}
	if secret == "" {
		secret = cfg.MFASecret
	}

	// Containerised deployments often need a different hub address than the
	// one baked into the (encrypted) configuration — e.g. a compose service
	// name instead of 127.0.0.1. SR_AGENT_SERVER wins, then the desktop
	// override used by docker-compose.desktop.yml.
	serverAddr := cfg.Server
	if v := os.Getenv("SR_AGENT_SERVER"); v != "" {
		serverAddr = v
	} else if v := os.Getenv("SR_AGENT_SERVER_OVERRIDE"); v != "" {
		serverAddr = v
	}

	routes := make([]tunnel.RouteMap, 0, len(cfg.Routes))
	for i, r := range cfg.Routes {
		m, err := tunnel.ParseRouteMap(r.Real, r.Virtual)
		if err != nil {
			return fmt.Errorf("routes[%d]: %w", i, err)
		}
		routes = append(routes, m)
	}

	eng, err := tunnel.New(tunnel.Options{
		Mode:         tunnel.ModeAgent,
		PrivateKey:   cfg.Private[:],
		Server:       serverAddr,
		ServerPublic: cfg.ServerPublic[:],
		TunnelCIDR:   cfg.TunnelCIDR,
		AgentID:      cfg.ID,
		RouteMaps:    routes,
		MFASecret:    secret,
		Version:      version,
		OnReady:      func() { printAgentReady(cfg, routes, secret != "") },
		OnInfo: func(info tunnel.ServerInfo) {
			if info.Hostname != "" {
				fmt.Printf("  服务端:  %s（监听 %s，%s）\n", info.Hostname, info.Listen, roleName(info.Role))
			}
		},
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Bridge networks reach the hub by compose service name, not loopback.
	name := cfg.Name
	if name == "" {
		name = cfg.ID
	}
	fmt.Printf("selfremote agent %s\n", version)
	fmt.Printf("  节点:    %s (%s)\n", name, cfg.ID)
	fmt.Printf("  服务端:  %s\n", serverAddr)
	fmt.Printf("  隧道:    %s\n", cfg.TunnelCIDR)
	fmt.Printf("  网段:    %s\n", routeList(routes))
	if secret != "" {
		fmt.Println("  MFA:     已配置动态码密钥（无人值守自动应答）")
	} else {
		fmt.Println("  MFA:     未配置（服务端若要求动态码，本节点将无法通过认证）")
	}
	go runAgentStatusWriter(ctx, eng, cfg.StatusFile)

	if err := eng.Run(ctx); err != nil {
		return err
	}
	fmt.Println("已断开，隧道设备与转发已清理。")
	return nil
}

func roleName(role string) string {
	if role == "server" {
		return "中转服务端"
	}
	if role == "gateway" {
		return "直连网关"
	}
	return role
}

func printAgentReady(cfg *config.Agent, routes []tunnel.RouteMap, hasMFA bool) {
	fmt.Println()
	fmt.Println("═══════════ selfremote agent 已上线 ═══════════")
	fmt.Printf("  节点:    %s (%s)\n", cfg.Name, cfg.ID)
	fmt.Printf("  服务端:  %s\n", cfg.Server)
	if hasMFA {
		fmt.Println("  MFA:     ✓ 动态码已通过")
	}
	fmt.Printf("  转发:    已开启（%s）\n", routeList(routes))
	fmt.Println("  本机需 ip_forward + SNAT（容器 entrypoint 自动配置）")
	fmt.Println("══════════════════════════════════════════════")
}

func routeList(routes []tunnel.RouteMap) string {
	if len(routes) == 0 {
		return "（未声明）"
	}
	out := make([]string, 0, len(routes))
	for _, m := range routes {
		out = append(out, m.String())
	}
	return strings.Join(out, ", ")
}

// agentStatusJSON is the agent's local status snapshot.
type agentStatusJSON struct {
	UpdatedAt string `json:"updated_at"`
	Server    string `json:"server"`
	TunnelIP  string `json:"tunnel_ip,omitempty"`
	Serving   bool   `json:"serving"`
	MFA       bool   `json:"mfa"`
	Connected bool   `json:"connected"`
	Drops     uint64 `json:"drops"`
	PublicKey string `json:"public_key"`
}
