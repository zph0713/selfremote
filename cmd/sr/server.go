package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"selfremote/internal/config"
	"selfremote/internal/serverapp"
	"selfremote/internal/tunnel"
)

// cmdServer runs the hub: one UDP socket accepting agents (site edges) and
// clients (user devices), relaying packets between them in user space. It
// needs no TUN device, no NET_ADMIN and no kernel forwarding — just a port.
func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cfgPath := fs.String("c", "", "path to server config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("missing -c <config file>")
	}
	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		return err
	}

	eng, err := tunnel.New(tunnel.Options{
		Mode:        tunnel.ModeServer,
		PrivateKey:  cfg.Private[:],
		Listen:      cfg.Listen,
		ClientsFile: cfg.ClientsFile,
		AgentsFile:  cfg.AgentsFile,
		TunnelCIDR:  cfg.TunnelCIDR,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	api := serverapp.New(serverapp.Config{
		Listen:  cfg.APIListen,
		Token:   cfg.APIToken,
		Engine:  eng,
		Version: version,
	})
	go func() {
		if err := api.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "控制 API 启动失败: %v\n", err)
		}
	}()

	if cfg.StatusFile != "" || cfg.NetInfoFile != "" {
		go runServerStatusWriter(ctx, api, cfg.StatusFile, cfg.NetInfoFile)
	}

	fmt.Printf("selfremote server %s\n", version)
	fmt.Printf("  listen:     %s\n", eng.LocalAddr())
	fmt.Printf("  public key: %s\n", base64.StdEncoding.EncodeToString(eng.PublicKey()))
	fmt.Printf("  tunnel:     %s (虚拟地址，不在内核里)\n", cfg.TunnelCIDR)
	if cfg.ClientsFile != "" {
		fmt.Printf("  clients:    %s (热加载)\n", cfg.ClientsFile)
	}
	if cfg.AgentsFile != "" {
		fmt.Printf("  agents:     %s (热加载)\n", cfg.AgentsFile)
	}
	if cfg.APIListen != "" {
		fmt.Printf("  control:    %s\n", cfg.APIListen)
	}
	fmt.Println("  relay:      用户态中转（client ↔ agent），站点之间默认不可互访")
	return eng.Run(ctx)
}
