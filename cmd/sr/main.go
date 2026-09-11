// Command sr is the selfremote CLI.
//
// selfremote is a self-hosted L3 tunnel (VPN-like) that lets a Mac reach the
// devices on its home LAN by their LAN IPs, from anywhere on the internet.
//
// Subcommands:
//
//	sr genkey              generate an X25519 key pair (base64)
//	sr gateway -c <file>   run as home gateway (on the NAS)
//	sr client  -c <file>   run as client (on the Mac)
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/flynn/noise"

	"selfremote/internal/config"
	"selfremote/internal/tunnel"
)

const version = "0.2.0-m1"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "genkey":
		err = cmdGenkey()
	case "gateway":
		err = cmdGateway(args)
	case "client":
		err = cmdClient(args)
	case "version", "-v", "--version":
		fmt.Println("selfremote", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `selfremote `+version+`

usage:
  sr genkey                 generate an X25519 key pair (base64)
  sr gateway -c <file>      run as home gateway (on the NAS)
  sr client  -c <file>      run as client (on the Mac)
  sr version
`)
}

// cmdGenkey prints a fresh X25519 key pair in base64, using the same key
// generation as the Noise handshake (DH25519).
func cmdGenkey() error {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	kp, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		return err
	}
	fmt.Printf("private_key = %s\npublic_key  = %s\n",
		base64.StdEncoding.EncodeToString(kp.Private),
		base64.StdEncoding.EncodeToString(kp.Public))
	return nil
}

func cmdGateway(args []string) error {
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	cfgPath := fs.String("c", "", "path to gateway config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("missing -c <config file>")
	}
	cfg, err := config.LoadGateway(*cfgPath)
	if err != nil {
		return err
	}

	peers := make([]tunnel.PeerConfig, 0, len(cfg.Peers))
	for i, p := range cfg.Peers {
		key := cfg.PeerKeys[i]
		peers = append(peers, tunnel.PeerConfig{Name: p.Name, PublicKey: key[:]})
	}
	eng, err := tunnel.New(tunnel.Options{
		Mode:       tunnel.ModeGateway,
		PrivateKey: cfg.Private[:],
		Listen:     cfg.Listen,
		Peers:      peers,
		TunnelCIDR: cfg.TunnelCIDR,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("selfremote gateway\n")
	fmt.Printf("  listen:     %s\n", eng.LocalAddr())
	fmt.Printf("  public key: %s\n", base64.StdEncoding.EncodeToString(eng.PublicKey()))
	fmt.Printf("  tunnel:     %s\n", cfg.TunnelCIDR)
	fmt.Printf("  peers:      %d\n", len(peers))
	return eng.Run(ctx)
}

func cmdClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	cfgPath := fs.String("c", "", "path to client config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("missing -c <config file>")
	}
	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		return err
	}

	eng, err := tunnel.New(tunnel.Options{
		Mode:         tunnel.ModeClient,
		PrivateKey:   cfg.Private[:],
		Server:       cfg.Server,
		ServerPublic: cfg.ServerPublic[:],
		TunnelCIDR:   cfg.TunnelCIDR,
		Routes:       cfg.Routes,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("selfremote client\n")
	fmt.Printf("  server: %s\n", cfg.Server)
	fmt.Printf("  tunnel: %s\n", cfg.TunnelCIDR)
	fmt.Printf("  routes: %v\n", cfg.Routes)
	return eng.Run(ctx)
}
