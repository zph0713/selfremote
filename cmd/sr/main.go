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
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/flynn/noise"

	"selfremote/internal/config"
)

const version = "0.1.0-m1"

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
	fmt.Printf("gateway config loaded: listen=%s peers=%d tunnel=%s\n",
		cfg.Listen, len(cfg.Peers), cfg.TunnelCIDR)
	return fmt.Errorf("gateway runtime not implemented yet (milestone M1.1)")
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
	fmt.Printf("client config loaded: server=%s routes=%v tunnel=%s\n",
		cfg.Server, cfg.Routes, cfg.TunnelCIDR)
	return fmt.Errorf("client runtime not implemented yet (milestone M1.1)")
}
