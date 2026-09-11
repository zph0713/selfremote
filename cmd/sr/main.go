// Command sr is the selfremote CLI.
//
// selfremote is a self-hosted L3 tunnel (VPN-like) that lets a Mac reach the
// devices on its home LAN by their LAN IPs, from anywhere on the internet.
//
// Subcommands:
//
//	sr genkey              generate an X25519 key pair (base64)
//	sr gateway -c <file>   run as home gateway (on the NAS)
//	sr client  -c <file>   run as client (on the Mac; <file> may be an
//	                       encrypted key file downloaded from the web UI)
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
	"selfremote/internal/keyfile"
	"selfremote/internal/tunnel"
)

const version = "0.2.1"

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
                            <file> may be an encrypted key file (.srkey)
                            downloaded from the web UI
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
		Mode:        tunnel.ModeGateway,
		PrivateKey:  cfg.Private[:],
		Listen:      cfg.Listen,
		Peers:       peers,
		ClientsFile: cfg.ClientsFile,
		TunnelCIDR:  cfg.TunnelCIDR,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.StatusFile != "" || cfg.NetInfoFile != "" {
		go runStatusWriter(ctx, eng, cfg.StatusFile, cfg.NetInfoFile)
	}

	fmt.Printf("selfremote gateway %s\n", version)
	fmt.Printf("  listen:     %s\n", eng.LocalAddr())
	fmt.Printf("  public key: %s\n", base64.StdEncoding.EncodeToString(eng.PublicKey()))
	fmt.Printf("  tunnel:     %s\n", cfg.TunnelCIDR)
	fmt.Printf("  peers:      %d\n", len(peers))
	if cfg.ClientsFile != "" {
		fmt.Printf("  clients:    %s (hot-reloaded)\n", cfg.ClientsFile)
	}
	if cfg.StatusFile != "" {
		fmt.Printf("  status:     %s\n", cfg.StatusFile)
	}
	return eng.Run(ctx)
}

func cmdClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	cfgPath := fs.String("c", "", "path to client config file (json, or an encrypted key file)")
	kpass := fs.String("kpass", "", "key-file passphrase (automation; prefer the interactive prompt)")
	mfaCode := fs.String("mfa", "", "MFA code for the first attempt (automation; prefer the interactive prompt)")
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

	// Encrypted key file: unlock first (in memory only).
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
		fmt.Println("密钥文件已解密（仅保存在内存中）")
	}

	cfg, err := config.LoadClientBytes(raw, *cfgPath)
	if err != nil {
		return err
	}

	// MFA prompt. A code passed via -mfa / SR_MFA is used for the first
	// attempt only; interactive retries always go through the prompt.
	mfaFirst := *mfaCode
	if mfaFirst == "" {
		mfaFirst = os.Getenv("SR_MFA")
	}
	var mfaTaken bool
	cs := &clientState{}
	authPrompt := func(attempt int) (string, bool) {
		if mfaFirst != "" && !mfaTaken {
			mfaTaken = true
			cs.setMFAUsed()
			return mfaFirst, true
		}
		fmt.Fprintf(os.Stderr, "请输入 Google Authenticator 动态验证码（6 位，直接回车取消）: ")
		line, err := readLine()
		if err != nil || line == "" {
			return "", false
		}
		cs.setMFAUsed()
		return line, true
	}

	eng, err := tunnel.New(tunnel.Options{
		Mode:         tunnel.ModeClient,
		PrivateKey:   cfg.Private[:],
		Server:       cfg.Server,
		ServerPublic: cfg.ServerPublic[:],
		TunnelCIDR:   cfg.TunnelCIDR,
		Routes:       cfg.Routes,
		AuthPrompt:   authPrompt,
		OnReady:      func() { cs.onReady(cfg) },
		OnInfo:       cs.onInfo,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("selfremote client %s\n", version)
	fmt.Printf("  server: %s\n", cfg.Server)
	fmt.Printf("  tunnel: %s\n", cfg.TunnelCIDR)
	fmt.Printf("  routes: %v\n", cfg.Routes)

	go statusLoop(ctx, eng, cs.isReady)

	if err := eng.Run(ctx); err != nil {
		return err
	}
	fmt.Println("已断开，路由已清理。")
	return nil
}
