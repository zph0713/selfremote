package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

// cmdPubkey prints the public half of a config's private key. Useful when a
// script only has server.json (or gateway.json) and needs the public key.
func cmdPubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	cfgPath := fs.String("c", "", "配置文件（server.json / gateway.json / agent 配置 / client 配置）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fmt.Errorf("用法: sr pubkey -c <配置文件>")
	}
	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		return err
	}
	var cfg struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("%s 解析失败: %w", *cfgPath, err)
	}
	priv, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil || len(priv) != 32 {
		return fmt.Errorf("%s: private_key 无效", *cfgPath)
	}
	var in, out [32]byte
	copy(in[:], priv)
	curve25519.ScalarBaseMult(&out, &in)
	fmt.Println(base64.StdEncoding.EncodeToString(out[:]))
	return nil
}
