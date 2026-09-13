package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/flynn/noise"

	"selfremote/internal/keyfile"
)

// enrollReply is what the control plane hands back after a successful enroll.
type enrollReply struct {
	SiteID   string `json:"site_id"`
	Name     string `json:"name"`
	TunnelIP string `json:"tunnel_ip"`
	Routes   []struct {
		Real    string `json:"real"`
		Virtual string `json:"virtual,omitempty"`
	} `json:"routes"`
	ServerAddr      string `json:"server_addr"`
	ServerPublicKey string `json:"server_public_key"`
}

// cmdAgentEnroll trades a one-time install code for a site registration.
//
// The keypair is minted HERE and the private half never leaves this machine —
// the control plane only ever sees the public key. Afterwards the agent
// authenticates with Noise IK (mutual), so the install code is needed exactly
// once, at installation time.
func cmdAgentEnroll(args []string) error {
	fs := flag.NewFlagSet("agent enroll", flag.ExitOnError)
	server := fs.String("server", os.Getenv("SR_ENROLL_SERVER"), "控制面地址，如 http://192.168.2.243:8080")
	code := fs.String("code", os.Getenv("SR_ENROLL_CODE"), "一次性安装码（控制面「站点 Agent」页生成）")
	out := fs.String("o", "", "配置文件输出路径")
	tunnel := fs.String("tunnel", "", "覆盖隧道服务端地址（默认用控制面下发的）")
	routes := fs.String("routes", "", "本站点开放的网段，逗号分隔（建站时没填时必填）")
	keypass := fs.String("keypass", "", "给配置文件加密的口令（默认明文，root-only）")
	force := fs.Bool("force", false, "覆盖已存在的配置文件")
	insecure := fs.Bool("insecure", false, "跳过 TLS 校验（自签名证书时使用）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	base := strings.TrimRight(strings.TrimSpace(*server), "/")
	if base == "" {
		return fmt.Errorf("缺少 -server（控制面地址，如 http://<主机>:8080）")
	}
	if *code == "" {
		return fmt.Errorf("缺少 -code（控制面「站点 Agent」页生成的一次性安装码）")
	}
	if *out == "" {
		return fmt.Errorf("缺少 -o <配置文件路径>")
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		return fmt.Errorf("配置文件已存在：%s（换机/重置请先加 -force 或删掉它）", *out)
	}

	// 1) 本地生成密钥对（私钥不出本机）
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	kp, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		return fmt.Errorf("生成密钥失败: %w", err)
	}
	hostname, _ := os.Hostname()

	var routeList []string
	for _, r := range strings.Split(*routes, ",") {
		if r = strings.TrimSpace(r); r != "" {
			routeList = append(routeList, r)
		}
	}
	reqBody, _ := json.Marshal(map[string]any{
		"code":       *code,
		"public_key": base64.StdEncoding.EncodeToString(kp.Public),
		"hostname":   hostname,
		"version":    version,
		"routes":     routeList,
	})

	// 2) 交安装码换注册
	client := &http.Client{Timeout: 30 * time.Second}
	if *insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	fmt.Printf("正在接入控制面 %s …\n", base)
	resp, err := client.Post(base+"/api/enroll", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("连接控制面失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("接入被拒绝（HTTP %d）：%s", resp.StatusCode, e.Error)
	}
	var reply enrollReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return fmt.Errorf("控制面返回无法解析: %w", err)
	}
	if reply.TunnelIP == "" || reply.ServerPublicKey == "" || reply.ServerAddr == "" {
		return fmt.Errorf("控制面返回不完整（缺少隧道地址/服务端公钥/地址）")
	}
	hubAddr := reply.ServerAddr
	if *tunnel != "" {
		hubAddr = *tunnel
	}

	// 3) 写配置
	cfg := map[string]any{
		"id":                reply.SiteID,
		"name":              reply.Name,
		"server":            hubAddr,
		"private_key":       base64.StdEncoding.EncodeToString(kp.Private),
		"server_public_key": reply.ServerPublicKey,
		"tunnel_cidr":       reply.TunnelIP + "/24",
		"routes":            reply.Routes,
	}
	plain, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	outBytes := plain
	if *keypass != "" {
		outBytes, err = keyfile.Seal(plain, *keypass)
		if err != nil {
			return fmt.Errorf("加密配置失败: %w", err)
		}
	}
	if err := os.WriteFile(*out, outBytes, 0o600); err != nil {
		return fmt.Errorf("写配置文件失败: %w", err)
	}

	fmt.Printf("已接入：站点 %s（%s）\n", reply.Name, reply.SiteID)
	fmt.Printf("  隧道地址: %s（本机在隧道内的地址）\n", reply.TunnelIP)
	fmt.Printf("  服务端:   %s\n", hubAddr)
	for _, rt := range reply.Routes {
		if rt.Virtual != "" {
			fmt.Printf("  网段:     %s → %s（另一站点占用，做地址翻译）\n", rt.Real, rt.Virtual)
		} else {
			fmt.Printf("  网段:     %s（原样呈现）\n", rt.Real)
		}
	}
	fmt.Printf("  配置:     %s%s\n", *out, map[bool]string{true: "（已加密）", false: ""}[*keypass != ""])
	return nil
}
