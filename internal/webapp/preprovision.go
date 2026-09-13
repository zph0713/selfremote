package webapp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// 预置站点导入（初次部署时 server 自己的那个站点）
//
// init.sh 在第一次部署时就把「本机站点」的配置写好（密钥、隧道地址、网段），
// 这样 `docker compose up -d` 起来时 web + server + agent 就是一个完整的、
// 已经互通的服务，不需要再登录网页手工建站。控制面启动时把 data/preprovision/
// *.site.json 里的站点导入数据库（幂等：按 agent_id 判断），并发布到 agents.json。
//
// 文件格式（由 init.sh 生成）：
//
//	{
//	  "agent_id": "home",
//	  "name": "本机站点",
//	  "public_key": "…",           // 站点自己的公钥（私钥只在 agent-home.json 里）
//	  "tunnel_ip": "10.77.0.100",
//	  "routes": [{"real": "192.168.2.0/24"}],
//	  "enabled": true
//	}
// ---------------------------------------------------------------------------

type preprovisionSite struct {
	AgentID   string       `json:"agent_id"`
	Name      string       `json:"name"`
	PublicKey string       `json:"public_key"`
	TunnelIP  string       `json:"tunnel_ip"`
	Routes    []AgentRoute `json:"routes"`
	Enabled   *bool        `json:"enabled,omitempty"`
}

// applyV04Migrations performs the one-shot cleanups v0.4 needs.
//
// v0.4 drops per-site TOTP: a site's proof of identity is the one-time install
// code at enrollment time, and the mutually-authenticated keypair afterwards.
// Sites created by v0.3 still carry a secret in the database, which would make
// the hub ask for a code the agent no longer has — clear those once.
func (s *Server) ApplyV04Migrations(ctx context.Context) error {
	const key = "migrated_v040_site_mfa"
	if s.getSetting(ctx, key, "") != "" {
		return nil
	}
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET totp_secret = '' WHERE totp_secret <> ''`)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		log.Printf("v0.4 迁移：清空 %d 个旧站点的动态码密钥（站点改为「安装码 + 密钥对」认证）", n)
		if err := s.syncAgents(ctx); err != nil {
			return err
		}
	}
	return s.setSetting(ctx, key, time.Now().Format(time.RFC3339))
}

// importPreprovision loads data/preprovision/*.site.json once at startup.
func (s *Server) ImportPreprovision(ctx context.Context) error {
	dir := filepath.Join(s.cfg.DataDir, "preprovision")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("读取 %s: %w", dir, err)
		}
		return nil
	}
	imported := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".site.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			log.Printf("preprovision: %s: %v", e.Name(), err)
			continue
		}
		var ps preprovisionSite
		if err := json.Unmarshal(raw, &ps); err != nil {
			log.Printf("preprovision: %s 解析失败: %v", e.Name(), err)
			continue
		}
		if ps.AgentID == "" || ps.PublicKey == "" {
			log.Printf("preprovision: %s 缺少 agent_id/public_key，跳过", e.Name())
			continue
		}
		existing, err := s.agentByAgentID(ctx, ps.AgentID)
		if err != nil {
			log.Printf("preprovision: 查询 %s 失败: %v", ps.AgentID, err)
			continue
		}
		if existing != nil {
			// 已经存在：预置文件对「还没真正接入过」的站点有权威
			// （补公钥，或覆盖 v0.3 时代由网页预生成的旧密钥）。
			switch {
			case existing.PublicKey == "":
				if err := s.bindAgentEnrollment(ctx, existing.ID, ps.PublicKey); err != nil {
					log.Printf("preprovision: 绑定 %s 公钥失败: %v", ps.AgentID, err)
					continue
				}
				log.Printf("preprovision: 站点 %s 已绑定预置公钥", ps.AgentID)
				imported++
			case existing.EnrolledAt.IsZero():
				if err := s.bindAgentEnrollment(ctx, existing.ID, ps.PublicKey); err != nil {
					log.Printf("preprovision: 更新 %s 公钥失败: %v", ps.AgentID, err)
					continue
				}
				log.Printf("preprovision: 站点 %s 用的是网页预生成的旧密钥，已换成预置密钥（本机站点才能连上）", ps.AgentID)
				imported++
			default:
				if existing.PublicKey != ps.PublicKey {
					log.Printf("preprovision: 站点 %s 已接入过（enrolled_at 有值），保留它的密钥，忽略预置公钥", ps.AgentID)
				}
			}
			continue
		}
		// 需要一个属主：预置站点归属第一个管理员。
		var userID int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT id FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1`).Scan(&userID); err != nil {
			log.Printf("preprovision: 还没有管理员账号，跳过 %s（注册管理员后重启控制面即可）", ps.AgentID)
			continue
		}
		enabled := true
		if ps.Enabled != nil {
			enabled = *ps.Enabled
		}
		a := &Agent{
			UserID:     userID,
			AgentID:    ps.AgentID,
			Name:       ps.Name,
			PublicKey:  ps.PublicKey,
			TunnelIP:   ps.TunnelIP,
			Enabled:    enabled,
			Routes:     ps.Routes,
			EnrolledAt: time.Now(),
		}
		if a.Name == "" {
			a.Name = a.AgentID
		}
		if a.TunnelIP == "" {
			ip, err := s.allocAgentIP(ctx)
			if err != nil {
				log.Printf("preprovision: %s: %v", ps.AgentID, err)
				continue
			}
			a.TunnelIP = ip
		}
		if err := s.addAgent(ctx, a); err != nil {
			log.Printf("preprovision: 导入 %s 失败: %v", ps.AgentID, err)
			continue
		}
		log.Printf("preprovision: 已导入站点 %s（%s，隧道 %s）", a.AgentID, routesText(a.Routes), a.TunnelIP)
		imported++
	}
	if imported > 0 {
		if err := s.syncAgents(ctx); err != nil {
			return fmt.Errorf("发布 agents.json: %w", err)
		}
	}
	return nil
}
