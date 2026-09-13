package webapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// The control plane talks to the hub over its control API (internal/serverapp)
// to read live state and to issue operator commands. Only the pieces the UI
// needs are mirrored here, deliberately without importing the tunnel package:
// the web image must stay independent of the data plane's code.

// hubAgent is one agent as the hub sees it.
type hubAgent struct {
	Name       string   `json:"name"`
	ID         string   `json:"id"`
	Role       string   `json:"role"`
	MFA        bool     `json:"mfa"`
	Connected  bool     `json:"connected"`
	Authed     bool     `json:"authed"`
	Remote     string   `json:"remote,omitempty"`
	Since      string   `json:"since,omitempty"`
	LastRecv   string   `json:"last_recv,omitempty"`
	RxBytes    uint64   `json:"rx_bytes"`
	TxBytes    uint64   `json:"tx_bytes"`
	Enabled    *bool    `json:"enabled,omitempty"`
	TunnelIP   string   `json:"tunnel_ip,omitempty"`
	Routes     []string `json:"routes,omitempty"`
	AnnounceAt string   `json:"announce_at,omitempty"`
	Mismatch   bool     `json:"config_mismatch,omitempty"`
	Info       *hubInfo `json:"info,omitempty"`
}

// hubInfo is an agent's own announce payload.
type hubInfo struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	Version  string   `json:"version"`
	TunnelIP string   `json:"tunnel_ip"`
	Serving  bool     `json:"serving"`
	UptimeS  int64    `json:"uptime_s"`
	Routes   []string `json:"routes,omitempty"`
	TS       string   `json:"ts,omitempty"`
}

// hubTotals summarises the hub's peer set.
type hubTotals struct {
	AgentsTotal   int `json:"agents_total"`
	AgentsOnline  int `json:"agents_online"`
	ClientsTotal  int `json:"clients_total"`
	ClientsOnline int `json:"clients_online"`
}

// hubStatus is the /api/v1/status payload.
type hubStatus struct {
	Version    string     `json:"version"`
	Hostname   string     `json:"hostname"`
	Listen     string     `json:"listen"`
	TunnelCIDR string     `json:"tunnel_cidr"`
	Totals     hubTotals  `json:"totals"`
	Peers      []hubAgent `json:"peers"`
	Conflicts  []string   `json:"conflicts,omitempty"`
	UpdatedAt  string     `json:"updated_at"`
}

// hubReachable reports whether the control API answered.
func (s *Server) hubStatus(ctx context.Context) (*hubStatus, bool) {
	if s.cfg.ServerAPI == "" {
		return nil, false
	}
	var st hubStatus
	if err := s.hubDo(ctx, http.MethodGet, "/api/v1/status", nil, &st); err != nil {
		return nil, false
	}
	return &st, true
}

// hubKick asks the hub to drop an agent's session (the agent reconnects).
func (s *Server) hubKick(ctx context.Context, agentID string) error {
	return s.hubDo(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/kick", nil, nil)
}

// hubRefresh asks an agent to announce its status right away.
func (s *Server) hubRefresh(ctx context.Context, agentID string) error {
	return s.hubDo(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/refresh", nil, nil)
}

func (s *Server) hubDo(ctx context.Context, method, path string, body any, out any) error {
	if s.cfg.ServerAPI == "" {
		return fmt.Errorf("未配置服务端管控地址（SRV_API_URL）")
	}
	url := strings.TrimRight(s.cfg.ServerAPI, "/") + path
	var rd *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = strings.NewReader(string(raw))
	} else {
		rd = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return err
	}
	if s.cfg.ServerToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.ServerToken)
	}
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("服务端管控 API 不可达：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("服务端管控 API 返回 %s", resp.Status)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return err
		}
	}
	return nil
}

// hubView is the merged picture the UI renders: what the control plane knows
// (database) joined with what the hub reports (live).
type hubView struct {
	Reachable bool
	Status    *hubStatus
	AgentByID map[string]hubAgent
}

func (s *Server) hubView(ctx context.Context) hubView {
	v := hubView{AgentByID: map[string]hubAgent{}}
	st, ok := s.hubStatus(ctx)
	if !ok {
		return v
	}
	v.Reachable = true
	v.Status = st
	for _, p := range st.Peers {
		if p.Role == "agent" {
			v.AgentByID[p.ID] = p
		}
	}
	return v
}

// liveAgentStatus renders the live state of one agent for the UI.
type liveAgentStatus struct {
	Known     bool // hub reports this agent
	Connected bool
	Authed    bool
	Serving   bool
	Hostname  string
	Version   string
	UptimeS   int64
	Routes    []string
	Remote    string
	LastSeen  string
	RxBytes   uint64
	TxBytes   uint64
	Mismatch  bool
	State     string // 在线 / 已停用 / 离线 / 未接入
}

func agentState(a *Agent, live hubAgent, hubReachable bool, enabledInDB bool) liveAgentStatus {
	st := liveAgentStatus{
		Known:     hubReachable,
		Connected: live.Connected,
		Authed:    live.Authed,
		Routes:    live.Routes,
		Remote:    live.Remote,
		LastSeen:  live.AnnounceAt,
		RxBytes:   live.RxBytes,
		TxBytes:   live.TxBytes,
		Mismatch:  live.Mismatch,
	}
	if live.Info != nil {
		st.Serving = live.Info.Serving
		st.Hostname = live.Info.Hostname
		st.Version = live.Info.Version
		st.UptimeS = live.Info.UptimeS
		if len(live.Routes) == 0 {
			st.Routes = live.Info.Routes
		}
	}
	switch {
	case !enabledInDB:
		st.State = "已停用"
	case !hubReachable:
		st.State = "服务端不可达"
	case st.Connected && st.Authed:
		st.State = "在线"
	case st.Connected:
		st.State = "认证中"
	default:
		st.State = "离线"
	}
	return st
}
