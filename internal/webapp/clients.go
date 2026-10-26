package webapp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// 客户端连接页（M5.0）
//
// 「客户端」= 装了 selfremote 的电脑。它在 hub 眼里就是一个 peer：隧道地址、
// 可访问站点、累计流量。流量按「协议 + 站点地址 + 端口」聚合，数据来自 hub
// 内存里的流表（/api/v1/peers/{id}/ports），不落库。
// ---------------------------------------------------------------------------

// hubPort mirrors tunnel.PortRow (the web plane stays independent of the
// tunnel package).
type hubPort struct {
	Proto         uint8  `json:"proto"`
	ProtoName     string `json:"proto_name"`
	SiteIP        string `json:"site_ip"`
	Port          uint16 `json:"port"`
	Clients       int    `json:"clients"`
	BytesToSite   uint64 `json:"bytes_to_site"`
	BytesFromSite uint64 `json:"bytes_from_site"`
	PktsToSite    uint64 `json:"pkts_to_site"`
	PktsFromSite  uint64 `json:"pkts_from_site"`
	BpsToSite     uint64 `json:"bps_to_site"`
	BpsFromSite   uint64 `json:"bps_from_site"`
	LastSeen      string `json:"last_seen"`
}

// clientLive is one client device joined with the hub's live view.
type clientLive struct {
	Known     bool
	Connected bool
	Authed    bool
	State     string
	Remote    string
	LastSeen  string
	RxBytes   uint64
	TxBytes   uint64
	RxBps     uint64
	TxBps     uint64
}

// clientRow is one row of the /clients table.
type clientRow struct {
	Device
	Live clientLive
}

// clientState renders the live state the same way agentState does, so both
// tables read consistently.
func clientState(dev *Device, live hubAgent, hubReachable bool) clientLive {
	st := clientLive{
		Known:     hubReachable,
		Connected: live.Connected,
		Authed:    live.Authed,
		Remote:    live.Remote,
		LastSeen:  live.LastRecv,
		RxBytes:   live.RxBytes,
		TxBytes:   live.TxBytes,
		RxBps:     live.RxBps,
		TxBps:     live.TxBps,
	}
	switch {
	case !dev.Enabled:
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

// handleClients renders the client connection table.
func (s *Server) handleClients(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	var (
		devs []Device
		err  error
	)
	if u.IsAdmin {
		devs, err = s.allDevices(ctx)
	} else {
		devs, err = s.devicesByUser(ctx, u.ID)
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	view := s.hubView(ctx)
	rows := make([]clientRow, 0, len(devs))
	for i := range devs {
		d := devs[i]
		rows = append(rows, clientRow{Device: d, Live: clientState(&d, view.PeerByName[d.Name], view.Reachable)})
	}
	sort.Slice(rows, func(i, j int) bool {
		// Online devices first, then by name.
		oi := rows[i].Live.State == "在线"
		oj := rows[j].Live.State == "在线"
		if oi != oj {
			return oi
		}
		return rows[i].Name < rows[j].Name
	})
	s.render(w, r, "clients.html", pageData{
		Title:       "客户端连接",
		AutoRefresh: true,
		Data: map[string]any{
			"Clients":      rows,
			"HubReachable": view.Reachable,
			"Hub":          view.Status,
			"IsAdmin":      u.IsAdmin,
		},
	})
}

// handleClientShow renders one client's detail: identity, sites and the
// per-port traffic table (refreshed by JS every 2 s).
func (s *Server) handleClientShow(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "参数错误", http.StatusBadRequest)
		return
	}
	dev, err := s.deviceByID(ctx, id)
	if err != nil || dev == nil {
		http.Error(w, "客户端不存在", http.StatusNotFound)
		return
	}
	if dev.UserID != u.ID && !u.IsAdmin {
		http.Error(w, "无权查看他人设备", http.StatusForbidden)
		return
	}
	view := s.hubView(ctx)
	live := clientState(dev, view.PeerByName[dev.Name], view.Reachable)
	ports, portErr := s.hubPeerPorts(ctx, dev.Name, 50)
	s.render(w, r, "client_show.html", pageData{
		Title: "客户端 " + dev.Name,
		Data: map[string]any{
			"Device":       dev,
			"Live":         live,
			"Ports":        ports,
			"PortsErr":     errText(portErr),
			"Fingerprint":  pubFingerprint(dev.PublicKey),
			"HubReachable": view.Reachable,
			"Sites":        dev.Sites,
			"PortPeer":     dev.Name,
		},
	})
}

// handleUIPeerPorts is the polling endpoint behind both detail pages.
func (s *Server) handleUIPeerPorts(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	id := r.PathValue("id")
	if !s.maySeePeer(ctx, u, id) {
		http.Error(w, "无权查看", http.StatusForbidden)
		return
	}
	ports, err := s.hubPeerPorts(ctx, id, queryLimit(r))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"peer": id, "ports": []hubPort{}, "error": errText(err)})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"peer":  id,
		"ports": ports,
		"at":    time.Now().Format(time.RFC3339),
	})
}

// handleUIOverview is the polling endpoint behind the list pages: rates only,
// the rest of the page stays server-rendered.
func (s *Server) handleUIOverview(w http.ResponseWriter, r *http.Request, u *User) {
	view := s.hubView(r.Context())
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	out := map[string]any{"reachable": view.Reachable, "peers": []any{}}
	if view.Status == nil {
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	peers := make([]map[string]any, 0, len(view.Status.Peers))
	for _, p := range view.Status.Peers {
		peers = append(peers, map[string]any{
			"id": p.ID, "name": p.Name, "role": p.Role,
			"connected": p.Connected, "authed": p.Authed,
			"rx_bps": p.RxBps, "tx_bps": p.TxBps,
			"rx_bytes": p.RxBytes, "tx_bytes": p.TxBytes,
		})
	}
	out["peers"] = peers
	_ = json.NewEncoder(w).Encode(out)
}

// maySeePeer reports whether u may read the traffic of a hub peer id (an agent
// id or a client device name).
func (s *Server) maySeePeer(ctx context.Context, u *User, id string) bool {
	if u.IsAdmin {
		return true
	}
	if a, err := s.agentByAgentID(ctx, id); err == nil && a != nil {
		return a.UserID == u.ID
	}
	devs, err := s.devicesByUser(ctx, u.ID)
	if err != nil {
		return false
	}
	for _, d := range devs {
		if d.Name == id {
			return true
		}
	}
	return false
}

// hubPeerPorts asks the hub for the per-port aggregate of one peer.
func (s *Server) hubPeerPorts(ctx context.Context, id string, limit int) ([]hubPort, error) {
	var out struct {
		Ports []hubPort `json:"ports"`
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	path := "/api/v1/peers/" + url.PathEscape(id) + "/ports?limit=" + strconv.Itoa(limit)
	if err := s.hubDo(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	if out.Ports == nil {
		out.Ports = []hubPort{}
	}
	return out.Ports, nil
}

func queryLimit(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return 50
	}
	if n > 500 {
		n = 500
	}
	return n
}

// pubFingerprint renders a short, human-comparable fingerprint of a base64
// X25519 public key (SHA-256, first 8 bytes). Used at registration time and in
// the client table so two sides can be compared by eye.
func pubFingerprint(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return strings.ToUpper(hex.EncodeToString(sum[:8]))
}
