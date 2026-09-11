package webapp

import (
	"fmt"
	"net/http"
	"time"
)

// statusFile mirrors the gateway's status.json.
type statusFile struct {
	UpdatedAt string `json:"updated_at"`
	Listen    string `json:"listen"`
	Totals    struct {
		Registered int `json:"registered"`
		Online     int `json:"online"`
	} `json:"totals"`
	Peers []struct {
		Name      string `json:"name"`
		User      string `json:"user"`
		Remote    string `json:"remote"`
		Connected bool   `json:"connected"`
		Authed    bool   `json:"authed"`
		MFA       bool   `json:"mfa"`
		Since     string `json:"since"`
		LastRecv  string `json:"last_recv"`
		Rx        uint64 `json:"rx_bytes"`
		Tx        uint64 `json:"tx_bytes"`
	} `json:"peers"`
}

// netInfoFile mirrors the gateway's netinfo.json.
type netInfoFile struct {
	UpdatedAt  string `json:"updated_at"`
	Hostname   string `json:"hostname"`
	Interfaces []struct {
		Name      string   `json:"name"`
		Up        bool     `json:"up"`
		Addresses []string `json:"addresses"`
	} `json:"interfaces"`
}

// userRow is the admin user list entry.
type userRow struct {
	ID          int64
	Username    string
	TOTPEnabled bool
	IsAdmin     bool
	CreatedAt   time.Time
	Devices     int
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	var st statusFile
	statusAt, _ := s.readJSONFile("status.json", &st)
	var ni netInfoFile
	netAt, _ := s.readJSONFile("netinfo.json", &ni)

	devs, _ := s.devicesByUser(ctx, u.ID)
	if u.IsAdmin {
		if all, err := s.allDevices(ctx); err == nil {
			devs = all
		}
	}

	statusAge := ""
	if !statusAt.IsZero() {
		statusAge = fmt.Sprintf("%.0f 秒前", time.Since(statusAt).Seconds())
	}
	netAge := ""
	if !netAt.IsZero() {
		netAge = fmt.Sprintf("%.0f 秒前", time.Since(netAt).Seconds())
	}
	s.render(w, r, "dashboard.html", pageData{
		Title:       "总览",
		AutoRefresh: true,
		Data: map[string]any{
			"Status":     st,
			"StatusAge":  statusAge,
			"Net":        ni,
			"NetAge":     netAge,
			"ServerAddr": s.serverAddr(),
			"Devices":    len(devs),
			"IsAdmin":    u.IsAdmin,
		},
	})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, u *User) {
	fresh, err := s.userByID(r.Context(), u.ID)
	if err != nil || fresh == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "settings.html", pageData{
		Title: "账号设置",
		User:  fresh,
		Data: map[string]any{
			"Enroll":  r.URL.Query().Get("enroll") == "1",
			"Pending": fresh.TOTPSecret != "" && !fresh.TOTPEnabled,
			"Enabled": fresh.TOTPEnabled,
		},
	})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, username, totp_enabled, is_admin, created_at FROM users ORDER BY id`)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var users []userRow
	for rows.Next() {
		var ur userRow
		var mfa, admin int
		if err := rows.Scan(&ur.ID, &ur.Username, &mfa, &admin, &ur.CreatedAt); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		ur.TOTPEnabled = mfa != 0
		ur.IsAdmin = admin != 0
		users = append(users, ur)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Device counts per user.
	counts := map[int64]int{}
	if all, err := s.allDevices(ctx); err == nil {
		for _, d := range all {
			counts[d.UserID]++
		}
	}
	for i := range users {
		users[i].Devices = counts[users[i].ID]
	}
	s.render(w, r, "users.html", pageData{
		Title: "用户管理",
		Data:  map[string]any{"Users": users},
	})
}
