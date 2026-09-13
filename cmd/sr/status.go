package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"os"
	"sort"
	"time"

	"selfremote/internal/serverapp"
	"selfremote/internal/tunnel"
)

// netInfoSnapshot collects the host's interfaces (published for the web UI so
// it can auto-detect the address clients should dial).
func netInfoSnapshot() netInfoJSON {
	host, _ := os.Hostname()
	out := netInfoJSON{
		UpdatedAt:  time.Now().Format(time.RFC3339),
		Hostname:   host,
		Interfaces: []ifaceInfo{},
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		entry := ifaceInfo{Name: ifc.Name, Up: ifc.Flags&net.FlagUp != 0}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			entry.Addresses = append(entry.Addresses, a.String())
		}
		sort.Strings(entry.Addresses)
		out.Interfaces = append(out.Interfaces, entry)
	}
	sort.Slice(out.Interfaces, func(i, j int) bool { return out.Interfaces[i].Name < out.Interfaces[j].Name })
	return out
}

// runStatusWriter publishes live gateway state for the web control plane:
//
//   - status file:  sessions / bytes / MFA state — every 3 s
//   - netinfo file: hostname + interfaces — every 30 s
//
// Writes are atomic (tmp + rename) so readers never see partial JSON.
func runStatusWriter(ctx context.Context, eng *tunnel.Engine, statusFile, netInfoFile string) {
	statusT := time.NewTicker(3 * time.Second)
	infoT := time.NewTicker(30 * time.Second)
	defer statusT.Stop()
	defer infoT.Stop()

	writeStatus := func() {
		if statusFile == "" {
			return
		}
		peers := eng.Stats()
		out := statusJSON{
			UpdatedAt: time.Now().Format(time.RFC3339),
			Listen:    eng.LocalAddr(),
			Peers:     make([]statusPeer, 0, len(peers)),
		}
		for _, p := range peers {
			sp := statusPeer{
				Name: p.Name, User: p.User, Role: p.Role, Remote: p.Remote,
				Connected: p.Connected, Authed: p.Authed, MFA: p.MFA,
				Rx: p.BytesIn, Tx: p.BytesOut,
				Since: p.Since, LastRecv: p.LastRecv,
				TunnelIP: p.TunnelIP, Routes: p.Routes,
			}
			if p.Enabled != nil {
				sp.Enabled = p.Enabled
			}
			if p.Connected {
				out.Totals.Online++
			}
			out.Peers = append(out.Peers, sp)
		}
		out.Totals.Registered = len(peers)
		if err := atomicWriteJSON(statusFile, out); err != nil {
			log.Printf("status writer: %v", err)
		}
	}

	writeNetInfo := func() {
		if netInfoFile == "" {
			return
		}
		if err := atomicWriteJSON(netInfoFile, netInfoSnapshot()); err != nil {
			log.Printf("netinfo writer: %v", err)
		}
	}

	writeStatus()
	writeNetInfo()
	for {
		select {
		case <-ctx.Done():
			return
		case <-statusT.C:
			writeStatus()
		case <-infoT.C:
			writeNetInfo()
		}
	}
}

// runServerStatusWriter publishes the hub snapshot to a JSON file, plus the
// host's network info every 30 s (the web UI auto-detects the address clients
// should dial from it, and the status file stays handy for debugging).
func runServerStatusWriter(ctx context.Context, api *serverapp.Server, path, netInfoPath string) {
	t := time.NewTicker(3 * time.Second)
	infoT := time.NewTicker(30 * time.Second)
	defer t.Stop()
	defer infoT.Stop()
	write := func() {
		if path == "" {
			return
		}
		if err := atomicWriteJSON(path, api.Snapshot()); err != nil {
			log.Printf("status writer: %v", err)
		}
	}
	writeNetInfo := func() {
		if netInfoPath == "" {
			return
		}
		if err := atomicWriteJSON(netInfoPath, netInfoSnapshot()); err != nil {
			log.Printf("netinfo writer: %v", err)
		}
	}
	write()
	writeNetInfo()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			write()
		case <-infoT.C:
			writeNetInfo()
		}
	}
}

// runAgentStatusWriter keeps a local snapshot of the agent's state, so the
// site operator can see (and script around) the tunnel without reading logs.
func runAgentStatusWriter(ctx context.Context, eng *tunnel.Engine, path string) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	write := func() {
		st := agentStatusJSON{
			UpdatedAt: time.Now().Format(time.RFC3339),
			Server:    eng.LocalAddr(),
			Serving:   eng.Forwarding(),
			Drops:     eng.AgentDrops(),
			PublicKey: base64.StdEncoding.EncodeToString(eng.PublicKey()),
		}
		if info := eng.AgentStatus(); info != nil {
			st.MFA = true
			st.TunnelIP = info.TunnelIP
			st.Connected = info.Serving || info.UptimeS > 0
		}
		for _, p := range eng.Stats() {
			if p.Connected {
				st.Connected = true
			}
		}
		if path == "" {
			return
		}
		if err := atomicWriteJSON(path, st); err != nil {
			log.Printf("agent status writer: %v", err)
		}
	}
	write()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			write()
		}
	}
}

type statusJSON struct {
	UpdatedAt string       `json:"updated_at"`
	Listen    string       `json:"listen"`
	Totals    statusTotals `json:"totals"`
	Peers     []statusPeer `json:"peers"`
}

type statusTotals struct {
	Registered int `json:"registered"`
	Online     int `json:"online"`
}

type statusPeer struct {
	Name      string   `json:"name"`
	User      string   `json:"user,omitempty"`
	Role      string   `json:"role,omitempty"`
	Remote    string   `json:"remote,omitempty"`
	Connected bool     `json:"connected"`
	Authed    bool     `json:"authed"`
	MFA       bool     `json:"mfa"`
	Since     string   `json:"since,omitempty"`
	LastRecv  string   `json:"last_recv,omitempty"`
	Rx        uint64   `json:"rx_bytes"`
	Tx        uint64   `json:"tx_bytes"`
	TunnelIP  string   `json:"tunnel_ip,omitempty"`
	Routes    []string `json:"routes,omitempty"`
	Enabled   *bool    `json:"enabled,omitempty"`
}

type netInfoJSON struct {
	UpdatedAt  string      `json:"updated_at"`
	Hostname   string      `json:"hostname"`
	Interfaces []ifaceInfo `json:"interfaces"`
}

type ifaceInfo struct {
	Name      string   `json:"name"`
	Up        bool     `json:"up"`
	Addresses []string `json:"addresses"`
}

func atomicWriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
