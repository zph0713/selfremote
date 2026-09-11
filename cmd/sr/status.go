package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"sort"
	"time"

	"selfremote/internal/tunnel"
)

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
				Name: p.Name, User: p.User, Remote: p.Remote,
				Connected: p.Connected, Authed: p.Authed, MFA: p.MFA,
				Rx: p.BytesIn, Tx: p.BytesOut,
			}
			if !p.Since.IsZero() {
				sp.Since = p.Since.Format(time.RFC3339)
			}
			if !p.LastRecv.IsZero() {
				sp.LastRecv = p.LastRecv.Format(time.RFC3339)
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
		host, _ := os.Hostname()
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Printf("netinfo writer: %v", err)
			return
		}
		out := netInfoJSON{
			UpdatedAt:  time.Now().Format(time.RFC3339),
			Hostname:   host,
			Interfaces: make([]ifaceInfo, 0, len(ifaces)),
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
		if err := atomicWriteJSON(netInfoFile, out); err != nil {
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
	Name      string `json:"name"`
	User      string `json:"user,omitempty"`
	Remote    string `json:"remote,omitempty"`
	Connected bool   `json:"connected"`
	Authed    bool   `json:"authed"`
	MFA       bool   `json:"mfa"`
	Since     string `json:"since,omitempty"`
	LastRecv  string `json:"last_recv,omitempty"`
	Rx        uint64 `json:"rx_bytes"`
	Tx        uint64 `json:"tx_bytes"`
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
