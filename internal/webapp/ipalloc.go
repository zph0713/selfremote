package webapp

import (
	"context"
	"fmt"
	"log"
)

// Tunnel addressing plan (must match the hub's expectations):
//
//	10.77.0.1          the hub itself (virtual address)
//	10.77.0.2-99       client devices
//	10.77.0.100-254    site agents
//
// Both ranges are served by the same hub, so they must not overlap.

const (
	tunnelPrefix  = "10.77.0."
	clientIPFirst = 2
	clientIPLast  = 99
	agentIPFirst  = 100
	agentIPLast   = 254
)

// tunnelIPsInUse lists every tunnel address already handed out.
func (s *Server) tunnelIPsInUse(ctx context.Context) (map[string]bool, error) {
	inUse := map[string]bool{}
	rows, err := s.db.QueryContext(ctx, `
		SELECT tunnel_ip FROM devices WHERE tunnel_ip <> ''
		UNION ALL
		SELECT tunnel_ip FROM agents WHERE tunnel_ip <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		inUse[ip] = true
	}
	return inUse, rows.Err()
}

func allocIP(inUse map[string]bool, first, last int) (string, error) {
	for i := first; i <= last; i++ {
		ip := fmt.Sprintf("%s%d", tunnelPrefix, i)
		if !inUse[ip] {
			inUse[ip] = true // reserve
			return ip, nil
		}
	}
	return "", fmt.Errorf("隧道地址池已用尽（%s%d-%d）", tunnelPrefix, first, last)
}

// allocClientIP reserves the next free device address.
func (s *Server) allocClientIP(ctx context.Context) (string, error) {
	inUse, err := s.tunnelIPsInUse(ctx)
	if err != nil {
		return "", err
	}
	return allocIP(inUse, clientIPFirst, clientIPLast)
}

// allocAgentIP reserves the next free agent address.
func (s *Server) allocAgentIP(ctx context.Context) (string, error) {
	inUse, err := s.tunnelIPsInUse(ctx)
	if err != nil {
		return "", err
	}
	return allocIP(inUse, agentIPFirst, agentIPLast)
}

// backfillTunnelIPs assigns addresses to rows created before v0.3, so an
// upgraded install keeps working without manual edits.
func (s *Server) backfillTunnelIPs(ctx context.Context) {
	inUse, err := s.tunnelIPsInUse(ctx)
	if err != nil {
		log.Printf("tunnel ip backfill: %v", err)
		return
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM devices WHERE tunnel_ip = '' ORDER BY id`)
	if err != nil {
		log.Printf("tunnel ip backfill: %v", err)
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		ip, err := allocIP(inUse, clientIPFirst, clientIPLast)
		if err != nil {
			log.Printf("tunnel ip backfill: %v", err)
			return
		}
		if err := s.setDeviceTunnelIP(ctx, id, ip); err != nil {
			log.Printf("tunnel ip backfill: device %d: %v", id, err)
			continue
		}
		log.Printf("tunnel ip backfill: device %d -> %s", id, ip)
	}
}
