// Package webapp implements the selfremote web control plane: registration,
// Google-Authenticator MFA, client key management and a live dashboard.
package webapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// User is a control-plane account.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	TOTPSecret   string
	TOTPEnabled  bool
	IsAdmin      bool
	CreatedAt    time.Time
}

// Device is one client key owned by a user.
type Device struct {
	ID        int64
	UserID    int64
	Name      string
	PublicKey string // base64
	Enabled   bool
	CreatedAt time.Time
	Username  string // joined for admin views

	// v0.3: the device's address on the tunnel network and the sites it may
	// reach (agent slugs). Both land in clients.json, which the hub enforces.
	TunnelIP string
	Sites    []string
}

// AgentRoute is one prefix a site agent serves.
type AgentRoute struct {
	Real    string `json:"real"`
	Virtual string `json:"virtual,omitempty"`
}

// Effective is the prefix clients address (the virtual one; identity when the
// agent did not need a remap).
func (r AgentRoute) Effective() string {
	if r.Virtual != "" {
		return r.Virtual
	}
	return r.Real
}

// Agent is one site edge registered in the control plane.
type Agent struct {
	ID         int64
	UserID     int64
	AgentID    string // slug used in ACLs and the agent registry
	Name       string
	PublicKey  string // base64
	TunnelIP   string // its own address on the tunnel network
	TOTPSecret string
	Enabled    bool
	Routes     []AgentRoute
	CreatedAt  time.Time
	Username   string
}

// Session is a web login session.
type Session struct {
	ID        string
	UserID    int64
	CSRF      string
	ExpiresAt time.Time
}

// RegistryRow is what the hub needs to know about one device.
type RegistryRow struct {
	DeviceName string
	Username   string
	PublicKey  string
	TOTPSecret string
	TunnelIP   string
	Sites      []string
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  totp_secret VARCHAR(64) NOT NULL DEFAULT '',
  totp_enabled TINYINT NOT NULL DEFAULT 0,
  is_admin TINYINT NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS recovery_codes (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  code_hash CHAR(64) NOT NULL,
  used TINYINT NOT NULL DEFAULT 0,
  KEY idx_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS devices (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  name VARCHAR(64) NOT NULL,
  public_key VARCHAR(64) NOT NULL UNIQUE,
  enabled TINYINT NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sessions (
  id CHAR(32) PRIMARY KEY,
  user_id BIGINT NOT NULL,
  csrf CHAR(32) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  KEY idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS agents (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  agent_id VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(64) NOT NULL,
  public_key VARCHAR(64) NOT NULL UNIQUE,
  tunnel_ip VARCHAR(45) NOT NULL DEFAULT '',
  totp_secret VARCHAR(64) NOT NULL DEFAULT '',
  enabled TINYINT NOT NULL DEFAULT 1,
  routes_json TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE devices ADD COLUMN IF NOT EXISTS tunnel_ip VARCHAR(45) NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS agents_json TEXT NULL;
`

func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	return db, nil
}

// migrate creates the schema (idempotent) and waits for the database to
// become reachable (the db container may still be starting).
func migrate(ctx context.Context, db *sql.DB) error {
	var err error
	for i := 0; i < 30; i++ {
		if err = db.PingContext(ctx); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		return err
	}
	for _, stmt := range strings.Split(schema, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- users

func (s *Server) countUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Server) createUser(ctx context.Context, username, passwordHash string, admin bool) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)`,
		username, passwordHash, admin)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var enabled, admin int
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &enabled, &admin, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.TOTPEnabled = enabled != 0
	u.IsAdmin = admin != 0
	return &u, nil
}

const userCols = `id, username, password_hash, totp_secret, totp_enabled, is_admin, created_at`

func (s *Server) userByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, name))
}

func (s *Server) userByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (s *Server) setTOTPSecret(ctx context.Context, userID int64, secret string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?`, secret, userID)
	return err
}

func (s *Server) enableTOTP(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_enabled = 1 WHERE id = ?`, userID)
	return err
}

// ---------------------------------------------------------------- sessions

func (s *Server) createSession(ctx context.Context, userID int64, id, csrf string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, csrf, expires_at) VALUES (?, ?, ?, ?)`,
		id, userID, csrf, expires)
	return err
}

// sessionUser resolves a session id to (user, session); expired rows are
// removed on the way.
func (s *Server) sessionUser(ctx context.Context, sid string) (*User, *Session, error) {
	if sid == "" {
		return nil, nil, nil
	}
	var sess Session
	var expires time.Time
	var u User
	var enabled, admin int
	err := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.user_id, s.csrf, s.expires_at,
		       u.id, u.username, u.password_hash, u.totp_secret, u.totp_enabled, u.is_admin, u.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id = ?`, sid).
		Scan(&sess.ID, &sess.UserID, &sess.CSRF, &expires,
			&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &enabled, &admin, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	u.TOTPEnabled = enabled != 0
	u.IsAdmin = admin != 0
	if time.Now().After(expires) {
		_ = s.deleteSession(ctx, sid)
		return nil, nil, nil
	}
	sess.ExpiresAt = expires
	return &u, &sess, nil
}

func (s *Server) deleteSession(ctx context.Context, sid string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, sid)
	return err
}

func (s *Server) purgeExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < NOW()`)
	return err
}

// ---------------------------------------------------------------- recovery

func (s *Server) setRecoveryCodes(ctx context.Context, userID int64, hashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)`, userID, h); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Server) useRecoveryCode(ctx context.Context, userID int64, hash string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE recovery_codes SET used = 1 WHERE user_id = ? AND code_hash = ? AND used = 0`,
		userID, hash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ---------------------------------------------------------------- devices

const deviceCols = `d.id, d.user_id, d.name, d.public_key, d.enabled, d.created_at, d.tunnel_ip, d.agents_json, u.username`

func scanDevices(rows *sql.Rows) ([]Device, error) {
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var enabled int
		var agentsJSON sql.NullString
		if err := rows.Scan(&d.ID, &d.UserID, &d.Name, &d.PublicKey, &enabled, &d.CreatedAt,
			&d.TunnelIP, &agentsJSON, &d.Username); err != nil {
			return nil, err
		}
		d.Enabled = enabled != 0
		d.Sites = decodeSites(agentsJSON.String)
		out = append(out, d)
	}
	return out, rows.Err()
}

func decodeSites(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

func encodeSites(sites []string) string {
	if len(sites) == 0 {
		return "[]"
	}
	raw, err := json.Marshal(sites)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

func (s *Server) devicesByUser(ctx context.Context, userID int64) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+deviceCols+` FROM devices d JOIN users u ON u.id = d.user_id
		 WHERE d.user_id = ? ORDER BY d.id`, userID)
	if err != nil {
		return nil, err
	}
	return scanDevices(rows)
}

func (s *Server) allDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+deviceCols+` FROM devices d JOIN users u ON u.id = d.user_id ORDER BY d.id`)
	if err != nil {
		return nil, err
	}
	return scanDevices(rows)
}

func (s *Server) deviceByID(ctx context.Context, id int64) (*Device, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+deviceCols+` FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = ?`, id)
	if err != nil {
		return nil, err
	}
	devs, err := scanDevices(rows)
	if err != nil || len(devs) == 0 {
		return nil, err
	}
	return &devs[0], nil
}

func (s *Server) addDevice(ctx context.Context, userID int64, name, publicKey, tunnelIP string, sites []string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO devices (user_id, name, public_key, tunnel_ip, agents_json) VALUES (?, ?, ?, ?, ?)`,
		userID, name, publicKey, tunnelIP, encodeSites(sites))
	return err
}

func (s *Server) setDeviceSites(ctx context.Context, id int64, sites []string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET agents_json = ? WHERE id = ?`, encodeSites(sites), id)
	return err
}

func (s *Server) setDeviceTunnelIP(ctx context.Context, id int64, ip string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET tunnel_ip = ? WHERE id = ?`, ip, id)
	return err
}

func (s *Server) deleteDevice(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
	return err
}

// registryRows returns every enabled device whose owner has MFA bound — the
// exact set the hub is allowed to accept.
func (s *Server) registryRows(ctx context.Context) ([]RegistryRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.name, u.username, d.public_key, u.totp_secret, d.tunnel_ip, d.agents_json
		FROM devices d JOIN users u ON u.id = d.user_id
		WHERE d.enabled = 1 AND u.totp_enabled = 1
		ORDER BY d.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RegistryRow
	for rows.Next() {
		var r RegistryRow
		var agentsJSON sql.NullString
		if err := rows.Scan(&r.DeviceName, &r.Username, &r.PublicKey, &r.TOTPSecret,
			&r.TunnelIP, &agentsJSON); err != nil {
			return nil, err
		}
		r.Sites = decodeSites(agentsJSON.String)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- agents

const agentCols = `a.id, a.user_id, a.agent_id, a.name, a.public_key, a.tunnel_ip, a.totp_secret, a.enabled, a.routes_json, a.created_at, u.username`

func scanAgents(rows *sql.Rows) ([]Agent, error) {
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		var enabled int
		var routesJSON string
		if err := rows.Scan(&a.ID, &a.UserID, &a.AgentID, &a.Name, &a.PublicKey, &a.TunnelIP,
			&a.TOTPSecret, &enabled, &routesJSON, &a.CreatedAt, &a.Username); err != nil {
			return nil, err
		}
		a.Enabled = enabled != 0
		if err := json.Unmarshal([]byte(routesJSON), &a.Routes); err != nil {
			return nil, fmt.Errorf("agent %s: routes: %w", a.AgentID, err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Server) allAgents(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+agentCols+` FROM agents a JOIN users u ON u.id = a.user_id ORDER BY a.agent_id`)
	if err != nil {
		return nil, err
	}
	return scanAgents(rows)
}

func (s *Server) agentsByUser(ctx context.Context, userID int64) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+agentCols+` FROM agents a JOIN users u ON u.id = a.user_id WHERE a.user_id = ? ORDER BY a.agent_id`,
		userID)
	if err != nil {
		return nil, err
	}
	return scanAgents(rows)
}

func (s *Server) agentByAgentID(ctx context.Context, agentID string) (*Agent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+agentCols+` FROM agents a JOIN users u ON u.id = a.user_id WHERE a.agent_id = ?`, agentID)
	if err != nil {
		return nil, err
	}
	as, err := scanAgents(rows)
	if err != nil || len(as) == 0 {
		return nil, err
	}
	return &as[0], nil
}

func (s *Server) agentByDBID(ctx context.Context, id int64) (*Agent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+agentCols+` FROM agents a JOIN users u ON u.id = a.user_id WHERE a.id = ?`, id)
	if err != nil {
		return nil, err
	}
	as, err := scanAgents(rows)
	if err != nil || len(as) == 0 {
		return nil, err
	}
	return &as[0], nil
}

func (s *Server) addAgent(ctx context.Context, a *Agent) error {
	routes, err := json.Marshal(a.Routes)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO agents (user_id, agent_id, name, public_key, tunnel_ip, totp_secret, enabled, routes_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.UserID, a.AgentID, a.Name, a.PublicKey, a.TunnelIP, a.TOTPSecret, boolInt(a.Enabled), string(routes))
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) setAgentEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET enabled = ? WHERE id = ?`, boolInt(enabled), id)
	return err
}

func (s *Server) setAgentTOTP(ctx context.Context, id int64, secret string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agents SET totp_secret = ? WHERE id = ?`, secret, id)
	return err
}

func (s *Server) deleteAgent(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM agents WHERE id = ?`, id)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
