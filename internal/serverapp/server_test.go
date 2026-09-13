package serverapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"selfremote/internal/tunnel"
)

func mustKeypair(t *testing.T) (priv, pub string) {
	t.Helper()
	// Distinct bytes are enough: the API never completes a handshake.
	return base64.StdEncoding.EncodeToString(make([]byte, 32)),
		base64.StdEncoding.EncodeToString(bytes32(1))
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func newTestAPI(t *testing.T) (*Server, *tunnel.Engine) {
	t.Helper()
	priv, _ := mustKeypair(t)
	_ = priv
	eng, err := tunnel.New(tunnel.Options{
		Mode:       tunnel.ModeServer,
		PrivateKey: bytes32(9),
		Listen:     "127.0.0.1:0",
		TunnelCIDR: "10.77.0.1/24",
		Peers: []tunnel.PeerConfig{
			{
				Name: "home", ID: "home", PublicKey: bytes32(2), Role: tunnel.RoleAgent, Enabled: true,
				TunnelIP: netip.MustParseAddr("10.77.0.101"),
				Routes:   []tunnel.RouteMap{{Real: netip.MustParsePrefix("192.168.1.0/24"), Virtual: netip.MustParsePrefix("10.200.7.0/24")}},
			},
			{
				Name: "mac", PublicKey: bytes32(3), Role: tunnel.RoleClient, Enabled: true,
				TunnelIP: netip.MustParseAddr("10.77.0.2"), AllowAgents: []string{"home"},
			},
		},
		SkipNetConfig: true, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); eng.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return New(Config{Engine: eng, Version: "test", Token: "tok"}), eng
}

func get(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestStatusEndpoint(t *testing.T) {
	api, _ := newTestAPI(t)
	h := api.Handler()

	// Without the token: refused.
	if rec := get(t, h, "/api/v1/status", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status without token = %d, want 401", rec.Code)
	}
	rec := get(t, h, "/api/v1/status", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var st Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Version != "test" || st.TunnelCIDR != "10.77.0.1/24" {
		t.Errorf("status = %+v", st)
	}
	if st.Totals.AgentsTotal != 1 || st.Totals.ClientsTotal != 1 {
		t.Errorf("totals = %+v", st.Totals)
	}
	if st.Totals.AgentsOnline != 0 || st.Totals.ClientsOnline != 0 {
		t.Errorf("nothing should be online yet: %+v", st.Totals)
	}

	// Agents listing carries the routes and the enable switch.
	rec = get(t, h, "/api/v1/agents", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("agents = %d", rec.Code)
	}
	var body struct {
		Agents []tunnel.PeerStats `json:"agents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Agents) != 1 || body.Agents[0].ID != "home" {
		t.Fatalf("agents = %+v", body.Agents)
	}
	if len(body.Agents[0].Routes) != 1 || !strings.Contains(body.Agents[0].Routes[0], "10.200.7.0/24") {
		t.Errorf("agent routes = %v", body.Agents[0].Routes)
	}
	if body.Agents[0].Enabled == nil || !*body.Agents[0].Enabled {
		t.Errorf("agent enabled flag missing")
	}
}

func TestAgentCommands(t *testing.T) {
	api, _ := newTestAPI(t)
	h := api.Handler()

	post := func(path string) int {
		req := httptest.NewRequest("POST", path, nil)
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// Known agent: accepted (it is offline, so no frame is sent, but the
	// command endpoint must not error).
	if code := post("/api/v1/agents/home/kick"); code != http.StatusOK {
		t.Errorf("kick = %d, want 200", code)
	}
	if code := post("/api/v1/agents/home/refresh"); code != http.StatusOK {
		t.Errorf("refresh = %d, want 200", code)
	}
	if code := post("/api/v1/agents/nope/kick"); code != http.StatusNotFound {
		t.Errorf("kick(unknown) = %d, want 404", code)
	}
}
