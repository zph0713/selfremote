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

// TestObservabilityEndpoints covers the M5.0 API surface: the overview, the
// per-peer port aggregate (empty until traffic flows) and the flow list. The
// content of those rows is exercised end-to-end in the tunnel package
// (TestHubRecordsPortFlows), which drives real relayed packets.
func TestObservabilityEndpoints(t *testing.T) {
	api, _ := newTestAPI(t)
	h := api.Handler()

	rec := get(t, h, "/api/v1/overview", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("overview = %d, body %s", rec.Code, rec.Body.String())
	}
	var ov Overview
	if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
		t.Fatal(err)
	}
	if ov.Status.Totals.AgentsTotal != 1 || ov.Status.Totals.ClientsTotal != 1 {
		t.Errorf("overview totals = %+v", ov.Status.Totals)
	}
	if ov.FlowEntries != 0 || ov.FlowDropped != 0 {
		t.Errorf("flow counters = (%d,%d), want zero before traffic", ov.FlowEntries, ov.FlowDropped)
	}

	// Clients endpoint lists the client peers only.
	rec = get(t, h, "/api/v1/clients", "tok")
	var cb struct {
		Clients []tunnel.PeerStats `json:"clients"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cb); err != nil {
		t.Fatal(err)
	}
	if len(cb.Clients) != 1 || cb.Clients[0].Name != "mac" {
		t.Errorf("clients = %+v, want the mac device", cb.Clients)
	}

	// Known peer with no traffic: an empty (not missing) port list.
	rec = get(t, h, "/api/v1/peers/home/ports", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("ports(home) = %d, body %s", rec.Code, rec.Body.String())
	}
	var pr PortsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &pr); err != nil {
		t.Fatal(err)
	}
	if pr.PeerID != "home" || pr.Ports == nil || len(pr.Ports) != 0 {
		t.Errorf("ports(home) = %+v, want an empty list for a known peer", pr)
	}
	if rec := get(t, h, "/api/v1/peers/nope/ports", "tok"); rec.Code != http.StatusNotFound {
		t.Errorf("ports(unknown) = %d, want 404", rec.Code)
	}

	// Flows endpoint is valid and empty.
	rec = get(t, h, "/api/v1/flows", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("flows = %d", rec.Code)
	}
	var fr FlowsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &fr); err != nil {
		t.Fatal(err)
	}
	if len(fr.Flows) != 0 {
		t.Errorf("flows = %d, want 0", len(fr.Flows))
	}

	// The bearer token is still required for all of them.
	if rec := get(t, h, "/api/v1/overview", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("overview without token = %d, want 401", rec.Code)
	}
	if rec := get(t, h, "/api/v1/peers/home/ports", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("ports without token = %d, want 401", rec.Code)
	}
}

// TestSnapshotIsCached pins the 1 s cache: several open browser tabs must not
// turn into several engine snapshots per second.
func TestSnapshotIsCached(t *testing.T) {
	api, _ := newTestAPI(t)
	first := api.Snapshot()
	second := api.Snapshot()
	if first.UpdatedAt != second.UpdatedAt {
		t.Errorf("snapshot not cached: %q != %q", first.UpdatedAt, second.UpdatedAt)
	}
}
