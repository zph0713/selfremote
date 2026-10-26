package webapp

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	"time"
)

// The client pages are server-rendered from hub data that is absent in a test
// (no hub, no DB), so the interesting failures are template/field mismatches:
// those surface as execution errors, which is exactly what this test watches.
func renderPage(t *testing.T, page string, data pageData) string {
	t.Helper()
	funcs := template.FuncMap{
		"human_bytes": humanBytes,
		"since":       humanSince,
		"ts":          func(t time.Time) string { return t.Format(time.RFC3339) },
		"v":           func() string { return Version },
		"hasSite":     hasSite,
	}
	files := []string{"templates/base.html", "templates/_ports.html", "templates/" + page}
	tpl, err := template.New("base").Funcs(funcs).ParseFS(assets, files...)
	if err != nil {
		t.Fatalf("parse %s: %v", page, err)
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "base.html", data); err != nil {
		t.Fatalf("execute %s: %v", page, err)
	}
	return buf.String()
}

func TestClientsPageRenders(t *testing.T) {
	dev := Device{
		ID: 7, UserID: 1, Name: "mac", Username: "u", Enabled: true,
		CreatedAt: time.Now().Add(-time.Hour), TunnelIP: "10.77.0.2",
		Sites: []string{"home"},
	}
	rows := []clientRow{
		{Device: dev, Live: clientLive{State: "在线", Connected: true, Authed: true,
			RxBytes: 1024, TxBytes: 2048, RxBps: 512, TxBps: 256, LastSeen: time.Now().Format(time.RFC3339)}},
		{Device: Device{ID: 8, Name: "offline", Enabled: true}, Live: clientLive{State: "离线"}},
	}
	html := renderPage(t, "clients.html", pageData{
		Title: "客户端",
		User:  &User{ID: 1, Username: "u", IsAdmin: true},
		Data: map[string]any{
			"Clients": rows, "HubReachable": true, "IsAdmin": true,
		},
	})
	for _, want := range []string{"客户端连接", "mac", "10.77.0.2", "在线", "离线", "/clients/7"} {
		if !strings.Contains(html, want) {
			t.Errorf("clients.html missing %q", want)
		}
	}
}

func TestClientShowPageRendersWithPorts(t *testing.T) {
	dev := Device{
		ID: 7, UserID: 1, Name: "mac", Username: "u", Enabled: true,
		CreatedAt: time.Now().Add(-time.Hour), TunnelIP: "10.77.0.2",
		Sites: []string{"home"}, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	ports := []hubPort{{
		Proto: 6, ProtoName: "tcp", SiteIP: "10.200.7.50", Port: 445, Clients: 1,
		BytesToSite: 4096, BytesFromSite: 8192, BpsToSite: 1000, BpsFromSite: 2000,
		LastSeen: time.Now().Format(time.RFC3339),
	}}
	html := renderPage(t, "client_show.html", pageData{
		Title: "客户端 mac",
		User:  &User{ID: 1, Username: "u", IsAdmin: true},
		Data: map[string]any{
			"Device": dev, "Live": clientLive{State: "在线"}, "Ports": ports,
			"PortPeer": "mac", "PortLabel": "站点数", "HubReachable": true,
			"Fingerprint": pubFingerprint(dev.PublicKey), "Sites": dev.Sites,
		},
	})
	for _, want := range []string{"mac", "tcp", "10.200.7.50", "445", "活跃端口与流量"} {
		if !strings.Contains(html, want) {
			t.Errorf("client_show.html missing %q", want)
		}
	}
}

func TestClientStateTransitions(t *testing.T) {
	dev := &Device{Enabled: true}
	cases := []struct {
		name    string
		live    hubAgent
		hubUp   bool
		enabled bool
		want    string
	}{
		{"online", hubAgent{Connected: true, Authed: true}, true, true, "在线"},
		{"authenticating", hubAgent{Connected: true}, true, true, "认证中"},
		{"offline", hubAgent{}, true, true, "离线"},
		{"disabled", hubAgent{Connected: true, Authed: true}, true, false, "已停用"},
		{"hub down", hubAgent{Connected: true, Authed: true}, false, true, "服务端不可达"},
	}
	for _, c := range cases {
		dev.Enabled = c.enabled
		if got := clientState(dev, c.live, c.hubUp).State; got != c.want {
			t.Errorf("%s: state = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestPubFingerprint(t *testing.T) {
	if got := pubFingerprint("not-base64"); got != "" {
		t.Errorf("invalid key fingerprint = %q, want empty", got)
	}
	a := pubFingerprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	b := pubFingerprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if a == "" || a != b || len(a) != 16 {
		t.Errorf("fingerprint = %q (len %d), want stable 16 hex chars", a, len(a))
	}
	if strings.ToUpper(a) != a {
		t.Errorf("fingerprint %q should be upper case", a)
	}
}
