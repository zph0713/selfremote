package webapp

import (
	"net/netip"
	"testing"
)

func mustP(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad prefix %q: %v", s, err)
	}
	return p
}

func TestAllocVirtualPrefixSkipsUsed(t *testing.T) {
	used := []netip.Prefix{mustP(t, "10.201.0.0/24"), mustP(t, "10.201.1.0/24")}
	got, err := allocVirtualPrefix(mustP(t, "192.168.1.0/24"), used)
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	if got.String() != "10.201.2.0/24" {
		t.Fatalf("want 10.201.2.0/24, got %s", got)
	}
}

// The virtual pool itself must not count as "reserved" for candidates, or every
// allocation fails (this bit us once: pool exhaustion on the second site).
func TestAllocVirtualPrefixWorksWithNoUsed(t *testing.T) {
	got, err := allocVirtualPrefix(mustP(t, "192.168.1.0/24"), nil)
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	if got.String() != "10.201.0.0/24" {
		t.Fatalf("want 10.201.0.0/24, got %s", got)
	}
}

func TestAllocVirtualPrefixKeepsMaskLength(t *testing.T) {
	got, err := allocVirtualPrefix(mustP(t, "10.1.0.0/16"), nil)
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	if got.Bits() != 16 {
		t.Fatalf("mask length changed: %s", got)
	}
}

func TestAssignRoutesAutoUsesRealWhenFree(t *testing.T) {
	routes, err := assignRoutesPure(routeModeAuto, []AgentRoute{{Real: "192.168.1.0/24"}}, nil)
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if routes[0].Virtual != "" {
		t.Fatalf("expected identity mapping, got %+v", routes[0])
	}
}

func TestAssignRoutesAutoVirtualizesOnCollision(t *testing.T) {
	used := []netip.Prefix{mustP(t, "192.168.1.0/24")}
	routes, err := assignRoutesPure(routeModeAuto, []AgentRoute{{Real: "192.168.1.0/24"}}, used)
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if routes[0].Virtual != "10.201.0.0/24" {
		t.Fatalf("want auto virtual 10.201.0.0/24, got %+v", routes[0])
	}
}

func TestAssignRoutesRealModeRejectsCollision(t *testing.T) {
	used := []netip.Prefix{mustP(t, "192.168.1.0/24")}
	if _, err := assignRoutesPure(routeModeReal, []AgentRoute{{Real: "192.168.1.0/24"}}, used); err == nil {
		t.Fatal("real mode should reject a colliding prefix")
	}
}

func TestAssignRoutesVirtualModeAlwaysRemaps(t *testing.T) {
	routes, err := assignRoutesPure(routeModeVirtual, []AgentRoute{{Real: "192.168.7.0/24"}}, nil)
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if routes[0].Virtual != "10.201.0.0/24" {
		t.Fatalf("want virtual mapping, got %+v", routes[0])
	}
}

func TestAssignRoutesRealPrefixInsidePoolGetsVirtualized(t *testing.T) {
	routes, err := assignRoutesPure(routeModeAuto, []AgentRoute{{Real: "10.201.0.0/24"}}, nil)
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	// 真实网段落在虚拟池里：必须换一个虚拟网段，且不能是它自己
	if routes[0].Virtual == "" || routes[0].Virtual == "10.201.0.0/24" {
		t.Fatalf("real prefix inside the pool must be remapped, got %+v", routes[0])
	}
}

func TestAssignRoutesManualMappingWins(t *testing.T) {
	used := []netip.Prefix{mustP(t, "192.168.1.0/24")}
	routes, err := assignRoutesPure(routeModeAuto,
		[]AgentRoute{{Real: "192.168.1.0/24", Virtual: "10.200.7.0/24"}}, used)
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if routes[0].Virtual != "10.200.7.0/24" {
		t.Fatalf("manual mapping ignored: %+v", routes[0])
	}
}

func TestAssignRoutesRejectsTunnelOverlap(t *testing.T) {
	// 10.77.0.0/24 是隧道本身：auto 模式下要虚拟化，real 模式下要报错
	routes, err := assignRoutesPure(routeModeAuto, []AgentRoute{{Real: "10.77.0.0/24"}}, nil)
	if err != nil {
		t.Fatalf("auto should remap the tunnel prefix: %v", err)
	}
	if routes[0].Virtual == "" {
		t.Fatalf("tunnel prefix must be remapped, got %+v", routes[0])
	}
	if _, err := assignRoutesPure(routeModeReal, []AgentRoute{{Real: "10.77.0.0/24"}}, nil); err == nil {
		t.Fatal("real mode must reject the tunnel prefix")
	}
}

func TestNormalizeRouteMode(t *testing.T) {
	cases := map[string]string{
		"":         routeModeAuto,
		"auto":     routeModeAuto,
		"REAL":     routeModeAuto, // unknown spellings fall back to auto
		"real":     routeModeReal,
		"virtual":  routeModeVirtual,
		"nonsense": routeModeAuto,
	}
	for in, want := range cases {
		if got := normalizeRouteMode(in); got != want {
			t.Errorf("normalizeRouteMode(%q) = %q, want %q", in, got, want)
		}
	}
}
