package tunnel

import (
	"reflect"
	"strings"
	"testing"
)

// TestIfaceCommandsDarwin pins the macOS command plan — especially the netmask
// format: macOS ifconfig rejects the hex form ("ffffff00") that
// net.IPMask.String() produces, so it must be dotted-quad. This exact bug once
// reached a real Mac because the macOS path had no coverage (all e2e runs used
// the Linux path).
func TestIfaceCommandsDarwin(t *testing.T) {
	add, del, err := ifaceCommands("darwin", "utun5", "10.77.0.2/24", []string{"192.168.2.0/24"})
	if err != nil {
		t.Fatalf("ifaceCommands: %v", err)
	}

	wantAdd := [][]string{
		{"ifconfig", "utun5", "inet", "10.77.0.2", "10.77.0.2", "netmask", "255.255.255.0", "up"},
		{"route", "-n", "add", "-net", "192.168.2.0/24", "-interface", "utun5"},
	}
	if !reflect.DeepEqual(add, wantAdd) {
		t.Fatalf("add commands:\n got %q\nwant %q", add, wantAdd)
	}

	wantDel := [][]string{
		{"route", "-n", "delete", "-net", "192.168.2.0/24"},
		{"ifconfig", "utun5", "down"},
	}
	if !reflect.DeepEqual(del, wantDel) {
		t.Fatalf("del commands:\n got %q\nwant %q", del, wantDel)
	}

	// Guard against the original bug explicitly.
	for _, cmd := range add {
		for _, arg := range cmd {
			if strings.Contains(arg, "ffffff") {
				t.Fatalf("hex netmask leaked into macOS command: %q", cmd)
			}
		}
	}

	// Non-/24 prefixes must also produce dotted-quad masks.
	add16, _, err := ifaceCommands("darwin", "utun5", "10.77.0.2/16", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := add16[0][6]; got != "255.255.0.0" {
		t.Fatalf("/16 netmask = %q, want 255.255.0.0", got)
	}
}

func TestIfaceCommandsLinux(t *testing.T) {
	add, del, err := ifaceCommands("linux", "sr0", "10.77.0.2/24", []string{"192.168.2.0/24"})
	if err != nil {
		t.Fatalf("ifaceCommands: %v", err)
	}
	wantAdd := [][]string{
		{"ip", "addr", "add", "10.77.0.2/24", "dev", "sr0"},
		{"ip", "link", "set", "dev", "sr0", "up"},
		{"ip", "route", "add", "192.168.2.0/24", "dev", "sr0"},
	}
	if !reflect.DeepEqual(add, wantAdd) {
		t.Fatalf("add commands:\n got %q\nwant %q", add, wantAdd)
	}
	wantDel := [][]string{
		{"ip", "route", "del", "192.168.2.0/24", "dev", "sr0"},
		{"ip", "addr", "del", "10.77.0.2/24", "dev", "sr0"},
	}
	if !reflect.DeepEqual(del, wantDel) {
		t.Fatalf("del commands:\n got %q\nwant %q", del, wantDel)
	}
}

func TestIfaceCommandsErrors(t *testing.T) {
	if _, _, err := ifaceCommands("windows", "sr0", "10.77.0.2/24", nil); err == nil {
		t.Fatal("windows must be reported as unsupported")
	}
	if _, _, err := ifaceCommands("darwin", "utun5", "not-a-cidr", nil); err == nil {
		t.Fatal("bad cidr must be rejected")
	}
}
