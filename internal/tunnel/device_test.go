package tunnel

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
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
		{"route", "-n", "add", "-net", "192.168.2.0", "-netmask", "255.255.255.0", "-interface", "utun5"},
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

	// Route targets are normalized to network address + dotted netmask
	// (the bare CIDR suffix is not valid on every macOS version).
	add20, _, err := ifaceCommands("darwin", "utun5", "10.77.0.2/24", []string{"192.168.16.5/20"})
	if err != nil {
		t.Fatal(err)
	}
	want20 := []string{"route", "-n", "add", "-net", "192.168.16.0", "-netmask", "255.255.240.0", "-interface", "utun5"}
	if !reflect.DeepEqual(add20[1], want20) {
		t.Fatalf("/20 route =\n got %q\nwant %q", add20[1], want20)
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

// ------------------------------------------------------- read-offset contract

// fakeTun emulates the offset semantics of a platform tun.Device.
type fakeTun struct {
	batches   [][]byte // packets to hand out
	darwin    bool     // emulate macOS: data at [offset-4:], packet starts at offset
	batchSize int
}

func (f *fakeTun) File() *os.File           { return nil }
func (f *fakeTun) MTU() (int, error)        { return 1360, nil }
func (f *fakeTun) Name() (string, error)    { return "faketun0", nil }
func (f *fakeTun) Events() <-chan tun.Event { return nil }
func (f *fakeTun) Close() error             { return nil }

func (f *fakeTun) BatchSize() int {
	if f.batchSize > 0 {
		return f.batchSize
	}
	return 1
}

func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(f.batches) == 0 {
		return 0, errors.New("no packets queued")
	}
	if f.darwin && offset < 4 {
		// wireguard-go's darwin Read does bufs[0][offset-4:]; replicate the
		// resulting panic so a regression is caught by this test.
		_ = bufs[0][offset-4:]
	}
	n := 0
	for _, pkt := range f.batches {
		if n >= len(bufs) {
			break
		}
		if f.darwin {
			region := bufs[n][offset-4:]
			region[0], region[1], region[2], region[3] = 0, 0, 0, 0
			copy(region[4:], pkt)
		} else {
			copy(bufs[n][offset:], pkt)
		}
		sizes[n] = len(pkt)
		n++
	}
	f.batches = nil
	return n, nil
}

func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	return len(bufs), nil
}

func TestReadOffsetFor(t *testing.T) {
	if got := readOffsetFor("darwin"); got != utunHeaderLen {
		t.Fatalf("darwin read offset = %d, want %d", got, utunHeaderLen)
	}
	if got := readOffsetFor("linux"); got != 0 {
		t.Fatalf("linux read offset = %d, want 0", got)
	}
}

// TestWgTunReadDarwinOffset pins the fix for the real-world panic
// "slice bounds out of range [-4:]" seen on a Mac: wireguard-go's darwin tun
// requires a read offset of at least 4 and places the packet at [offset:].
func TestWgTunReadDarwinOffset(t *testing.T) {
	pkt := testPacket(0x42)
	dev := &fakeTun{batches: [][]byte{pkt}, darwin: true}
	w := &wgTun{dev: dev, readOff: readOffsetFor("darwin")}
	buf := make([]byte, 2048)
	n, err := w.Read(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], pkt) {
		t.Fatalf("darwin read mismatch:\n got %x\nwant %x", buf[:n], pkt)
	}

	// Regression guard: with readOff 0 the darwin contract is violated (this
	// is the exact crash from the field).
	bad := &wgTun{dev: &fakeTun{batches: [][]byte{pkt}, darwin: true}, readOff: 0}
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("readOff=0 must violate the darwin offset contract")
			}
		}()
		_, _ = bad.Read(buf, 0)
	}()
}

func TestWgTunReadLinuxAndPendingQueue(t *testing.T) {
	a, b := testPacket(1), testPacket(2)
	dev := &fakeTun{batches: [][]byte{a, b}, batchSize: 2}
	w := &wgTun{dev: dev, readOff: readOffsetFor("linux")}
	buf := make([]byte, 4096)

	n, err := w.Read(buf, 0)
	if err != nil || !bytes.Equal(buf[:n], a) {
		t.Fatalf("linux read #1 (err=%v)", err)
	}
	n, err = w.Read(buf, 0) // served from the pending queue
	if err != nil || !bytes.Equal(buf[:n], b) {
		t.Fatalf("linux read #2 from pending queue (err=%v)", err)
	}
}
