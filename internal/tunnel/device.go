package tunnel

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"

	"golang.zx2c4.com/wireguard/tun"
)

// Device is the minimal view of a TUN device the engine needs. The
// wireguard-go tun.Device (batch oriented) is adapted to this single-packet
// interface by wgTun.
type Device interface {
	// Read reads one IP packet into buf[offset:] and returns its length.
	Read(buf []byte, offset int) (int, error)
	// Write writes one IP packet from buf[offset:] and returns bytes written.
	Write(buf []byte, offset int) (int, error)
	Name() (string, error)
	Close() error
}

// virtioNetHdrLen is the virtio-net header size. wireguard-go's Linux tun
// always requests IFF_VNET_HDR and, when the kernel supports GSO/GRO offloads,
// switches to "vnet mode": Write then requires the packet to be preceded by a
// 10-byte virtio-net header (offset must be >= 10), and Read may return several
// packets per call (a GSO super-packet split into segments). We always write
// with a zeroed header (plain packets, no GSO) and queue extra read segments.
const virtioNetHdrLen = 10

// utunHeaderLen is the per-packet header (address family, host byte order)
// that macOS utun sockets prepend. wireguard-go's darwin Read/Write require a
// buffer offset of at least this size: data lands at [offset-utunHeaderLen:]
// and the packet itself starts at offset.
const utunHeaderLen = 4

type wgTun struct {
	dev tun.Device

	// readOff is the offset passed to the underlying Device.Read; packets end
	// up at scratch[i][readOff : readOff+size]. macOS needs >= utunHeaderLen
	// (offset 0 panics inside wireguard-go with "slice bounds out of range
	// [-4:]"); the Linux implementation is field-proven with 0.
	readOff int

	scratch [][]byte
	sizes   []int
	pending [][]byte
}

// readOffsetFor returns the read offset a platform requires.
func readOffsetFor(goos string) int {
	if goos == "darwin" {
		return utunHeaderLen
	}
	return 0
}

func (w *wgTun) Read(buf []byte, offset int) (int, error) {
	for {
		if len(w.pending) > 0 {
			p := w.pending[0]
			w.pending = w.pending[1:]
			return copy(buf[offset:], p), nil
		}
		if w.scratch == nil {
			nb := w.dev.BatchSize()
			if nb < 1 {
				nb = 1
			}
			w.scratch = make([][]byte, nb)
			for i := range w.scratch {
				w.scratch[i] = make([]byte, maxDatagram)
			}
			w.sizes = make([]int, nb)
		}
		n, err := w.dev.Read(w.scratch, w.sizes, w.readOff)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}
		for i := 1; i < n; i++ {
			w.pending = append(w.pending, append([]byte(nil), w.scratch[i][w.readOff:w.readOff+w.sizes[i]]...))
		}
		return copy(buf[offset:], w.scratch[0][w.readOff:w.readOff+w.sizes[0]]), nil
	}
}

func (w *wgTun) Write(buf []byte, offset int) (int, error) {
	pkt := buf[offset:]
	if len(pkt) == 0 {
		return 0, nil
	}
	full := make([]byte, virtioNetHdrLen+len(pkt))
	copy(full[virtioNetHdrLen:], pkt)
	if _, err := w.dev.Write([][]byte{full}, virtioNetHdrLen); err != nil {
		return 0, err
	}
	return len(pkt), nil
}

func (w *wgTun) Name() (string, error) { return w.dev.Name() }
func (w *wgTun) Close() error          { return w.dev.Close() }

// CreateTUN creates the platform TUN device: "sr0" on Linux and Windows
// (Windows needs wintun.dll at runtime), "utun" on macOS.
func CreateTUN(mtu int) (Device, error) {
	name := "sr0"
	if runtime.GOOS == "darwin" {
		name = "utun"
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun device: %w", err)
	}
	return &wgTun{dev: dev, readOff: readOffsetFor(runtime.GOOS)}, nil
}

// ifaceCommands builds the platform commands that configure (and tear down)
// the tunnel interface. It is deliberately a pure function so every platform's
// command plan can be unit-tested from any OS (the macOS path in particular
// cannot be exercised from a Linux CI container).
func ifaceCommands(goos, name, cidr string, routes []string) (add, del [][]string, err error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid tunnel_cidr %q: %w", cidr, err)
	}
	switch goos {
	case "linux":
		add = append(add, []string{"ip", "addr", "add", cidr, "dev", name})
		add = append(add, []string{"ip", "link", "set", "dev", name, "up"})
		for _, r := range routes {
			add = append(add, []string{"ip", "route", "add", r, "dev", name})
			del = append(del, []string{"ip", "route", "del", r, "dev", name})
		}
		del = append(del, []string{"ip", "addr", "del", cidr, "dev", name})
	case "darwin":
		ip := p.Addr().String()
		// macOS ifconfig wants a dotted-quad netmask ("255.255.255.0").
		// net.IPMask.String() returns hex ("ffffff00") which ifconfig rejects
		// with "bad value" — use net.IP(mask).String() instead.
		mask := net.IP(net.CIDRMask(p.Bits(), 32)).String()
		add = append(add, []string{"ifconfig", name, "inet", ip, ip, "netmask", mask, "up"})
		for _, r := range routes {
			pr, err := netip.ParsePrefix(r)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid route %q: %w", r, err)
			}
			// -net/-netmask with a network address is accepted by every macOS
			// version (the bare CIDR suffix is not universally supported).
			// Deletion is best-effort: bringing the interface down purges its
			// routes anyway.
			add = append(add, []string{
				"route", "-n", "add",
				"-net", pr.Masked().Addr().String(),
				"-netmask", net.IP(net.CIDRMask(pr.Bits(), 32)).String(),
				"-interface", name,
			})
			del = append(del, []string{"route", "-n", "delete", "-net", r})
		}
		del = append(del, []string{"ifconfig", name, "down"})
	default:
		return nil, nil, fmt.Errorf("interface configuration not implemented on %s", goos)
	}
	return add, del, nil
}

// configureInterface assigns the tunnel address, brings the interface up and
// adds the extra routes pointing at the device.
func configureInterface(dev Device, cidr string, routes []string) error {
	name, err := dev.Name()
	if err != nil {
		return fmt.Errorf("device name: %w", err)
	}
	add, _, err := ifaceCommands(runtime.GOOS, name, cidr, routes)
	if err != nil {
		return err
	}
	for _, cmd := range add {
		if out, err := run(cmd...); err != nil {
			return fmt.Errorf("%s %s: %w (%s)", cmd[0], cmd[1], err, out)
		}
	}
	return nil
}

// teardownInterface reverses configureInterface, best effort.
func teardownInterface(dev Device, cidr string, routes []string) {
	name, err := dev.Name()
	if err != nil {
		return
	}
	_, del, err := ifaceCommands(runtime.GOOS, name, cidr, routes)
	if err != nil {
		return
	}
	for _, cmd := range del {
		run(cmd...)
	}
}

func run(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	return string(out), err
}
