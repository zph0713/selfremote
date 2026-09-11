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

type wgTun struct {
	dev tun.Device

	scratch [][]byte
	sizes   []int
	pending [][]byte
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
		n, err := w.dev.Read(w.scratch, w.sizes, offset)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}
		for i := 1; i < n; i++ {
			w.pending = append(w.pending, append([]byte(nil), w.scratch[i][:w.sizes[i]]...))
		}
		return copy(buf[offset:], w.scratch[0][:w.sizes[0]]), nil
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
	return &wgTun{dev: dev}, nil
}

// configureInterface assigns the tunnel address, brings the interface up and
// adds the extra routes pointing at the device.
func configureInterface(dev Device, cidr string, routes []string) error {
	name, err := dev.Name()
	if err != nil {
		return fmt.Errorf("device name: %w", err)
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("invalid tunnel_cidr %q: %w", cidr, err)
	}
	switch runtime.GOOS {
	case "linux":
		if out, err := run("ip", "addr", "add", cidr, "dev", name); err != nil {
			return fmt.Errorf("ip addr add: %w (%s)", err, out)
		}
		if out, err := run("ip", "link", "set", "dev", name, "up"); err != nil {
			return fmt.Errorf("ip link up: %w (%s)", err, out)
		}
		for _, r := range routes {
			if out, err := run("ip", "route", "add", r, "dev", name); err != nil {
				return fmt.Errorf("ip route add %s: %w (%s)", r, err, out)
			}
		}
	case "darwin":
		ip := p.Addr().String()
		mask := net.IPMask(net.CIDRMask(p.Bits(), 32)).String()
		if out, err := run("ifconfig", name, "inet", ip, ip, "netmask", mask, "up"); err != nil {
			return fmt.Errorf("ifconfig: %w (%s)", err, out)
		}
		for _, r := range routes {
			if out, err := run("route", "-n", "add", "-net", r, "-interface", name); err != nil {
				return fmt.Errorf("route add %s: %w (%s)", r, err, out)
			}
		}
	default:
		return fmt.Errorf("interface configuration not implemented on %s", runtime.GOOS)
	}
	return nil
}

// teardownInterface reverses configureInterface, best effort.
func teardownInterface(dev Device, cidr string, routes []string) {
	name, err := dev.Name()
	if err != nil {
		return
	}
	switch runtime.GOOS {
	case "linux":
		for _, r := range routes {
			run("ip", "route", "del", r, "dev", name)
		}
		run("ip", "addr", "del", cidr, "dev", name)
	case "darwin":
		for _, r := range routes {
			run("route", "-n", "delete", "-net", r)
		}
		run("ifconfig", name, "down")
	}
}

func run(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	return string(out), err
}
