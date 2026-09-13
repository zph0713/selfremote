//go:build linux

package tunnel

import (
	"log"
	"os"
	"os/exec"
)

// SetupSiteForwarding prepares a Linux site host so tunnel traffic can reach
// the local network: IPv4 forwarding plus the SNAT/FORWARD rules (idempotent).
//
// It is best effort: without root/NET_ADMIN the calls fail and the operator
// gets a clear log line instead of a dead tunnel. Container deployments get the
// same rules from the image entrypoint, so running both is harmless.
func SetupSiteForwarding(tunnelCIDR string) {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		log.Printf("site: 开启 ip_forward 失败（%v）；内网不通时请在宿主机执行 sysctl -w net.ipv4.ip_forward=1", err)
	} else {
		log.Printf("site: net.ipv4.ip_forward = 1")
	}

	ipt := iptablesBinary()
	rules := [][]string{
		// 出内网前做源地址改写（除隧道口外的任何出口，多网卡无需指定接口名）
		{"-t", "nat", "-C", "POSTROUTING", "-s", tunnelCIDR, "!", "-o", "sr0", "-j", "MASQUERADE"},
		// 隧道进来的包只允许再出内网
		{"-C", "FORWARD", "-i", "sr0", "!", "-o", "sr0", "-j", "ACCEPT"},
		// 回包（conntrack 已建立）允许回隧道
		{"-C", "FORWARD", "!", "-i", "sr0", "-o", "sr0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	for _, r := range rules {
		if err := exec.Command(ipt, r...).Run(); err == nil {
			continue // 已存在
		}
		add := append([]string{}, r...)
		for i, a := range add {
			if a == "-C" {
				add[i] = "-A"
				break
			}
		}
		if out, err := exec.Command(ipt, add...).CombinedOutput(); err != nil {
			log.Printf("site: %s %v 失败（%v: %s）—— 站点内网可能不通", ipt, add, err, trimOutput(out))
		}
	}
}

func iptablesBinary() string {
	for _, name := range []string{"iptables-legacy", "iptables"} {
		if _, err := exec.LookPath(name); err == nil {
			return name
		}
	}
	return "iptables"
}

func trimOutput(b []byte) string {
	s := string(b)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
