package webapp

import (
	"context"
	"fmt"
	"net/netip"
)

// ---------------------------------------------------------------------------
// 站点网段的对外呈现方式（server 级开关，网页可切换）
//
//	auto（默认）: 直接用站点真实网段；两个站点真的撞车时才给后来者分配虚拟网段
//	real        : 永远用真实网段（冲突则拒绝接入，让运维自己改网段）
//	virtual     : 永远分配虚拟网段（站点之间完全隔离，客户端只见 10.201.x）
//
// 虚拟化本身由站点侧做无状态地址翻译（internal/tunnel/addrmap.go），server 只按
// 注册表里的映射选路，所以切换模式不需要动 server。
// ---------------------------------------------------------------------------

const (
	routeModeAuto    = "auto"
	routeModeReal    = "real"
	routeModeVirtual = "virtual"
)

// virtualPoolBase 是虚拟网段的起点（10.201.0.0/16，最多 256 个 /24 站点）。
const virtualPoolBase = uint32(10)<<24 | uint32(201)<<16

func normalizeRouteMode(v string) string {
	switch v {
	case routeModeReal, routeModeVirtual:
		return v
	default:
		return routeModeAuto
	}
}

// reservedPrefixes 谁都不许占：隧道自身（以及将来可能加进来的保留段）。
func reservedPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.77.0.0/24"), // 隧道网段
	}
}

// poolPrefixes 是虚拟网段的分配池：站点「真实网段」落在池里时必须虚拟化，
// 但分配候选本身当然要落在这个池里 —— 所以两者要分开判断。
func poolPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.201.0.0/16"),
	}
}

func overlapsAny(p netip.Prefix, list []netip.Prefix) bool {
	for _, q := range list {
		if p.Overlaps(q) {
			return true
		}
	}
	return false
}

// otherEffectivePrefixes lists the prefixes other sites already publish.
func otherEffectivePrefixes(agents []Agent, self *Agent) []netip.Prefix {
	var out []netip.Prefix
	for i := range agents {
		a := agents[i]
		if self != nil && a.ID == self.ID {
			continue
		}
		for _, rt := range a.Routes {
			if p, err := netip.ParsePrefix(rt.Effective()); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// allocVirtualPrefix picks a free block of the same length out of the pool.
func allocVirtualPrefix(real netip.Prefix, used []netip.Prefix) (netip.Prefix, error) {
	bits := real.Bits()
	if bits < 8 || bits > 28 {
		return netip.Prefix{}, fmt.Errorf("网段 %s 的掩码长度不支持虚拟化（只支持 /8–/28）", real)
	}
	block := uint32(1) << uint(32-bits)
	for off := uint32(0); off < 1<<16; off += block {
		n := virtualPoolBase + off
		addr := netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
		cand := netip.PrefixFrom(addr, bits).Masked()
		if !overlapsAny(cand, used) && !overlapsAny(cand, reservedPrefixes()) {
			return cand, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("虚拟网段池已用尽（10.201.0.0/16）")
}

// assignRoutes turns a site's real prefixes into the published mapping, honouring
// the server's route mode. It returns a clear error when the mode forbids an
// unavoidable collision.
func (s *Server) assignRoutes(ctx context.Context, reals []AgentRoute, self *Agent) ([]AgentRoute, error) {
	mode := normalizeRouteMode(s.getSetting(ctx, routeModeKey, routeModeAuto))
	agents, err := s.allAgents(ctx)
	if err != nil {
		return nil, err
	}
	return assignRoutesPure(mode, reals, otherEffectivePrefixes(agents, self))
}

// assignRoutesPure is the testable core: given a mode and the prefixes other
// sites already publish, decide what this site hands out.
func assignRoutesPure(mode string, reals []AgentRoute, used []netip.Prefix) ([]AgentRoute, error) {
	mode = normalizeRouteMode(mode)
	used = append([]netip.Prefix(nil), used...) // don't mutate the caller's slice

	out := make([]AgentRoute, 0, len(reals))
	for _, rt := range reals {
		p, err := netip.ParsePrefix(rt.Real)
		if err != nil {
			return nil, fmt.Errorf("网段 %q 不是合法 CIDR", rt.Real)
		}
		// 手工指定的映射（"real => virtual"）优先，只做冲突检查。
		if rt.Virtual != "" {
			v, err := netip.ParsePrefix(rt.Virtual)
			if err != nil {
				return nil, fmt.Errorf("虚拟网段 %q 不是合法 CIDR", rt.Virtual)
			}
			if overlapsAny(v, used) || overlapsAny(v, reservedPrefixes()) {
				return nil, fmt.Errorf("手工指定的虚拟网段 %s 与已有站点或保留网段冲突", v)
			}
			out = append(out, AgentRoute{Real: p.String(), Virtual: v.String()})
			used = append(used, v)
			continue
		}
		reserved := overlapsAny(p, reservedPrefixes()) || overlapsAny(p, poolPrefixes())
		conflict := reserved || overlapsAny(p, used)

		wantVirtual := mode == routeModeVirtual || (mode == routeModeAuto && conflict)
		if mode == routeModeReal && conflict {
			why := "与已有站点冲突"
			if reserved {
				why = "落在保留网段（隧道/虚拟池）里"
			}
			return nil, fmt.Errorf("网段 %s %s，当前路由模式是「真实网段」：请改网段，或把控制面的路由模式切成 auto/virtual（也可以写成 %s => 10.200.7.0/24 手工指定）", p, why, p)
		}
		if wantVirtual {
			// 候选不能是它自己：把真实网段也算进「已占用」
			banned := append(append([]netip.Prefix(nil), used...), p)
			v, err := allocVirtualPrefix(p, banned)
			if err != nil {
				return nil, err
			}
			out = append(out, AgentRoute{Real: p.String(), Virtual: v.String()})
			used = append(used, v)
			continue
		}
		out = append(out, AgentRoute{Real: p.String()})
		used = append(used, p)
	}
	return out, nil
}

// routeModeLabel renders the mode for the UI.
func routeModeLabel(mode string) string {
	switch normalizeRouteMode(mode) {
	case routeModeReal:
		return "真实网段（冲突直接拒绝）"
	case routeModeVirtual:
		return "总是虚拟网段"
	default:
		return "自动（冲突才虚拟化）"
	}
}
