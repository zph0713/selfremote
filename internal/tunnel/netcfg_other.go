//go:build !linux

package tunnel

// SetupSiteForwarding is a no-op outside Linux: macOS sites rely on the
// system's own forwarding/NAT settings (and are mostly used for testing).
func SetupSiteForwarding(tunnelCIDR string) {}
