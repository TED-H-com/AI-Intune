// Package netidentity defines the bounded LAN address disclosure shared by the
// observer and operator projection. Addresses are evidence, never identity keys.
package netidentity

import "net/netip"

const MaxLANIPv4 = 16

var tailscaleIPv4 = netip.MustParsePrefix("100.64.0.0/10")

// ValidLANIPv4 accepts canonical unicast IPv4, including private subnets, but
// excludes loopback, link-local, unspecified, multicast and Tailscale's range.
func ValidLANIPv4(value string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.Is4() && ip.String() == value && ip.IsGlobalUnicast() && !tailscaleIPv4.Contains(ip)
}
