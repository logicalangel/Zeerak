package mcp

import "net"

// cidrContains reports whether cidr (e.g. "10.0.0.0/8") covers ip.
// Returns false on parse errors.
func cidrContains(cidr, ip string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	return n.Contains(addr)
}
