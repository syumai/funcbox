package policy

import "net"

// alibabaMetadataIP is the metadata service address used on Alibaba
// Cloud ECS instances (analogous to AWS/GCP's 169.254.169.254, which
// is already covered by the link-local range).
var alibabaMetadataIP = net.IPv4(100, 100, 100, 200)

// BlockedIP reports whether ip should never be dialed by a function's
// outbound fetch, regardless of fetch policy: loopback, link-local
// (including the 169.254.169.254 cloud metadata address, which falls
// within 169.254.0.0/16), unspecified, multicast, and the Alibaba
// Cloud metadata address (100.100.100.200/32) all return true.
//
// BlockedIP is a pure function of the address; it does not know about
// organization overrides. The runtime layer decides whether and how
// an organization setting may relax this guard.
func BlockedIP(ip net.IP) bool {
	if ip == nil {
		// Fail closed: an address we can't classify is never safe to dial.
		return true
	}
	if ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil && ip4.Equal(alibabaMetadataIP) {
		return true
	}
	return false
}
