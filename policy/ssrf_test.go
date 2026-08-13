package policy

import (
	"net"
	"testing"
)

func TestBlockedIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "IPv4 loopback", ip: "127.0.0.1", want: true},
		{name: "IPv6 loopback", ip: "::1", want: true},
		{name: "link-local", ip: "169.254.1.1", want: true},
		{name: "cloud metadata (AWS/GCP/Azure)", ip: "169.254.169.254", want: true},
		{name: "IPv6 link-local", ip: "fe80::1", want: true},
		{name: "unspecified IPv4", ip: "0.0.0.0", want: true},
		{name: "unspecified IPv6", ip: "::", want: true},
		{name: "multicast IPv4", ip: "224.0.0.1", want: true},
		{name: "multicast IPv6", ip: "ff02::1", want: true},
		{name: "Alibaba Cloud metadata", ip: "100.100.100.200", want: true},
		{name: "public IPv4", ip: "8.8.8.8", want: false},
		{name: "public IPv6", ip: "2001:4860:4860::8888", want: false},
		{name: "private RFC1918 is not blocked by this guard", ip: "10.0.3.7", want: false},
		{name: "another Alibaba /8-range address is not blocked", ip: "100.100.100.201", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) failed", tt.ip)
			}
			got := BlockedIP(ip)
			if got != tt.want {
				t.Errorf("BlockedIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestBlockedIP_Nil(t *testing.T) {
	if !BlockedIP(nil) {
		t.Fatal("BlockedIP(nil) = false, want true (fail closed)")
	}
}
