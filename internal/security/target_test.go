package security

import "testing"

func TestValidatePrivateIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, ip string
		valid    bool
	}{
		{"rfc1918-10", "10.2.3.4", true}, {"rfc1918-172", "172.31.9.2", true}, {"rfc1918-192", "192.168.20.53", true},
		{"loopback", "127.0.0.1", true}, {"ipv6-ula", "fd12:3456::53", true}, {"ipv6-loopback", "::1", true},
		{"public-v4", "8.8.8.8", false}, {"public-v6", "2001:4860:4860::8888", false}, {"hostname", "dns.internal", false}, {"invalid", "not-an-ip", false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePrivateIP(tt.ip)
			if (err == nil) != tt.valid {
				t.Fatalf("ValidatePrivateIP(%q) error=%v, valid=%v", tt.ip, err, tt.valid)
			}
		})
	}
}
