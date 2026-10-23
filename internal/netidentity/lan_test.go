package netidentity

import "testing"

func TestValidLANIPv4(t *testing.T) {
	for _, value := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "203.0.113.5"} {
		if !ValidLANIPv4(value) {
			t.Errorf("rejected %q", value)
		}
	}
	for _, value := range []string{"", "0.0.0.0", "127.1.2.3", "169.254.1.1", "224.1.1.1", "255.255.255.255", "100.64.0.0", "100.127.255.255", "::1", "::ffff:10.0.0.1", "010.0.0.1", "10.0.0.1/24", "10.0.0.1\nsecret"} {
		if ValidLANIPv4(value) {
			t.Errorf("accepted %q", value)
		}
	}
}
