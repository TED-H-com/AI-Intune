package probe

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/teddashh/AI-Intune/internal/netidentity"
)

type lanTestAddr string

func (a lanTestAddr) Network() string { return "ip+net" }
func (a lanTestAddr) String() string  { return string(a) }

func TestLANIPv4NativeInterfaces(t *testing.T) {
	interfaces := []net.Interface{}
	values := map[string][]net.Addr{}
	for _, name := range []string{"eth0", "en0", "Wi-Fi", "lo", "tailscale0", "docker0", "virbr0", "br-abcd", "br0", "bridge100", "veth12", "vEthernet (WSL)", "utun2", "down", "broken"} {
		flags := net.FlagUp
		if name == "lo" {
			flags |= net.FlagLoopback
		}
		if name == "down" {
			flags = 0
		}
		interfaces = append(interfaces, net.Interface{Name: name, Flags: flags})
		values[name] = []net.Addr{lanTestAddr("172.20.0.1/16")}
	}
	values["eth0"] = []net.Addr{lanTestAddr("192.168.1.3/24"), lanTestAddr("100.100.1.1/32"), lanTestAddr("127.0.0.2/8"), lanTestAddr("169.254.1.1/16"), lanTestAddr("::1/128"), lanTestAddr("224.0.0.1/24"), lanTestAddr("bad")}
	values["en0"] = []net.Addr{lanTestAddr("192.168.1.3/24"), lanTestAddr("10.0.0.4/24")}
	values["Wi-Fi"] = []net.Addr{lanTestAddr("192.168.2.2/24")}
	got := collectLANIPv4(interfaces, func(i net.Interface) ([]net.Addr, error) {
		if i.Name == "broken" {
			return nil, errors.New("unavailable")
		}
		return values[i.Name], nil
	})
	want := []string{"10.0.0.4", "192.168.1.3", "192.168.2.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestLANIPv4BoundAndStableOrder(t *testing.T) {
	values := []net.Addr{}
	for i := 30; i > 0; i-- {
		values = append(values, lanTestAddr(fmt.Sprintf("10.0.0.%d/24", i)))
	}
	got := collectLANIPv4([]net.Interface{{Name: "eth0", Flags: net.FlagUp}}, func(net.Interface) ([]net.Addr, error) { return values, nil })
	if len(got) != netidentity.MaxLANIPv4 || got[0] != "10.0.0.1" {
		t.Fatalf("bad bounded addresses: %v", got)
	}
}
