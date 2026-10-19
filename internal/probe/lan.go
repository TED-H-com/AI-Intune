package probe

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/teddashh/AI-Intune/internal/netidentity"
)

func lanIPv4() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	return collectLANIPv4(interfaces, func(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() })
}

// collectLANIPv4 uses native interfaces on every supported OS; no external CLI
// or network call is needed. Sorting makes multi-address truncation stable.
func collectLANIPv4(interfaces []net.Interface, addrs func(net.Interface) ([]net.Addr, error)) []string {
	seen := map[string]bool{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || excludedLANInterface(iface.Name) || nativeLANBridge(iface.Name) {
			continue
		}
		values, err := addrs(iface)
		if err != nil {
			continue
		}
		for _, addr := range values {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			value := ip.String()
			if netidentity.ValidLANIPv4(value) {
				seen[value] = true
			}
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	if len(values) > netidentity.MaxLANIPv4 {
		values = values[:netidentity.MaxLANIPv4]
	}
	return values
}

func excludedLANInterface(name string) bool {
	name = strings.ToLower(name)
	for _, prefix := range []string{"tailscale", "docker", "virbr", "br-", "bridge", "veth", "cni", "flannel", "podman", "utun", "vEthernet"} {
		if strings.HasPrefix(name, strings.ToLower(prefix)) {
			return true
		}
	}
	// Linux bridge names commonly use br0/br1 rather than Docker's br-*.
	return len(name) > 2 && strings.HasPrefix(name, "br") && name[2] >= '0' && name[2] <= '9'
}

// Linux bridges may have arbitrary names. Other platforms use the interface
// exclusions above (bridgeN / vEthernet); an absent sysfs entry is not an error.
func nativeLANBridge(name string) bool {
	if runtime.GOOS != "linux" || filepath.Base(name) != name {
		return false
	}
	_, err := os.Stat(filepath.Join("/sys/class/net", name, "bridge"))
	return err == nil
}
