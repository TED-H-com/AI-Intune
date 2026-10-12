package scriptcatalog

import "strings"

// OSFamily converts a reported OS name or kernel platform to a catalog family.
// Unrecognized names fail closed rather than being assumed to be Linux.
func OSFamily(raw string) string {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" || name == "unknown" {
		return ""
	}
	if strings.Contains(name, "windows") {
		return "windows"
	}
	for _, marker := range []string{"darwin", "macos", "mac os x"} {
		if strings.Contains(name, marker) {
			return "darwin"
		}
	}
	for _, marker := range []string{"linux", "ubuntu", "debian", "fedora", "rhel", "red hat", "rocky", "alma", "almalinux", "centos", "arch", "alpine", "suse", "opensuse", "gentoo", "raspbian", "mint", "nixos", "kali", "pop!_os"} {
		for _, word := range strings.Fields(name) {
			if word == marker || (marker == "linux" && strings.HasSuffix(word, "/linux")) {
				return "linux"
			}
		}
		if marker == "red hat" && strings.Contains(name, marker) {
			return "linux"
		}
	}
	return ""
}
