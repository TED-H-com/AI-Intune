package scriptcatalog

import "testing"

func TestOSFamily(t *testing.T) {
	for raw, want := range map[string]string{
		"Ubuntu 22.04.5 LTS": "linux", "Ubuntu 26.04.1 LTS": "linux", "Debian GNU/Linux 12": "linux", "Oracle Linux Server 9": "linux",
		"macOS 15": "darwin", "Windows 11 Pro": "windows", "Darwin": "darwin", "Mac OS X": "darwin", "": "", "unknown": "", "FreeBSD": "", "6.8.0": "",
		"Fedora 42": "linux", "RHEL 9": "linux", "Rocky Linux 9": "linux", "AlmaLinux 9": "linux", "CentOS 9": "linux", "Arch Linux": "linux", "Alpine Linux": "linux", "openSUSE Leap": "linux", "Amazon Linux": "linux",
	} {
		t.Run(raw, func(t *testing.T) {
			if got := OSFamily(raw); got != want {
				t.Fatalf("OSFamily(%q)=%q, want %q", raw, got, want)
			}
			e := Entry{AllowedOS: []string{want}}
			if e.AllowsOS(raw) != (want != "") {
				t.Fatal("AllowsOS mismatch")
			}
		})
	}
}
