package store

import (
	appcatalog "github.com/teddashh/AI-Intune/internal/catalog"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"strings"
	"testing"
)

func TestScriptScheduleDiskOSPrettyNames(t *testing.T) {
	for _, raw := range []string{"Ubuntu 22.04.5 LTS", "Ubuntu 26.04.1 LTS", "Debian GNU/Linux 12", "Oracle Linux Server 9", "macOS 15", "Windows 11 Pro", "unknown", ""} {
		t.Run(raw, func(t *testing.T) {
			family := scriptcatalog.OSFamily(raw)
			for _, path := range []string{"script", "schedule", "disk"} {
				t.Run(path, func(t *testing.T) {
					s, r, a, _ := scriptFixture(t)
					if path == "disk" {
						s, r, _ = deepFixture(t)
						a = diskAdmin()
					}
					if _, err := s.db.Exec(`UPDATE machine_registry SET os=? WHERE machine_id=?`, raw, r.Targets[0]); err != nil {
						t.Fatal(err)
					}
					var err error
					if path == "schedule" {
						_, err = s.ScheduleManage(ScheduleRequest{Name: "pretty-os", ScriptID: r.ScriptID, ScriptSHA256: r.ScriptSHA256, Args: r.Args, Targets: r.Targets, Cron: "*/5 * * * *", Enabled: true, Reason: r.Reason}, "upsert", false, "", a)
					} else {
						_, err = s.ScriptRun(r, false, "", a)
					}
					if family == "linux" {
						if err != nil {
							t.Fatal(err)
						}
					} else if err == nil || !strings.Contains(err.Error(), "OS '"+raw+"' (family '"+family+"')") {
						t.Fatalf("expected raw OS and family rejection: %v", err)
					}
				})
			}
			p, err := appcatalog.PlatformFromProbeIdentity(raw, "amd64")
			if family == "" {
				if err == nil {
					t.Fatal("unknown deployment platform accepted")
				}
			} else if err != nil || p.OS != family {
				t.Fatalf("deployment platform: %+v %v", p, err)
			}
		})
	}
}

func TestScriptOSUsesLatestIdentityAndKernelPlatform(t *testing.T) {
	for _, tc := range []struct{ os, kernel, family string }{
		{"Ubuntu 26.04.1 LTS", "6.8.0", "linux"},
		{"Windows 11 Pro", "", "windows"},
		{"Ubuntu 22.04.5 LTS", "Darwin", "darwin"},
		{"unknown", "Linux", "linux"},
		{"", "6.8.0", "linux"},
	} {
		t.Run(tc.os+tc.kernel, func(t *testing.T) {
			s, r, a, now := scriptFixture(t)
			insertChangeObservation(t, s, "platform", r.Targets[0], KindIdentity, KindIdentity,
				`{"os":"`+tc.os+`","kernel":"`+tc.kernel+`","arch":"amd64"}`, fmtTime(now), fmtTime(now))
			_, err := s.ScriptRun(r, false, "", a)
			if tc.family == "linux" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "family '"+tc.family+"'") {
				t.Fatalf("wrong platform rejection: %v", err)
			}
			os, arch, err := s.MachinePlatformIdentity(r.Targets[0])
			if err != nil {
				t.Fatal(err)
			}
			target, err := appcatalog.PlatformFromProbeIdentity(os, arch)
			if err != nil || target.OS != tc.family {
				t.Fatalf("deployment identity %+v %v", target, err)
			}
		})
	}
}
