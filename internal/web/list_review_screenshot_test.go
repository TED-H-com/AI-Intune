package web

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestListReviewScreenshots exports real SSR pages with synthetic registry data.
func TestListReviewScreenshots(t *testing.T) {
	dir := os.Getenv("CLAWCTL_LIST_SCREENSHOT_DIR")
	if dir == "" {
		t.Skip("set CLAWCTL_LIST_SCREENSHOT_DIR to export fixture HTML")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, st := newServer(t)
	onlineMachine(t, st, "build-linux-01")
	onlineMachine(t, st, "workstation-02")
	enroll(t, st, "field-laptop-03", time.Now().UTC())
	retired := onlineMachine(t, st, "workstation-02-old")
	if err := st.RetireMachine(retired, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, row := range [][3]string{{"unused-registration", "build-linux-01", "build-linux-01"}, {"abandoned-registration", "lab-host-04", "lab-host-04"}} {
		if _, err := st.DB().Exec(`INSERT INTO machine_registry(machine_id,display_name,hostname,created_at) VALUES(?,?,?,?)`, row[0], row[1], row[2], time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	for name, path := range map[string]string{
		"devices": "/machines?section=machines", "retired": "/machines?lifecycle=retired&section=machines",
		"cleanup": "/machines/lifecycle", "agents": "/jobs", "apps": "/apps", "reports": "/reports",
	} {
		body := get(t, s, path)
		if err := os.WriteFile(filepath.Join(dir, name+".html"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
