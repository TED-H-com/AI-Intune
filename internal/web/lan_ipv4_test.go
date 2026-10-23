package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMachineLANIPv4(t *testing.T) {
	s, st := newServer(t)
	id := onlineMachine(t, st, "lan-fixture")
	body := get(t, s, "/machines/"+id)
	if dir := os.Getenv("CLAWCTL_LAN_SCREENSHOT_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "machine-before.html"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	b := batch(time.Now().UTC())
	b.Identity.LANIPv4 = []string{"192.168.10.3", "10.1.2.3", "100.64.0.1", "secret-marker"}
	if err := st.RecordObservation(id, b, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	body = get(t, s, "/machines/"+id)
	for _, value := range []string{"LAN 位址", "192.168.10.3", "10.1.2.3", "2 筆無效或重複"} {
		if !strings.Contains(body, value) {
			t.Errorf("missing %q", value)
		}
	}
	if strings.Contains(body, "secret-marker") {
		t.Fatal("invalid LAN value disclosed")
	}
	if dir := os.Getenv("CLAWCTL_LAN_SCREENSHOT_DIR"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "machine-after.html"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
