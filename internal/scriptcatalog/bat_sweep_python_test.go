package scriptcatalog

import (
	"os/exec"
	"testing"
)

func TestBATSweepFakeConnector(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python 3 unavailable")
	}
	cmd := exec.Command(python, "-B", "-m", "unittest", "bat_sweep_test")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("BAT tests: %v\n%s", err, out)
	}
}
