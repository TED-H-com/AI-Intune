package operator

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/netidentity"
)

func TestLANIPv4ProjectionAndLegacyIdentity(t *testing.T) {
	var legacy model.Identity
	if err := json.Unmarshal([]byte(`{"hostname":"older-agent"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	empty := projectLANIPv4(legacy.LANIPv4)
	if empty.Items == nil || empty.Total != 0 || empty.Invalid != 0 || empty.Truncated {
		t.Fatalf("bad legacy projection: %+v", empty)
	}
	raw := []string{"10.0.0.1", "10.0.0.1", "127.0.0.1", "100.64.0.1", "secret-path-token\n"}
	for i := 2; i <= 20; i++ {
		raw = append(raw, fmt.Sprintf("10.0.0.%d", i))
	}
	got := projectLANIPv4(raw)
	if got.Total != 24 || got.Invalid != 4 || len(got.Items) != netidentity.MaxLANIPv4 || !got.Truncated {
		t.Fatalf("bad projection: %+v", got)
	}
	body, _ := json.Marshal(got)
	if strings.Contains(string(body), "secret") || strings.Contains(string(body), "127.0.0.1") {
		t.Fatalf("unsafe values disclosed: %s", body)
	}
}
