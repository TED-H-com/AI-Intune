package web

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

type fakeDiskAlertsPageSource struct {
	machines              int
	listCalls, labelCalls int
	after                 string
}

func (f *fakeDiskAlertsPageSource) DiskAlertsPageAfter(after string) (store.DiskAlertsPage, error) {
	f.listCalls++
	f.after = after
	result := store.DiskAlertsPage{Next: "1:next"}
	for i := 0; i < store.DiskAlertsPageSize; i++ {
		result.Items = append(result.Items, store.DiskAlert{MachineID: fmt.Sprintf("machine-%d", i%f.machines)})
	}
	return result, nil
}
func (f *fakeDiskAlertsPageSource) DiskAlertMountLabels(ids []string) (map[string][]store.DiskMountUsage, error) {
	f.labelCalls++
	if len(ids) != f.machines {
		return nil, fmt.Errorf("expected %d machines, got %d", f.machines, len(ids))
	}
	labels := map[string][]store.DiskMountUsage{}
	for _, id := range ids {
		labels[id] = []store.DiskMountUsage{{Mount: "/data"}}
	}
	return labels, nil
}
func TestDiskAlertsPageQueryCountIndependentOfMachines(t *testing.T) {
	for _, machines := range []int{1, 10, 100} {
		source := &fakeDiskAlertsPageSource{machines: machines}
		page, err := loadDiskAlertsPage(source, "0:previous")
		if err != nil {
			t.Fatal(err)
		}
		if source.listCalls != 1 || source.labelCalls != 1 || source.after != "0:previous" || page.Next != "1:next" || len(page.Labels) != machines {
			t.Fatalf("source=%+v page=%+v", source, page)
		}
	}
}

func TestDiskAlertsWebPagination(t *testing.T) {
	s, st := newServer(t)
	machine := onlineMachine(t, st, "example-device")
	now := time.Now().UTC().Format(time.RFC3339)
	for i := 0; i < 101; i++ {
		if _, err := st.DB().Exec(`INSERT INTO disk_alerts(id,machine_id,condition_key,severity,opened_at,last_reading) VALUES(?,?,?,'critical',?,?)`, fmt.Sprintf("alert-%03d", i), machine, fmt.Sprintf("condition-%d", i), now, now); err != nil {
			t.Fatal(err)
		}
	}
	principal := diskWebPrincipal(true, false, "")
	first := diskWebRequest(t, s, "GET", "/tenant/disk-alerts", nil, principal, false)
	if first.Code != 200 || strings.Count(first.Body.String(), "Acknowledgement reason") != 100 || !strings.Contains(first.Body.String(), "Next page") {
		t.Fatal("first page not bounded", first.Code)
	}
	second := diskWebRequest(t, s, "GET", "/tenant/disk-alerts?after="+url.QueryEscape("0:alert-099"), nil, principal, false)
	if second.Code != 200 || strings.Count(second.Body.String(), "Acknowledgement reason") != 1 || strings.Contains(second.Body.String(), "Next page") {
		t.Fatal("last page incorrect", second.Code)
	}
}
