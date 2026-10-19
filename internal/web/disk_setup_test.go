package web

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDiskSetupFormsAndReadAPI(t *testing.T) {
	s, st := newServer(t)
	now := time.Now().UTC()
	if err := st.UpsertMachine(store.Machine{MachineID: "example-disk", DisplayName: "Example disk host", OS: "linux", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	d := model.BlockDevice{Type: "disk", Path: "/dev/nvme1n1", KName: "nvme1n1", Serial: "example", Model: "Example", SizeBytes: 2 << 30}
	used := d
	used.Path = "/dev/sda"
	used.FSType = "ext4"
	b := model.ObservationBatch{MeasuredAt: now, BlockDevices: []model.BlockDevice{d, used}, Readiness: &model.ReadinessFacts{ServiceUser: "agent", Config: model.ReadinessConfig{AutoRemediate: true}}}
	if err := st.RecordObservation("example-disk", b, now); err != nil {
		t.Fatal(err)
	}
	admin := diskWebPrincipal(true, false, "")
	viewer := diskWebPrincipal(false, false, "")
	path := "/machines/example-disk"
	w := diskWebRequest(t, s, "GET", path, nil, viewer, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Ready to set up") || strings.Contains(w.Body.String(), "Approve disk setup") || !strings.Contains(w.Body.String(), "</html>") {
		t.Fatal(w.Code, "viewer disk page incorrect")
	}
	w = diskWebRequest(t, s, "GET", path, nil, admin, false)
	if w.Code != 200 || strings.Count(w.Body.String(), ">Approve disk setup</button>") != 1 || !strings.Contains(w.Body.String(), `name="owner" value="agent"`) {
		t.Fatal(w.Code, "admin form incorrect")
	}
	form := url.Values{"device": {d.Path}, "mount_point": {"/data"}, "fstype": {"ext4"}, "label": {"data"}, "owner": {"agent"}, "confirm": {"yes"}}
	approve := path + "/disks/approve"
	if w = diskWebRequest(t, s, "POST", approve, form, viewer, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	stale := diskWebPrincipal(true, true, "example-admin")
	if w = diskWebRequest(t, s, "POST", approve, form, stale, false); w.Code != 403 {
		t.Fatal("missing MFA accepted", w.Code)
	}
	stale.MFAVerifiedAt = now.Add(-time.Hour)
	if w = diskWebRequest(t, s, "POST", approve, form, stale, false); w.Code != 403 {
		t.Fatal("stale MFA accepted", w.Code)
	}
	for key, value := range map[string]string{"mount_point": "/etc/data", "fstype": "other", "label": "bad label", "owner": "root", "device": "/dev/sda", "confirm": ""} {
		original := form.Get(key)
		form.Set(key, value)
		w = diskWebRequest(t, s, "POST", approve, form, admin, false)
		form.Set(key, original)
		if w.Code != 400 {
			t.Fatalf("%s: %d", key, w.Code)
		}
	}
	form.Set("force", "true")
	w = diskWebRequest(t, s, "POST", approve, form, admin, false)
	form.Del("force")
	if w.Code != 400 {
		t.Fatal("unknown field", w.Code)
	}
	stale.MFAVerifiedAt = time.Now()
	if w = diskWebRequest(t, s, "POST", approve, form, stale, false); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = diskWebRequest(t, s, "GET", path, nil, admin, false); strings.Contains(w.Body.String(), ">Approve disk setup</button>") || !strings.Contains(w.Body.String(), ">Cancel</button>") {
		t.Fatal("active job form wrong")
	}
	if w = diskWebRequest(t, s, "GET", "/v1/operator/machines/example-disk/disks", nil, viewer, false); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"pending"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	jobs, _ := st.MachineDisks("example-disk")
	cancel := url.Values{"job_id": {jobs.Jobs[0].Job.ID}}
	if w = diskWebRequest(t, s, "POST", path+"/disks/cancel", cancel, admin, false); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
}
