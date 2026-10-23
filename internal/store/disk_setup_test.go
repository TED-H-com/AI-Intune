package store

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"testing"
	"time"
)

func setupDiskFixture(t *testing.T) (*Store, model.DiskJob, time.Time) {
	t.Helper()
	s := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	s.nowFn = func() time.Time { return now }
	if err := s.UpsertMachine(Machine{MachineID: "disk-machine", DisplayName: "Example", OS: "linux", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	d := model.BlockDevice{Type: "disk", Path: "/dev/nvme1n1", KName: "nvme1n1", Model: "Example", Serial: "example", SizeBytes: 2 << 30}
	if err := s.RecordObservation("disk-machine", model.ObservationBatch{MeasuredAt: now, BlockDevices: []model.BlockDevice{d}}, now); err != nil {
		t.Fatal(err)
	}
	return s, model.DiskJob{Device: d.Path, Model: d.Model, Serial: d.Serial, SizeBytes: d.SizeBytes, MountPoint: "/data", FSType: "ext4", Label: "data", Owner: "agent"}, now
}
func TestDiskSetupLifecycle(t *testing.T) {
	s, j, now := setupDiskFixture(t)
	id, err := s.ApproveDiskSetup("disk-machine", j, AuditEntry{At: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ApproveDiskSetup("disk-machine", j, AuditEntry{At: now}); err == nil {
		t.Fatal("duplicate active job")
	}
	jobs, err := s.DeliverDiskJobs("disk-machine")
	if err != nil || len(jobs) != 1 || jobs[0].ID != id {
		t.Fatal(jobs, err)
	}
	jobs, err = s.DeliverDiskJobs("disk-machine")
	if err != nil || len(jobs) != 1 {
		t.Fatal("lost delivery retry", jobs, err)
	}
	if err = s.CancelDiskSetup("disk-machine", id, AuditEntry{}); err == nil {
		t.Fatal("cancelled delivered job")
	}
	result := model.DiskJobResult{ID: id, State: "done", UUID: "12345678", MountPoint: "/data", FSType: "ext4", DF: "example"}
	batch := model.ObservationBatch{MeasuredAt: now, DiskJobResults: []model.DiskJobResult{result}}
	for i := 0; i < 2; i++ {
		if err = s.RecordObservation("disk-machine", batch, now); err != nil {
			t.Fatal(err)
		}
	}
	batch.DiskJobResults[0].State = "failed"
	if err = s.RecordObservation("disk-machine", batch, now); err != nil {
		t.Fatal(err)
	}
	out, err := s.MachineDisks("disk-machine")
	if err != nil || out.Jobs[0].State != "done" {
		t.Fatal(out, err)
	}
	jobs, err = s.DeliverDiskJobs("disk-machine")
	if err != nil || len(jobs) != 0 {
		t.Fatal(jobs, err)
	}
	for _, action := range []string{"disk_setup_approve", "disk_setup_result"} {
		var n int
		if err = s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, action).Scan(&n); err != nil || n != 1 {
			t.Fatal(action, n, err)
		}
	}
}
func TestDiskSetupExpiryCancelAndIdentity(t *testing.T) {
	s, j, now := setupDiskFixture(t)
	id, err := s.ApproveDiskSetup("disk-machine", j, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CancelDiskSetup("disk-machine", id, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='disk_setup_cancel'`).Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
	if _, err = s.ApproveDiskSetup("disk-machine", j, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	s.nowFn = func() time.Time { return now.Add(24 * time.Hour) }
	jobs, err := s.DeliverDiskJobs("disk-machine")
	if err != nil || len(jobs) != 0 {
		t.Fatal(jobs, err)
	}
	out, err := s.MachineDisks("disk-machine")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range out.Jobs {
		if r.State != "expired" {
			t.Fatal(r)
		}
	}
	j.Serial = "different"
	if _, err = s.ApproveDiskSetup("disk-machine", j, AuditEntry{}); err == nil {
		t.Fatal("identity mismatch approved")
	}
}
func TestDiskSetupResultsBoundAndAtomicAudit(t *testing.T) {
	s, j, now := setupDiskFixture(t)
	id, err := s.ApproveDiskSetup("disk-machine", j, AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DeliverDiskJobs("disk-machine")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.UpsertMachine(Machine{MachineID: "other", OS: "linux", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	b := model.ObservationBatch{MeasuredAt: now, DiskJobResults: []model.DiskJobResult{{ID: id, State: "refused", Reason: "Disk is mounted"}}}
	if err = s.RecordObservation("other", b, now); err != nil {
		t.Fatal(err)
	}
	out, _ := s.MachineDisks("disk-machine")
	if out.Jobs[0].State != "delivered" {
		t.Fatal("cross-machine result accepted")
	}
	if _, err = s.db.Exec(`CREATE TRIGGER reject_disk_audit BEFORE INSERT ON audit_log WHEN NEW.action='disk_setup_result' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordObservation("disk-machine", b, now); err == nil {
		t.Fatal("audit failure ignored")
	}
	out, _ = s.MachineDisks("disk-machine")
	if out.Jobs[0].State != "delivered" {
		t.Fatal("result not rolled back")
	}
}

func TestEmptyDiskInventoryClearsOldFacts(t *testing.T) {
	s, _, now := setupDiskFixture(t)
	batch := model.ObservationBatch{MeasuredAt: now, BlockDevices: []model.BlockDevice{}}
	// Preserve a measured empty inventory across the actual JSON wire.
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.ObservationBatch
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.BlockDevices == nil {
		t.Fatal("empty inventory lost on the wire")
	}
	if err = s.RecordObservation("disk-machine", decoded, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	out, err := s.MachineDisks("disk-machine")
	if err != nil || len(out.Devices) != 0 {
		t.Fatal(out, err)
	}
}
