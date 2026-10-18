package main

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/store"
	"testing"
	"time"
)

func TestCheckinDiskJobsDeliveryAndCompletion(t *testing.T) {
	f := settingAPIFixture(t)
	now := time.Now().UTC()
	d := model.BlockDevice{Path: "/dev/nvme1n1", KName: "nvme1n1", Type: "disk", Serial: "example", Model: "Example", SizeBytes: 2 << 30}
	if err := f.store.RecordObservation(f.machine.id, model.ObservationBatch{MeasuredAt: now, BlockDevices: []model.BlockDevice{d}}, now); err != nil {
		t.Fatal(err)
	}
	j := model.DiskJob{Device: d.Path, Serial: d.Serial, Model: d.Model, SizeBytes: d.SizeBytes, MountPoint: "/data", FSType: "ext4", Label: "data", Owner: "agent"}
	id, err := f.store.ApproveDiskSetup(f.machine.id, j, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	r := settingCheckin(t, f, now, "")
	if len(r.DiskJobs) != 1 || r.DiskJobs[0].ID != id {
		t.Fatal(r.DiskJobs)
	}
	if err = f.store.RecordObservation(f.machine.id, model.ObservationBatch{MeasuredAt: now, DiskJobResults: []model.DiskJobResult{{ID: id, State: "refused", Reason: "Disk is mounted"}}}, now); err != nil {
		t.Fatal(err)
	}
	r = settingCheckin(t, f, now.Add(time.Minute), "")
	if len(r.DiskJobs) != 0 {
		t.Fatal("finished job delivered")
	}
}
