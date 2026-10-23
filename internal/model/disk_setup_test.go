package model

import "testing"

func TestUnusedDisk(t *testing.T) {
	base := BlockDevice{Type: "disk", Path: "/dev/nvme1n1", KName: "nvme1n1", Serial: "example", SizeBytes: 2 << 30}
	if !UnusedDisk(base) {
		t.Fatal("empty disk rejected")
	}
	cases := map[string]func(*BlockDevice){
		"partition": func(d *BlockDevice) { d.Type = "part" }, "loop": func(d *BlockDevice) { d.KName = "loop0" }, "zram": func(d *BlockDevice) { d.KName = "zram0" }, "rom": func(d *BlockDevice) { d.Type = "rom" }, "small": func(d *BlockDevice) { d.SizeBytes = (1 << 30) - 1 }, "removable": func(d *BlockDevice) { d.Removable = true }, "readonly": func(d *BlockDevice) { d.ReadOnly = true }, "children": func(d *BlockDevice) { d.Children = []BlockDevice{{}} }, "fstype": func(d *BlockDevice) { d.FSType = "ext4" }, "uuid": func(d *BlockDevice) { d.UUID = "example" }, "label": func(d *BlockDevice) { d.Label = "data" }, "mounted": func(d *BlockDevice) { d.Mountpoints = []string{"/data"} }, "boot": func(d *BlockDevice) { d.Boot = true }, "member": func(d *BlockDevice) { d.Member = true }, "identity": func(d *BlockDevice) { d.Serial = "" }, "path": func(d *BlockDevice) { d.Path = "/tmp/disk" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d := base
			change(&d)
			if UnusedDisk(d) {
				t.Fatal("unsafe disk offered")
			}
		})
	}
	base.Serial = ""
	base.WWN = "example"
	if !UnusedDisk(base) {
		t.Fatal("WWN should suffice")
	}
}
func TestDiskJobValidation(t *testing.T) {
	j := DiskJob{ID: "example-job", Device: "/dev/nvme1n1", Serial: "example", SizeBytes: 2 << 30, MountPoint: "/data", FSType: "ext4", Label: "data", Owner: "agent"}
	if err := j.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/", "/etc/data", "/usr/data", "/boot/data", "/proc/a", "/sys/a", "/dev/a", "/run/a", "/var/lib/clawctl-state", "/data/../etc", "/data//a", "relative", "/data x"} {
		t.Run(p, func(t *testing.T) {
			v := j
			v.MountPoint = p
			if v.Validate() == nil {
				t.Fatal("forbidden path accepted")
			}
		})
	}
}
