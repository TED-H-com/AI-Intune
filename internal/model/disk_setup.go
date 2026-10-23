package model

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// BlockDevice contains observed facts, never permission to format a device.
type BlockDevice struct {
	Name        string        `json:"name"`
	Path        string        `json:"path"`
	KName       string        `json:"kname"`
	Type        string        `json:"type"`
	SizeBytes   int64         `json:"size_bytes"`
	Model       string        `json:"model"`
	Serial      string        `json:"serial"`
	WWN         string        `json:"wwn"`
	FSType      string        `json:"fstype"`
	UUID        string        `json:"uuid"`
	Label       string        `json:"label"`
	Mountpoints []string      `json:"mountpoints"`
	PKName      string        `json:"pkname"`
	Removable   bool          `json:"removable"`
	ReadOnly    bool          `json:"read_only"`
	Transport   string        `json:"transport"`
	Boot        bool          `json:"boot"`
	Member      bool          `json:"member"`
	Children    []BlockDevice `json:"children"`
}

func UnusedDisk(d BlockDevice) bool {
	return d.Type == "disk" && !strings.HasPrefix(d.KName, "loop") && !strings.HasPrefix(d.KName, "zram") && !strings.HasPrefix(d.KName, "sr") && !strings.HasPrefix(d.Path, "/dev/loop") && !strings.HasPrefix(d.Path, "/dev/zram") && !strings.HasPrefix(d.Path, "/dev/sr") && !d.Removable && !d.ReadOnly && d.SizeBytes >= 1<<30 && len(d.Children) == 0 && d.FSType == "" && d.UUID == "" && d.Label == "" && len(d.Mountpoints) == 0 && !d.Boot && !d.Member && (strings.TrimSpace(d.Serial) != "" || strings.TrimSpace(d.WWN) != "") && diskDevice.MatchString(d.Path)
}

var diskDevice = regexp.MustCompile(`^/dev/[A-Za-z0-9_-]+$`)
var DiskJobID = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)
var diskMount = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
var diskLabel = regexp.MustCompile(`^[A-Za-z0-9_-]{1,16}$`)
var diskOwner = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,31}$`)

type DiskJob struct {
	ID         string `json:"id"`
	Device     string `json:"device"`
	Serial     string `json:"serial"`
	WWN        string `json:"wwn"`
	SizeBytes  int64  `json:"size_bytes"`
	Model      string `json:"model"`
	MountPoint string `json:"mount_point"`
	FSType     string `json:"fstype"`
	Label      string `json:"label"`
	Owner      string `json:"owner"`
}

func (j DiskJob) Validate() error {
	if !DiskJobID.MatchString(j.ID) || !diskDevice.MatchString(j.Device) || j.SizeBytes < 1<<30 || j.Serial == "" && j.WWN == "" || len(j.Serial) > 256 || len(j.WWN) > 256 || len(j.Model) > 256 {
		return fmt.Errorf("Invalid disk identity")
	}
	for _, s := range []string{j.Serial, j.WWN, j.Model} {
		for _, c := range s {
			if c < 32 || c > 126 {
				return fmt.Errorf("Invalid disk identity")
			}
		}
	}
	m := j.MountPoint
	if len(m) > 256 || !diskMount.MatchString(m) || m == "/" || strings.Contains(m, "..") || path.Clean(m) != m {
		return fmt.Errorf("Choose an absolute mount point without ..")
	}
	for _, p := range []string{"/etc", "/usr", "/boot", "/proc", "/sys", "/dev", "/run"} {
		if m == p || strings.HasPrefix(m, p+"/") {
			return fmt.Errorf("Choose a mount point outside system directories")
		}
	}
	if strings.HasPrefix(m, "/var/lib/clawctl") {
		return fmt.Errorf("Choose a mount point outside system directories")
	}
	if j.FSType != "ext4" && j.FSType != "xfs" {
		return fmt.Errorf("Choose ext4 or xfs")
	}
	if !diskLabel.MatchString(j.Label) || !diskOwner.MatchString(j.Owner) || j.Owner == "root" {
		return fmt.Errorf("Enter a label and a non-root owner user")
	}
	return nil
}

type DiskJobResult struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
	Step       string `json:"step,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	Partition  string `json:"partition,omitempty"`
	MountPoint string `json:"mount_point,omitempty"`
	FSType     string `json:"fstype,omitempty"`
	DF         string `json:"df,omitempty"`
}

func (r DiskJobResult) Valid() bool {
	if !DiskJobID.MatchString(r.ID) || (r.State != "done" && r.State != "refused" && r.State != "failed") {
		return false
	}
	for _, s := range []string{r.Reason, r.Step, r.UUID, r.Partition, r.MountPoint, r.FSType, r.DF} {
		if len(s) > 512 {
			return false
		}
		for _, c := range s {
			if c < 32 || c > 126 {
				return false
			}
		}
	}
	return true
}
