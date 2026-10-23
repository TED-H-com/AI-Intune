package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/model"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type lsDevice struct {
	Name, Path, KName, Type, Model, Serial, WWN, FSType, UUID, Label, PKName, Tran string
	Size                                                                           json.RawMessage
	RM, RO                                                                         json.RawMessage
	Mountpoints                                                                    []*string
	Mountpoint                                                                     *string
	Children                                                                       []lsDevice
}

func diskText(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= 32 && c <= 126 && b.Len() < 256 {
			b.WriteRune(c)
		}
	}
	return strings.TrimSpace(b.String())
}
func ParseBlockDevices(raw []byte) ([]model.BlockDevice, error) {
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("disk inventory exceeds limit")
	}
	var v struct{ Blockdevices []lsDevice }
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	truth := func(b json.RawMessage) bool { return string(b) == "true" || string(b) == "1" || string(b) == `"1"` }
	knownFlag := func(b json.RawMessage) bool {
		switch string(b) {
		case "true", "false", "0", "1", `"0"`, `"1"`:
			return true
		}
		return false
	}
	var convert func(lsDevice, int) (model.BlockDevice, error)
	convert = func(n lsDevice, depth int) (model.BlockDevice, error) {
		if depth > 32 {
			return model.BlockDevice{}, fmt.Errorf("disk tree too deep")
		}
		if n.Type == "disk" && (!knownFlag(n.RM) || !knownFlag(n.RO)) {
			return model.BlockDevice{}, fmt.Errorf("disk read-only or removable status is unknown")
		}
		size, _ := strconv.ParseInt(strings.Trim(string(n.Size), `"`), 10, 64)
		d := model.BlockDevice{Name: diskText(n.Name), Path: diskText(n.Path), KName: diskText(n.KName), Type: diskText(n.Type), SizeBytes: size, Model: diskText(n.Model), Serial: diskText(n.Serial), WWN: diskText(n.WWN), FSType: diskText(n.FSType), UUID: diskText(n.UUID), Label: diskText(n.Label), PKName: diskText(n.PKName), Transport: diskText(n.Tran), Removable: truth(n.RM), ReadOnly: truth(n.RO)}
		points := n.Mountpoints
		if n.Mountpoint != nil {
			points = append(points, n.Mountpoint)
		}
		for _, p := range points {
			if p != nil && *p != "" {
				s := diskText(*p)
				d.Mountpoints = append(d.Mountpoints, s)
				if s == "/" || s == "/boot" || strings.HasPrefix(s, "/boot/") {
					d.Boot = true
				}
			}
		}
		d.Member = d.Type == "lvm" || d.Type == "crypt" || strings.HasPrefix(d.Type, "raid") || d.FSType == "LVM2_member" || d.FSType == "linux_raid_member" || d.FSType == "crypto_LUKS" || d.FSType == "zfs_member" || d.FSType == "btrfs"
		for _, c := range n.Children {
			child, e := convert(c, depth+1)
			if e != nil {
				return d, e
			}
			d.Children = append(d.Children, child)
			d.Boot = d.Boot || child.Boot
			d.Member = d.Member || child.Member
		}
		return d, nil
	}
	var all []model.BlockDevice
	for _, n := range v.Blockdevices {
		d, e := convert(n, 0)
		if e != nil {
			return nil, e
		}
		all = append(all, d)
	}
	// Also cover flat util-linux output using the parent chain.
	parents := map[string]string{}
	boot := map[string]bool{}
	var walk func(model.BlockDevice)
	walk = func(d model.BlockDevice) {
		parents[d.KName] = d.PKName
		if d.Boot {
			boot[d.KName] = true
		}
		for _, c := range d.Children {
			walk(c)
		}
	}
	for _, d := range all {
		walk(d)
	}
	for k := range boot {
		for i := 0; i < 64 && k != ""; i++ {
			boot[k] = true
			k = parents[k]
		}
	}
	// Preserve flat children too: a disk with any reported descendant can
	// never look empty just because util-linux omitted the nested tree.
	flat := map[string][]model.BlockDevice{}
	for _, d := range all {
		if d.PKName != "" {
			flat[d.PKName] = append(flat[d.PKName], d)
		}
	}
	var attach func(model.BlockDevice, int) (model.BlockDevice, error)
	attach = func(d model.BlockDevice, depth int) (model.BlockDevice, error) {
		if depth > 32 {
			return d, fmt.Errorf("cyclic disk inventory")
		}
		for _, c := range flat[d.KName] {
			exists := false
			for _, old := range d.Children {
				if old.KName == c.KName {
					exists = true
				}
			}
			if !exists {
				d.Children = append(d.Children, c)
			}
		}
		for i, c := range d.Children {
			var err error
			d.Children[i], err = attach(c, depth+1)
			if err != nil {
				return d, err
			}
			d.Member = d.Member || d.Children[i].Member
		}
		return d, nil
	}
	out := []model.BlockDevice{}
	for _, d := range all {
		if d.Type == "disk" && !strings.HasPrefix(d.KName, "loop") && !strings.HasPrefix(d.KName, "zram") {
			d.Boot = d.Boot || boot[d.KName]
			var err error
			d, err = attach(d, 0)
			if err != nil {
				return nil, err
			}
			out = append(out, d)
		}
	}
	return out, nil
}

type diskOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *diskOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > 1<<20 {
		b.overflow = true
		return 0, fmt.Errorf("inventory too large")
	}
	return b.Buffer.Write(p)
}
func CollectBlockDevices(ctx context.Context) []model.BlockDevice {
	if runtime.GOOS != "linux" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, mount := range []string{"MOUNTPOINTS", "MOUNTPOINT"} {
		cmd := exec.CommandContext(ctx, "lsblk", "--json", "--bytes", "--output", "NAME,PATH,KNAME,TYPE,SIZE,MODEL,SERIAL,WWN,FSTYPE,UUID,LABEL,"+mount+",PKNAME,RM,RO,TRAN")
		var out diskOutput
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			if out.overflow {
				return nil
			}
			continue
		}
		d, e := ParseBlockDevices(out.Bytes())
		if e == nil {
			return d
		}
		return nil
	}
	return nil
}
