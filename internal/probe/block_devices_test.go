package probe

import (
	"context"
	"github.com/teddashh/AI-Intune/internal/model"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBlockDeviceFixtures(t *testing.T) {
	raw, err := os.ReadFile("testdata/disks/inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	ds, err := ParseBlockDevices(raw)
	if err != nil || len(ds) != 9 {
		t.Fatal(ds, err)
	}
	if !model.UnusedDisk(ds[0]) || !ds[1].Boot || !ds[2].Boot {
		t.Fatal(ds)
	}
	for i := 2; i <= 6; i++ {
		if !ds[i].Member {
			t.Errorf("member %d not detected", i)
		}
	}
	if !ds[7].Removable || !ds[8].ReadOnly {
		t.Fatal(ds)
	}
	if len(ds[1].Children) != 1 {
		t.Fatal("partition lost")
	}
	old := `{"blockdevices":[{"type":"disk","rm":false,"ro":false,"kname":"sda","mountpoint":"/boot"}]}`
	ds, err = ParseBlockDevices([]byte(old))
	if err != nil || !ds[0].Boot {
		t.Fatal(ds, err)
	}
	if diskText("a\nb\x00"+strings.Repeat("x", 300)) != "ab"+strings.Repeat("x", 254) {
		t.Fatal("sanitization")
	}
	for _, raw := range []string{"{", strings.Repeat(" ", (1<<20)+1)} {
		if _, err = ParseBlockDevices([]byte(raw)); err == nil {
			t.Fatal("invalid accepted")
		}
	}
}

func TestFlatDiskChildrenAndBootChain(t *testing.T) {
	ds, err := ParseBlockDevices([]byte(`{"blockdevices":[{"kname":"sda","path":"/dev/sda","type":"disk","rm":false,"ro":false,"serial":"example","size":2147483648},{"kname":"sda1","pkname":"sda","type":"part","fstype":"LVM2_member"},{"kname":"dm-0","pkname":"sda1","type":"lvm","mountpoints":["/"]}]}`))
	if err != nil || len(ds) != 1 || !ds[0].Boot || !ds[0].Member || len(ds[0].Children) != 1 || model.UnusedDisk(ds[0]) {
		t.Fatal(ds, err)
	}
}

func TestCollectBlockDevicesFallbackAndBound(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux inventory")
	}
	dir := t.TempDir()
	stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DISK_FIXTURE_CALLS\"\ncase \"$*\" in *MOUNTPOINTS*) exit 1;; esac\nprintf '%s\\n' \"$DISK_FIXTURE_JSON\"\n"
	if err := os.WriteFile(filepath.Join(dir, "lsblk"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls")
	t.Setenv("DISK_FIXTURE_CALLS", calls)
	t.Setenv("PATH", dir)
	t.Setenv("DISK_FIXTURE_JSON", `{"blockdevices":[{"type":"disk","path":"/dev/sda","kname":"sda","size":2147483648,"serial":"example","rm":false,"ro":false}]}`)
	ds := CollectBlockDevices(context.Background())
	if len(ds) != 1 || !model.UnusedDisk(ds[0]) {
		t.Fatal(ds)
	}
	raw, _ := os.ReadFile(calls)
	if strings.Count(string(raw), "--json") != 2 || !strings.Contains(string(raw), ",MOUNTPOINT,") {
		t.Fatal(string(raw))
	}
	b := &diskOutput{}
	if _, err := b.Write(make([]byte, (1<<20)+1)); err == nil || !b.overflow || b.Len() != 0 {
		t.Fatal("output limit missing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ds = CollectBlockDevices(ctx); ds != nil {
		t.Fatal("cancelled inventory returned disks")
	}
}

func TestDiskInventoryFailsClosedOnUnknownFlags(t *testing.T) {
	for _, raw := range []string{
		`{"blockdevices":[{"type":"disk","rm":null,"ro":false}]}`,
		`{"blockdevices":[{"type":"disk","rm":false}]}`,
		`{"blockdevices":[{"type":"disk","rm":false,"ro":"unknown"}]}`,
	} {
		if _, err := ParseBlockDevices([]byte(raw)); err == nil {
			t.Fatal("unknown disk flags accepted", raw)
		}
	}
}
