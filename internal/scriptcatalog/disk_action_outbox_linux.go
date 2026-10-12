//go:build linux

package scriptcatalog

import (
	"encoding/json"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
)

type DiskOutboxItem struct {
	JobID string
	Name  string
	Data  json.RawMessage
}

func diskOutboxDirectory() (*os.File, error) {
	account, err := user.Current()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(account.HomeDir, ".local/state/ai-intune/quarantine")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	file := os.NewFile(uintptr(fd), "quarantine outbox")
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
		file.Close()
		return nil, os.ErrPermission
	}
	return file, nil
}
func DiskActionOutbox() []DiskOutboxItem {
	if os.Geteuid() == 0 {
		return nil
	}
	dir, err := diskOutboxDirectory()
	if err != nil {
		return nil
	}
	defer dir.Close()
	out := []DiskOutboxItem{}
	for len(out) < 100 {
		names, err := dir.Readdirnames(256)
		if err != nil && err != io.EOF {
			return out
		}
		if len(names) == 0 {
			break
		}
		for _, name := range names {
			if !strings.HasPrefix(name, "result-") || !strings.HasSuffix(name, ".json") || len(out) >= 100 {
				continue
			}
			fd, e := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if e != nil {
				continue
			}
			file := os.NewFile(uintptr(fd), "action receipt")
			var st syscall.Stat_t
			if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
				file.Close()
				continue
			}
			raw, e := io.ReadAll(io.LimitReader(file, (256<<10)+1))
			file.Close()
			if e != nil || len(raw) > 256<<10 {
				continue
			}
			var receipt struct {
				Job string `json:"job_id"`
			}
			if json.Unmarshal(raw, &receipt) != nil || name != "result-"+receipt.Job+".json" {
				continue
			}
			ackFD, ackErr := syscall.Openat(int(dir.Fd()), name+".ack", syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if ackErr == nil {
				ack := os.NewFile(uintptr(ackFD), "receipt acknowledgement")
				mark, _ := io.ReadAll(io.LimitReader(ack, 65))
				ack.Close()
				if string(mark) == Digest(raw) {
					continue
				}
			}
			out = append(out, DiskOutboxItem{JobID: receipt.Job, Name: name, Data: raw})
		}
	}
	return out
}
func AcknowledgeDiskOutbox(item DiskOutboxItem) {
	dir, err := diskOutboxDirectory()
	if err != nil {
		return
	}
	defer dir.Close()
	if item.Name != "result-"+item.JobID+".json" || strings.ContainsAny(item.Name, "/\\") {
		return
	}
	// Keep the bounded outbox journal. Atomic overwrite with an ack marker avoids
	// deleting a replacement after an acknowledgement race.
	fd, err := syscall.Openat(int(dir.Fd()), item.Name, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return
	}
	file := os.NewFile(uintptr(fd), "receipt")
	raw, err := io.ReadAll(io.LimitReader(file, (256<<10)+1))
	file.Close()
	if err != nil || string(raw) != string(item.Data) {
		return
	}
	ackFD, err := syscall.Openat(int(dir.Fd()), item.Name+".ack", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return
	}
	ack := os.NewFile(uintptr(ackFD), "receipt acknowledgement")
	_, err = ack.WriteString(Digest(item.Data))
	if err == nil {
		_ = ack.Sync()
	}
	ack.Close()
	_ = dir.Sync()
}
