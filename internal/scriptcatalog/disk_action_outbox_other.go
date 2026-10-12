//go:build !linux

package scriptcatalog

import "encoding/json"

type DiskOutboxItem struct {
	JobID string
	Name  string
	Data  json.RawMessage
}

func DiskActionOutbox() []DiskOutboxItem   { return nil }
func AcknowledgeDiskOutbox(DiskOutboxItem) {}
