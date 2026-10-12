package main

import (
	"context"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"net/url"
	"strings"
	"time"
)

func syncDiskActionOutbox(ctx context.Context, hub, token string) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, item := range scriptcatalog.DiskActionOutbox() {
		if ctx.Err() != nil {
			return
		}
		var receipt struct {
			Digest string `json:"digest"`
		}
		endpoint := strings.TrimRight(hub, "/") + "/v1/disk-actions/" + url.PathEscape(item.JobID) + "/results"
		if postJSONStrict(ctx, endpoint, token, item.Data, &receipt) == nil {
			scriptcatalog.AcknowledgeDiskOutbox(item)
		}
	}
}
