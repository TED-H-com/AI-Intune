package web

import (
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
	"strings"
)

type diskAlertTableView struct {
	Items    []diskAlertRow
	CanAdmin bool
}
type diskAlertRow struct {
	store.DiskAlert
	Label string
}

func diskAlertTable(items []store.DiskAlert, admin bool, labels ...map[string][]store.DiskMountUsage) diskAlertTableView {
	out := diskAlertTableView{CanAdmin: admin}
	for _, a := range items {
		out.Items = append(out.Items, diskAlertRow{DiskAlert: a, Label: diskAlertConditionLabel(a.ConditionKey, func() []store.DiskMountUsage {
			if len(labels) > 0 {
				return labels[0][a.MachineID]
			}
			return nil
		}())})
	}
	return out
}
func diskAlertConditionLabel(key string, mounts []store.DiskMountUsage) string {
	if strings.HasPrefix(key, "mount:") {
		mount := "Mount"
		digest := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(key, "mount:"), ":critical"), ":warn")
		for _, m := range append([]store.DiskMountUsage{{Mount: "/"}}, mounts...) {
			if scriptcatalog.Digest([]byte(m.Mount)) == digest {
				mount = m.Mount
				break
			}
		}
		if strings.HasSuffix(key, ":critical") {
			return mount + " disk usage critical"
		}
		return mount + " disk usage warning"
	}
	switch {
	case strings.HasPrefix(key, "dual-owner:"):
		return "Dual ownership · " + diskAlertScope(key)
	case strings.HasPrefix(key, "summary-stale:"):
		return "Cleanup summary older than 48 hours · " + diskAlertScope(key)
	case strings.HasPrefix(key, "consecutive-lock-skips:"):
		return "Two consecutive lock skips · " + diskAlertScope(key)
	case key == "approvals-pending":
		return "Disk approvals pending longer than 24 hours"
	case key == "truncated-scan" || key == "truncated-safe-scan":
		return "Disk scan truncated"
	case strings.HasPrefix(key, "delivery-failed:"):
		return "Critical alert delivery delayed"
	default:
		return "Disk alert"
	}
}
func diskAlertScope(key string) string {
	if strings.HasSuffix(key, ":root") {
		return "root scope"
	}
	return "user scope"
}
