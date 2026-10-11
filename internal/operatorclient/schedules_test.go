package operatorclient

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"testing"
)

func TestScheduleClient(t *testing.T) {
	digest := settingClientDigest("a")
	body := store.ScheduleRequest{Name: "probe-check", ExpectedRevision: 0}
	client := settingClientServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/operator/schedules":
			json.NewEncoder(w).Encode([]store.Schedule{})
		case "/v1/operator/schedules/upsert/preview":
			if r.Header.Get("Idempotency-Key") != "" {
				t.Error("preview idempotency")
			}
			json.NewEncoder(w).Encode(store.ScheduleResult{PreviewDigest: digest})
		case "/v1/operator/schedules/upsert/apply":
			if r.Header.Get("Idempotency-Key") != "schedule-key" {
				t.Error("apply key")
			}
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(store.ScheduleResult{PreviewDigest: digest, Schedule: store.Schedule{ID: "s-1", Name: "probe-check", Revision: 1}})
		case "/v1/operator/schedules/s-1/run-now":
			json.NewEncoder(w).Encode(map[string]any{"job_ids": []string{"job-a"}})
		default:
			t.Error(r.URL.Path)
		}
	})
	ctx := context.Background()
	if _, e := client.ScheduleRead(ctx, ""); e != nil {
		t.Fatal(e)
	}
	p, e := client.ScheduleManage(ctx, body, "upsert", false, "")
	if e != nil {
		t.Fatal(e)
	}
	body.PreviewDigest = p.PreviewDigest
	if _, e = client.ScheduleManage(ctx, body, "upsert", true, "schedule-key"); e != nil {
		t.Fatal(e)
	}
	if _, e = client.ScheduleRunNow(ctx, "s-1"); e != nil {
		t.Fatal(e)
	}
}
