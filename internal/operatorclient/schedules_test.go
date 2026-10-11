package operatorclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/store"
)

func TestScheduleClient(t *testing.T) {
	testScheduleClient(t, func(handler http.HandlerFunc) *Client { return settingClientServer(t, handler) })
}

// Exercise the same strict client without listening on a sandbox socket.
func TestScheduleClientResponseShapes(t *testing.T) {
	testScheduleClient(t, func(handler http.HandlerFunc) *Client {
		base, _ := url.Parse("http://100.64.0.1:8080")
		return &Client{base: base, http: &http.Client{Transport: assignedUserTransport(func(r *http.Request) (*http.Response, error) {
			w := httptest.NewRecorder()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			handler(w, r)
			response := w.Result()
			response.Request = r
			return response, nil
		})}}
	})
}

func testScheduleClient(t *testing.T, makeClient func(http.HandlerFunc) *Client) {
	t.Helper()
	digest := settingClientDigest("a")
	schedule := store.Schedule{ID: "s-1", Name: "probe-check", Revision: 1, Args: json.RawMessage(`{}`), Targets: []string{"machine-a"}, LastJobIDs: []string{}}
	listReads, runs := 0, 0
	client := makeClient(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/operator/schedules":
			items := []store.Schedule{}
			if listReads > 0 {
				items = append(items, schedule)
			}
			listReads++
			json.NewEncoder(w).Encode(store.ScheduleListResponse{Items: items})
		case r.URL.Path == "/v1/operator/schedules/s-1":
			json.NewEncoder(w).Encode(schedule)
		case strings.HasSuffix(r.URL.Path, "/preview"):
			if r.Header.Get("Idempotency-Key") != "" {
				t.Error("preview idempotency")
			}
			json.NewEncoder(w).Encode(store.ScheduleResult{PreviewDigest: digest, Schedule: schedule})
		case strings.HasSuffix(r.URL.Path, "/apply"):
			if r.Header.Get("Idempotency-Key") != "schedule-key" {
				t.Error("apply key")
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(store.ScheduleResult{PreviewDigest: digest, Schedule: schedule})
		case r.URL.Path == "/v1/operator/schedules/s-1/run-now":
			jobs := []string{}
			if runs == 0 {
				jobs = append(jobs, "job-a")
			}
			runs++
			json.NewEncoder(w).Encode(store.ScheduleRunNowResponse{JobIDs: jobs})
		default:
			t.Error(r.URL.Path)
		}
	})
	ctx := context.Background()
	for _, want := range []int{0, 1} {
		out, e := client.ScheduleRead(ctx, "")
		if e != nil {
			t.Fatal(e)
		}
		items, ok := out.([]store.Schedule)
		if !ok || items == nil || len(items) != want {
			t.Fatalf("list %+v", out)
		}
	}
	if out, e := client.ScheduleRead(ctx, "s-1"); e != nil || out.(store.Schedule).ID != schedule.ID {
		t.Fatalf("get %+v %v", out, e)
	}
	for _, op := range []string{"upsert", "set-enabled"} {
		body := store.ScheduleRequest{Name: "probe-check", ExpectedRevision: 0}
		p, e := client.ScheduleManage(ctx, body, op, false, "")
		if e != nil {
			t.Fatal(e)
		}
		body.PreviewDigest = p.PreviewDigest
		if _, e = client.ScheduleManage(ctx, body, op, true, "schedule-key"); e != nil {
			t.Fatal(e)
		}
	}
	for _, want := range []int{1, 0} {
		out, e := client.ScheduleRunNow(ctx, "s-1")
		if e != nil {
			t.Fatal(e)
		}
		jobs := out.(store.ScheduleRunNowResponse).JobIDs
		if jobs == nil || len(jobs) != want {
			t.Fatalf("run %+v", out)
		}
	}
}

func TestScheduleListEnvelopeIsStrict(t *testing.T) {
	for _, raw := range []string{`[]`, `{"items":null}`, `{"items":[],"unknown":true}`, `{"Items":[]}`, `{"items":[],"items":[]}`, `{}`} {
		var out store.ScheduleListResponse
		if e := decodeStrictJSONDocument([]byte(raw), "schedules", &out); e == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
