package store

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"strings"
	"testing"
	"time"
)

func TestLoopHundredCallsProgressAndDecisions(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	m := mustEnroll(t, s, "loop-device", now)
	a := model.CallActivity{ProcessSignature: strings.Repeat("a", 64), CallSignature: strings.Repeat("b", 64)}
	report := func(at time.Time) {
		t.Helper()
		if err := s.RecordCheckin(m, model.Checkin{SentAt: at, CallActivity: []model.CallActivity{a}}, at); err != nil {
			t.Fatal(err)
		}
	}
	report(now)
	for i := 1; i <= 100; i++ {
		a.TotalCalls = int64(i)
		report(now.Add(time.Duration(i) * time.Second))
		if i == 50 {
			rows, e := s.LoopEpisodes(m)
			if e != nil || len(rows) != 0 {
				t.Fatal("threshold must be exceeded", e)
			}
		}
		if i == 51 {
			rows, e := s.LoopEpisodes(m)
			if e != nil || len(rows) != 1 {
				t.Fatal("threshold crossing missed", e)
			}
		}
	}
	episodes, err := s.LoopEpisodes(m)
	if err != nil || len(episodes) != 1 {
		t.Fatalf("episodes %v %v", episodes, err)
	}
	e := episodes[0]
	if e.Calls != 100 || e.Rate != 10 || e.LastProgress != nil || e.ResolvedAt != nil {
		t.Fatalf("wrong evidence %+v", e)
	}
	// Same counter and delayed old counter cannot inflate the window.
	report(now.Add(101 * time.Second))
	a.TotalCalls = 40
	report(now.Add(102 * time.Second))
	episodes, _ = s.LoopEpisodes(m)
	if episodes[0].Calls != 100 {
		t.Fatal("replay added calls")
	}
	if err = s.LoopDecision(e.ID, false, now.Add(103*time.Second)); err != nil {
		t.Fatal(err)
	}
	episodes, _ = s.LoopEpisodes(m)
	if episodes[0].AcknowledgedAt == nil || episodes[0].ResolvedAt != nil {
		t.Fatal("ack cleared episode")
	}
	a.TotalCalls = 101
	a.Progress = 1
	report(now.Add(104 * time.Second))
	episodes, _ = s.LoopEpisodes(m)
	if episodes[0].ResolvedAt == nil {
		t.Fatal("progress did not resolve")
	}
	a.TotalCalls = 202
	report(now.Add(105 * time.Second))
	episodes, _ = s.LoopEpisodes(m)
	if len(episodes) != 2 || episodes[0].LastProgress == nil {
		t.Fatal("new loop missing")
	}
	if err = s.LoopDecision(episodes[0].ID, true, now.Add(106*time.Second)); err != nil {
		t.Fatal(err)
	}
	a.TotalCalls = 203
	report(now.Add(107 * time.Second))
	episodes, _ = s.LoopEpisodes(m)
	if len(episodes) != 2 {
		t.Fatal("resolution did not reset window")
	}
}
func TestLoopNormalHeartbeatsAndSlidingWindow(t *testing.T) {
	for _, mode := range []string{"legacy", "normal", "progress", "window", "different-signatures"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestStore(t)
			now := time.Now().UTC().Truncate(time.Second)
			m := mustEnroll(t, s, "normal-device", now)
			for i := 0; i <= 100; i++ {
				a := model.CallActivity{ProcessSignature: strings.Repeat("a", 64), CallSignature: strings.Repeat("b", 64), TotalCalls: int64(i)}
				step := time.Second
				switch mode {
				case "normal", "window":
					step = 90 * time.Second
				case "progress":
					a.Progress = int64(i / 10)
				case "different-signatures":
					a.TotalCalls = int64(i / 2)
					if i%2 == 0 {
						a.CallSignature = strings.Repeat("c", 64)
					}
				}
				at := now.Add(time.Duration(i) * step)
				c := model.Checkin{SentAt: at, AgentSeq: int64(i)}
				if mode != "legacy" {
					c.CallActivity = []model.CallActivity{a}
				}
				if err := s.RecordCheckin(m, c, at); err != nil {
					t.Fatal(err)
				}
			}
			episodes, err := s.LoopEpisodes(m)
			if err != nil || len(episodes) != 0 {
				t.Fatalf("false positive %v %v", episodes, err)
			}
		})
	}
}
func TestLoopPolicyAndValidation(t *testing.T) {
	s := newTestStore(t)
	p, err := s.LoopPolicy()
	if err != nil || p.Threshold != 50 || p.WindowSeconds != 600 {
		t.Fatal(p, err)
	}
	if s.SetLoopPolicy(LoopPolicy{Threshold: 1, WindowSeconds: 600}) == nil {
		t.Fatal("invalid threshold")
	}
	if s.SetLoopPolicy(LoopPolicy{Threshold: 20, WindowSeconds: 60}) != nil {
		t.Fatal("valid policy")
	}
	a := model.CallActivity{ProcessSignature: strings.Repeat("a", 64), CallSignature: strings.Repeat("b", 64)}
	if ValidateLoopActivity([]model.CallActivity{a, a}) == nil {
		t.Fatal("duplicate accepted")
	}
	a.CallSignature = "raw arguments"
	if ValidateLoopActivity([]model.CallActivity{a}) == nil {
		t.Fatal("raw signature accepted")
	}
}
