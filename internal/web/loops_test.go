package web

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

func TestLoopsWebPolicyAndEpisode(t *testing.T) {
	s, st := newServer(t)
	m := onlineMachine(t, st, "loop-device")
	admin := diskWebPrincipal(true, false, "")
	empty := diskWebRequest(t, s, "GET", "/attention/loops", nil, admin, false)
	if empty.Code != 200 || !strings.Contains(empty.Body.String(), "No loop episodes reported") || !strings.Contains(empty.Body.String(), "Save detection policy") {
		t.Fatal("missing usable empty state", empty.Code)
	}
	form := url.Values{"action": {"policy"}, "threshold": {"10"}, "window_seconds": {"120"}}
	denied := diskWebRequest(t, s, "POST", "/attention/loops", form, diskWebPrincipal(false, false, ""), false)
	if denied.Code != 403 {
		t.Fatal("non-admin mutation", denied.Code)
	}
	saved := diskWebRequest(t, s, "POST", "/attention/loops", form, admin, false)
	if saved.Code != 303 {
		t.Fatal("policy not saved", saved.Code)
	}
	p, err := st.LoopPolicy()
	if err != nil || p.Threshold != 10 {
		t.Fatal("policy not persisted", p, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	a := model.CallActivity{ProcessSignature: strings.Repeat("a", 64), CallSignature: strings.Repeat("b", 64)}
	for i := 0; i <= 100; i++ {
		a.TotalCalls = int64(i)
		at := now.Add(time.Duration(i) * time.Second)
		if err = st.RecordCheckin(m, model.Checkin{SentAt: at, CallActivity: []model.CallActivity{a}}, at); err != nil {
			t.Fatal(err)
		}
	}
	populated := diskWebRequest(t, s, "GET", "/attention/loops", nil, admin, false)
	for _, want := range []string{"Acknowledge", "Resolve", "100", "Last progress", "Unknown", a.CallSignature} {
		if !strings.Contains(populated.Body.String(), want) {
			t.Fatal("missing episode content", want)
		}
	}
	machine := diskWebRequest(t, s, "GET", "/machines/"+m, nil, admin, false)
	if machine.Code != 200 || !strings.Contains(machine.Body.String(), a.CallSignature) {
		t.Fatal("machine missing loop panel", machine.Code)
	}
	episodes, _ := st.LoopEpisodes(m)
	for _, action := range []string{"acknowledge", "resolve"} {
		f := url.Values{"action": {action}, "id": {strconv.FormatInt(episodes[0].ID, 10)}}
		got := diskWebRequest(t, s, "POST", "/attention/loops", f, admin, false)
		if got.Code != 303 {
			t.Fatal(action, got.Code)
		}
	}
	episodes, _ = st.LoopEpisodes(m)
	if episodes[0].AcknowledgedAt == nil || episodes[0].ResolvedAt == nil {
		t.Fatal("decisions not persisted")
	}
}
