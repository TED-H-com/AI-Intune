package web

import (
	"bytes"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/state"
	"github.com/teddashh/AI-Intune/internal/store"
)

func TestAttentionStatusTemplate(t *testing.T) {
	s, _ := newServer(t)
	degraded := state.Degraded
	view := buildMachineIndexPage(operator.MachineListRequest{}, operator.MachineListResult{
		Items: []operator.MachineSummary{{MachineID: "test", DisplayName: "Test machine", State: &degraded}},
	})
	view.AttentionReasons["test"] = attentionReasons(degraded,
		[]state.CredFact{{Provider: "grok", Status: "expired", Note: "secret-token"}},
		[]state.Finding{{Kind: "workload", Advisory: true, Message: "secret-token"}})
	var out bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&out, "machines-index.html", page{MachineList: view}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Needs attention", "grok login expired, OpenClaw advisory", `value="Degraded"`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(out.String(), "secret-token") {
		t.Fatal("credential or diagnostic text leaked")
	}
}

func TestAttentionReasonsBoundAndDeduplicate(t *testing.T) {
	findings := []state.Finding{{Kind: "workload", Advisory: true}, {Kind: "workload", Advisory: true}, {Kind: "disk", Severity: 2}, {Kind: "agent", Severity: 3}}
	credentials := []state.CredFact{{Provider: "grok", Status: "expired"}}
	if got := attentionReasons(state.Degraded, credentials, findings); got != "grok login expired, OpenClaw advisory, Disk space low +1 more" {
		t.Fatalf("reasons = %q", got)
	}
	if got := attentionReasons(state.Online, credentials, findings); got != "" {
		t.Fatalf("online reasons = %q", got)
	}
}

func TestDashboardAttentionStatusTemplate(t *testing.T) {
	s, _ := newServer(t)
	ov := store.Overview{Machines: []store.MachineRow{{Machine: store.Machine{DisplayName: "Test"}, State: state.Degraded, Facts: state.Facts{Credentials: []state.CredFact{{Provider: "grok", Status: "expired"}}}, Findings: []state.Finding{{Kind: "workload", Advisory: true}}}}}
	var out bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&out, "dashboard.html", page{Overview: ov, MachineTable: buildDashboardMachineTable(ov, ""), Dashboard: buildDashboardStats(ov, nil, true)}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Needs attention") || !strings.Contains(out.String(), "grok login expired, OpenClaw advisory") {
		t.Fatal("missing inline attention status and reasons")
	}
}

func TestAttentionJudgeReasonsStayShortAndSafe(t *testing.T) {
	if got := attentionReasons(state.Degraded, nil, nil, "節點剛回報，但 OpenClaw process 不存在 secret-token"); got != "OpenClaw stopped" {
		t.Fatalf("judge summary = %q", got)
	}
	j := operator.MachineJudgement{State: state.Degraded, Findings: operator.MachineFindingPage{Items: []operator.MachineFinding{{Kind: "workload", Advisory: true}}}}
	e := &operator.MachineEvidenceResult{Credentials: operator.MachineCredentialPage{Items: []operator.MachineCredential{{Provider: operator.EvidenceText{Text: "grok"}, Status: "expired"}}}}
	if got := detailAttentionReasons(j, e); got != "grok login expired, OpenClaw advisory" {
		t.Fatalf("detail summary = %q", got)
	}
}
