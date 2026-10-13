package store

import (
	"errors"
	"testing"
)

func TestUsageAccountAuthenticatedMachine(t *testing.T) {
	s, machine, _ := usageFixture(t)
	other := mustEnroll(t, s, "other-account-machine", s.now())
	a := UsageAccount{AccountID: usageTestHash, MachineID: other, Provider: "openai", Plan: "pro", DiscoverySource: "status", LastSeen: s.now()}
	if err := s.UpsertUsageAccount(other, a); err != nil {
		t.Fatal(err)
	}
	a.Plan = "free"
	a.LastSeen = a.LastSeen.Add(-1)
	if err := s.UpsertUsageAccount(machine, a); !errors.Is(err, ErrUsageInvalid) {
		t.Fatalf("cross-machine write: %v", err)
	}
	a.MachineID = ""
	if err := s.UpsertUsageAccount("", a); !errors.Is(err, ErrUsageInvalid) {
		t.Fatalf("missing authenticated machine: %v", err)
	}
	if err := s.UpsertUsageAccount(machine, a); err != nil {
		t.Fatal(err)
	}
	accounts, err := s.UsageAccounts()
	if err != nil || len(accounts) != 2 {
		t.Fatalf("accounts: %v, %v", accounts, err)
	}
	for _, account := range accounts {
		if account.MachineID == other && account.Plan != "pro" {
			t.Fatal("modified another machine's account")
		}
		if account.MachineID != other && account.MachineID != machine {
			t.Fatal("account was not bound to authenticated machine")
		}
	}
}
