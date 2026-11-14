package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

func cmdJob(argv []string) {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: clawctl-hub job create|list|show|evidence [flags]")
		os.Exit(2)
	}
	switch argv[0] {
	case "create":
		if err := runJobCreateCommand(context.Background(), argv[1:], os.Stdout, os.Stderr); err != nil && !errors.Is(err, flag.ErrHelp) {
			log.Fatal(terminalSafe(err.Error()))
		}
	case "list", "show", "evidence":
		if err := runJobReadCommand(context.Background(), argv, os.Stdout, os.Stderr); err != nil && !errors.Is(err, flag.ErrHelp) {
			log.Fatal(terminalSafe(err.Error()))
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: job %s (available: create, list, show, evidence)\n", argv[0])
		os.Exit(2)
	}
}

// resolveMachine 把人打的名字對到名冊上的一台。
// allowRetired=false 用在開單（退場的機器不開單），true 用在看歷史。
func resolveMachine(st *store.Store, name string, allowRetired bool) (store.Machine, error) {
	if name == "" {
		return store.Machine{}, errors.New("must specify --machine (display_name or machine_id)")
	}
	ms, err := st.ListMachines()
	if err != nil {
		return store.Machine{}, err
	}
	var hits []store.Machine
	for _, m := range ms {
		if m.MachineID == name || m.DisplayName == name {
			hits = append(hits, m)
		}
	}
	switch len(hits) {
	case 0:
		return store.Machine{}, fmt.Errorf("machine %q not found in registry", name)
	case 1:
		if hits[0].RetiredAt != nil && !allowRetired {
			return store.Machine{}, fmt.Errorf("%s was retired at %s, cannot create job", name, hits[0].RetiredAt.UTC().Format(time.RFC3339))
		}
		return hits[0], nil
	default:
		// ⚠ display_name 不保證唯一（重灌後再報到就會有兩台同名）。
		// 猜一台的話，單會開到另一台 —— 這裡要人用 machine_id 講清楚。
		ids := make([]string, 0, len(hits))
		for _, h := range hits {
			ids = append(ids, h.MachineID)
		}
		return store.Machine{}, fmt.Errorf("%q matched %d machines: %s - specify machine_id", name, len(hits), strings.Join(ids, ", "))
	}
}
