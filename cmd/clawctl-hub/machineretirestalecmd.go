package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/store"
)

func runMachineRetireStaleSubcommand(ctx context.Context, argv []string, out, errOut io.Writer, deps machineCommandDeps) error {
	fs := flag.NewFlagSet("machine retire-stale", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {
		fmt.Fprintln(errOut, "Usage: clawctl-hub machine retire-stale --db PATH [--apply [--container-stopped]] [--reason REASON] [--json]")
		fs.PrintDefaults()
	}
	dbPath := fs.String("db", "", "Existing host-local ledger path")
	apply := fs.Bool("apply", false, "Retire eligible machines; default lists candidates")
	jsonOutput := fs.Bool("json", false, "Print JSON")
	container := fs.Bool("container-stopped", false, "Apply inside Docker using ledger locks as stopped-Hub proof")
	reason := fs.String("reason", "", "Retirement reason override")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("machine retire-stale: unexpected positional arguments")
	}
	if strings.TrimSpace(*dbPath) == "" {
		return errors.New("machine retire-stale: --db is required")
	}
	if *container && !*apply {
		return errors.New("machine retire-stale: --container-stopped requires --apply")
	}
	now := time.Now().UTC()
	if !*apply {
		db, err := store.OpenStaleMachineReadOnly(*dbPath)
		if err != nil {
			return err
		}
		defer db.Close()
		candidates, err := store.StaleMachineCandidatesFromDB(db, now)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return writeLifecycleJSON(out, struct {
				Mode       string                        `json:"mode"`
				Now        time.Time                     `json:"now"`
				Candidates []store.StaleMachineCandidate `json:"candidates"`
			}{"dry-run", now, candidates})
		}
		for _, c := range candidates {
			if _, err := fmt.Fprintf(out, "machine_id=%s display_name=%q hostname=%q created_at=%s branches=%s duplicate_of=%s\n", terminalSafe(c.MachineID), terminalSafe(c.DisplayName), terminalSafe(c.Hostname), c.CreatedAt.Format(time.RFC3339), staleBranchText(c.Branches), terminalSafe(strings.Join(c.DuplicateOf, ","))); err != nil {
				return err
			}
		}
		_, err = fmt.Fprintf(out, "Candidates: %d\n", len(candidates))
		return err
	}
	if *container {
		path := deps.dockerenvPath
		if path == "" {
			path = "/.dockerenv"
		}
		deps.verifyHubStopped = func(context.Context, string) error {
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("machine retire-stale: Docker marker required: %w", err)
			}
			if !info.Mode().IsRegular() {
				return errors.New("machine retire-stale: Docker marker must be a file")
			}
			return nil
		}
	}
	return withDirectOperatorStore(ctx, "machine retire-stale", *dbPath, deps, func(st *store.Store) error {
		candidates, err := st.StaleMachineCandidates(now)
		if err != nil {
			return err
		}
		service := operator.New(st)
		type outcome struct {
			MachineID     string                      `json:"machine_id"`
			PreviousState store.MachineLifecycleState `json:"previous_state,omitempty"`
			State         store.MachineLifecycleState `json:"state,omitempty"`
			Revision      int64                       `json:"revision"`
			Skipped       bool                        `json:"skipped,omitempty"`
			Error         string                      `json:"error,omitempty"`
		}
		results := []outcome{}
		retired, skipped, failed := 0, 0, 0
		for _, candidate := range candidates {
			r := outcome{MachineID: candidate.MachineID}
			err := func() error {
				c, ok, err := st.StaleMachineCandidate(candidate.MachineID, now)
				if err != nil {
					return err
				}
				if !ok {
					r.Skipped = true
					skipped++
					return nil
				}
				current, err := service.MachineLifecycle(c.MachineID)
				if err != nil {
					return err
				}
				revision := current.LifecycleRevision
				preview, err := service.PreviewMachineLifecycle(operator.MachineLifecyclePreviewRequest{MachineID: c.MachineID, DesiredState: store.MachineLifecycleRetired, ExpectedRevision: &revision})
				if err != nil {
					return err
				}
				if len(preview.Blockers) > 0 {
					return fmt.Errorf("retirement blocked: %v", preview.Blockers)
				}
				key, err := operator.NewIdempotencyKey("cli-machine-retire-stale")
				if err != nil {
					return err
				}
				why := *reason
				if strings.TrimSpace(why) == "" {
					why = "retire-stale: never-enrolled, 0 check-ins, " + staleBranchText(c.Branches)
				}
				result, err := service.ChangeMachineLifecycle(operator.MachineLifecycleRequest{MachineID: c.MachineID, DesiredState: store.MachineLifecycleRetired, ExpectedRevision: &revision, ConfirmDisplayName: c.DisplayName, PreviewDigest: preview.PreviewDigest, Reason: why, IdempotencyKey: key, Actor: operator.Actor{SourceAddr: "local-cli", WhoUnavailable: "host-maintenance:retire-stale", UserAgent: "clawctl-hub machine retire-stale", SourceKind: operator.SourceKindDirectDBCLI}})
				if err != nil {
					return err
				}
				r.PreviousState = result.PreviousState
				r.State = result.State
				r.Revision = result.LifecycleRevision
				retired++
				return nil
			}()
			if err != nil {
				r.Error = err.Error()
				failed++
			}
			results = append(results, r)
			if !*jsonOutput {
				var writeErr error
				if r.Error != "" {
					_, writeErr = fmt.Fprintf(out, "%s: failed: %s\n", terminalSafe(r.MachineID), terminalSafe(r.Error))
				} else if r.Skipped {
					_, writeErr = fmt.Fprintf(out, "%s: skipped\n", terminalSafe(r.MachineID))
				} else {
					_, writeErr = fmt.Fprintf(out, "%s: %s -> %s revision=%d\n", terminalSafe(r.MachineID), r.PreviousState, r.State, r.Revision)
				}
				if writeErr != nil {
					return writeErr
				}
			}
		}
		if *jsonOutput {
			err = writeLifecycleJSON(out, struct {
				Mode    string    `json:"mode"`
				Now     time.Time `json:"now"`
				Results []outcome `json:"results"`
				Retired int       `json:"retired"`
				Skipped int       `json:"skipped"`
				Failed  int       `json:"failed"`
			}{"apply", now, results, retired, skipped, failed})
		} else {
			_, err = fmt.Fprintf(out, "Retired: %d; skipped: %d; failed: %d\n", retired, skipped, failed)
		}
		if err != nil {
			return err
		}
		if failed > 0 {
			return fmt.Errorf("machine retire-stale: %d retirement(s) failed", failed)
		}
		return nil
	})
}
func staleBranchText(branches []store.StaleMachineBranch) string {
	parts := make([]string, len(branches))
	for i, b := range branches {
		parts[i] = string(b)
	}
	return strings.Join(parts, ",")
}
