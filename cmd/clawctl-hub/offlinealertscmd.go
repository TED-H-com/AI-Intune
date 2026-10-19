package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/store"
)

func cmdOfflineAlerts(argv []string) {
	if err := runOfflineAlertsCommand(context.Background(), argv, os.Stdout, os.Stderr, productionMachineCommandDeps()); err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}

// This command uses deterministic operator discovery and the same preview and
// apply contract as the browser. JSON output keeps retry coordinates reviewable.
func runOfflineAlertsCommand(ctx context.Context, argv []string, out, errOut io.Writer, deps machineCommandDeps) error {
	fs := flag.NewFlagSet("offline-alerts", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var hubURL auditStringFlag
	fs.Var(&hubURL, "hub-url", "operator API URL (auto-discovered if omitted)")
	minutes := fs.Int("set-minutes", -1, "Unreachable minutes before notifying (1..1440)")
	preview := fs.Bool("preview", false, "preview without applying")
	reason := fs.String("reason", "", "change reason")
	confirm := fs.String("confirm", "", "type OFFLINE ALERTS to apply")
	key := fs.String("idempotency-key", "", "retry: original request key")
	digest := fs.String("preview-digest", "", "retry: original preview digest")
	revision := fs.Int64("expected-revision", -1, "retry: original expected revision")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("offline-alerts: unexpected positional arguments")
	}
	seen := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	client, err := reportHTTPClient("offline-alerts", hubURL.value, hubURL.set, deps)
	if err != nil {
		return err
	}
	encode := func(v any) error { return json.NewEncoder(out).Encode(v) }
	if !seen["set-minutes"] {
		if *preview || seen["reason"] || seen["confirm"] || seen["idempotency-key"] || seen["preview-digest"] || seen["expected-revision"] {
			return errors.New("offline-alerts: writes require --set-minutes")
		}
		result, err := client.OfflineAlertSettings(ctx)
		if err != nil {
			return err
		}
		return encode(result)
	}
	if !store.ValidOfflineAlertMinutes(*minutes) {
		return errors.New("offline-alerts: minutes must be 1..1440")
	}
	retry := seen["idempotency-key"] || seen["preview-digest"] || seen["expected-revision"]
	if retry && (*preview || *key == "" || *digest == "" || *revision < 0) {
		return errors.New("offline-alerts: retries require original key, digest and revision; no --preview")
	}
	if !retry {
		p, err := client.PreviewOfflineAlertSettings(ctx, *minutes)
		if err != nil {
			return err
		}
		if *preview {
			return encode(p)
		}
		*revision = p.Current.Revision
		*digest = p.PreviewDigest
		*key, err = operator.NewIdempotencyKey("cli-offline-alerts")
		if err != nil {
			return err
		}
	}
	if *confirm != "OFFLINE ALERTS" {
		return errors.New("offline-alerts: --confirm 'OFFLINE ALERTS' is required")
	}
	if err := validateReportChangeCLIText("reason", *reason, 500); err != nil {
		return err
	}
	result, err := client.ApplyOfflineAlertSettings(ctx, *key, store.OfflineAlertSettingsRequest{Minutes: *minutes, ExpectedRevision: revision, PreviewDigest: *digest, Reason: *reason, Confirm: *confirm})
	if err != nil {
		fmt.Fprintf(errOut, "Retry the same request with --idempotency-key %s --expected-revision %d --preview-digest %s\n", *key, *revision, *digest)
		return err
	}
	return encode(result)
}
