package store

import (
	"database/sql"
	"fmt"
)

// Transactional revisions detect inserts AND in-place updates/deletes, including
// evidence timestamped before now but committed after derivation. No wall clock
// or rowid can provide that guarantee. Triggers also cover other Store instances.
func migrateReconcileEvidence(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS reconcile_evidence_revision (
 scope TEXT PRIMARY KEY, revision INTEGER NOT NULL
 )`); err != nil {
		return err
	}
	// All identifiers below are compile-time constants. Empty scope is shared
	// evidence. Each changed row costs an indexed revision upsert per affected
	// scope (UPDATE covers both old/new machine_id), including retention DELETEs.
	// Registry and credential rows also bump shared evidence. Prune already
	// bounds writer transactions; keep triggers enabled so every delete path,
	// rollback and other Store instance preserves invalidation automatically.
	// Credential peers cross machine boundaries; ordinary checkins don't.
	perMachine := []string{"machine_registry", "machine_checkins", "observed_state", "machine_identity_hints", "machine_state_history", "canary_silent_failures", "workload_observation_witness", "workload_observation_evidence", "jobs", "deployment_targets"}
	global := []string{"deployments", "desired_state", "active_workload_policy", "deployment_soak_boundaries", "deployment_boundary_pauses"}
	bump := func(scope string) string {
		return `INSERT INTO reconcile_evidence_revision(scope,revision) VALUES(` + scope + `,1)
   ON CONFLICT(scope) DO UPDATE SET revision=revision+1;`
	}
	for _, table := range append(perMachine, global...) {
		local := false
		for _, name := range perMachine {
			if name == table {
				local = true
			}
		}
		for _, event := range []string{"INSERT", "UPDATE", "DELETE"} {
			body := bump("''")
			if local {
				body = ""
				if event != "INSERT" {
					body += bump("OLD.machine_id")
				}
				if event != "DELETE" {
					body += bump("NEW.machine_id")
				}
			}
			if table == "machine_registry" {
				body += bump("''")
			}
			if table == "observed_state" {
				// Only credential observations affect another machine's derived facts.
				for _, ref := range []string{"OLD", "NEW"} {
					if (event == "INSERT" && ref == "OLD") || (event == "DELETE" && ref == "NEW") {
						continue
					}
					body += `INSERT INTO reconcile_evidence_revision(scope,revision) SELECT '',1 WHERE ` + ref + `.kind='credential'
      ON CONFLICT(scope) DO UPDATE SET revision=revision+1;`
				}
			}
			stmt := fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS reconcile_revision_%s_%s AFTER %s ON %s BEGIN %s END`, table, event, event, table, body)
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("reconcile revision %s: %w", table, err)
			}
		}
	}
	return tx.Commit()
}

type reconcileRevision map[string]int64

// Capture before the first Overview read. Overview uses multiple read snapshots,
// but unchanged revisions at validation prove that all relevant evidence stayed
// fixed across those reads. A concurrent commit can only force a retry, including
// when Overview already saw that commit; it cannot validate a mixed judgement.
func (s *Store) reconcileRevisions() (reconcileRevision, error) {
	rows, err := s.rdb.Query(`SELECT scope,revision FROM reconcile_evidence_revision`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := reconcileRevision{}
	for rows.Next() {
		var scope string
		var revision int64
		if err := rows.Scan(&scope, &revision); err != nil {
			return nil, err
		}
		out[scope] = revision
	}
	return out, rows.Err()
}

func reconcileRevisionMatches(tx dbTx, before reconcileRevision, machineID string) (bool, error) {
	for _, scope := range []string{"", machineID} {
		var revision int64
		if err := tx.QueryRow(`SELECT COALESCE((SELECT revision FROM reconcile_evidence_revision WHERE scope=?),0)`, scope).Scan(&revision); err != nil {
			return false, err
		}
		if revision != before[scope] {
			return false, nil
		}
	}
	return true, nil
}
