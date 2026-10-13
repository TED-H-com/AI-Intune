package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsagePolicyMigrationSafeguardsAtomic(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		name := "later schema failure"
		if rollback {
			name = "restoration failure rolls back"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { db.Close() }()
			legacy := strings.Replace(schemaSQL, "CHECK(kind IN ('disk','usage'))", "CHECK(kind='disk')", 1)
			if _, err := db.Exec(legacy); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`CREATE INDEX policy_digest_extra ON ops_policies(digest);
CREATE TRIGGER policy_superseded_extra BEFORE UPDATE OF superseded_at ON ops_policies
BEGIN SELECT RAISE(ABORT,'extra protection'); END;
INSERT INTO ops_policies VALUES ('legacy','disk',1,'{}','digest','human','2026-10-13T00:00:00Z',NULL)`); err != nil {
				t.Fatal(err)
			}
			if rollback {
				// The standard unique index will fail to restore after the table rebuild.
				if _, err := db.Exec(`DROP INDEX ops_policy_current;
INSERT INTO ops_policies VALUES ('legacy','disk',2,'{}','digest','human','2026-10-13T00:00:00Z',NULL)`); err != nil {
					t.Fatal(err)
				}
			}
			err = migrateUsagePolicyKind(db)
			if rollback {
				if err == nil {
					t.Fatal("expected safeguard restoration failure")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				// Simulate failure in schema installation after the migration commits.
				if _, err := db.Exec(`CREATE INDEX simulate_schema_failure ON missing_table(id)`); err == nil {
					t.Fatal("expected schema failure")
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			var ddl string
			if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE name='ops_policies'`).Scan(&ddl); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ddl, "'usage'") == rollback {
				t.Fatalf("unexpected durable table schema: %s", ddl)
			}
			objects := []string{"ops_policy_immutable", "ops_policy_no_delete", "policy_digest_extra", "policy_superseded_extra"}
			if !rollback {
				objects = append(objects, "ops_policy_current")
			}
			for _, name := range objects {
				var n int
				if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE tbl_name='ops_policies' AND name=?`, name).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n != 1 {
					t.Fatalf("lost safeguard %s", name)
				}
			}
			for _, statement := range []string{
				`UPDATE ops_policies SET body='changed'`,
				`DELETE FROM ops_policies`,
				`UPDATE ops_policies SET superseded_at='2026-10-14T00:00:00Z'`,
			} {
				if _, err := db.Exec(statement); err == nil {
					t.Fatalf("lost protection: %s", statement)
				}
			}
			var n int
			if err := db.QueryRow(`SELECT COUNT(*) FROM ops_policies_usage_migration`).Scan(&n); err == nil {
				t.Fatal("rebuild table survived")
			}
			if !rollback {
				if _, err := db.Exec(`INSERT INTO ops_policies VALUES ('legacy','disk',2,'{}','digest','human','2026-10-13T00:00:00Z',NULL)`); err == nil {
					t.Fatal("lost current-policy uniqueness")
				}
			} else {
				if err := db.QueryRow(`SELECT COUNT(*) FROM ops_policies`).Scan(&n); err != nil || n != 2 {
					t.Fatalf("rollback lost original rows: count=%d err=%v", n, err)
				}
			}
		})
	}
}
