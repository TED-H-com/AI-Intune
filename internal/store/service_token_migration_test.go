package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Build an actual deployed schema, not a fresh database with new columns.
func TestServiceTokenExistingDatabaseMigration(t *testing.T) {
	fastAccountHashes(t)
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(schemaSQL, "id TEXT PRIMARY KEY, name TEXT NOT NULL, scope", "id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, scope", 1)
	if _, err = db.Exec(legacy); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	token, secret, err := s.CreateServiceToken(ServiceToken{Name: "legacy", Scope: "view", ExpiresAt: s.now().Add(time.Hour), Allowlist: []string{"GET /v1/operator/jobs"}}, actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	// Restore the pre-upgrade service_tokens table and keep a real token row.
	_, err = s.db.Exec(`CREATE TABLE legacy_service_tokens (
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, scope TEXT NOT NULL CHECK(scope IN ('view','operate')),
 token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash)=32), allowlist TEXT NOT NULL, source_cidrs TEXT NOT NULL,
 created_by TEXT NOT NULL REFERENCES hub_accounts(account_id), created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL, last_used_at TEXT, revoked_at TEXT);
 INSERT INTO legacy_service_tokens SELECT id,name,scope,token_hash,allowlist,source_cidrs,created_by,created_at,expires_at,last_used_at,revoked_at FROM service_tokens;
 DROP TABLE service_tokens;
 ALTER TABLE legacy_service_tokens RENAME TO service_tokens;`)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	for i := 0; i < 2; i++ {
		s, err = Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.AuthenticateServiceToken(secret, "GET /v1/operator/service-tokens/self", "192.0.2.1", "view"); err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next, _, err := s.RotateServiceToken(token.ID, "192.0.2.1")
	if err != nil || next.Name != token.Name || next.RotationChainID != token.ID {
		t.Fatal("legacy rotation", err)
	}
}
