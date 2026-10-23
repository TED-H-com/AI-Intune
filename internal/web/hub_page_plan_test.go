package web

import (
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Like TestEveryPruneSubqueryIsIndexOnly, assert the planner's actual access
// paths. Capture the real rendered page queries so the test cannot silently
// diverge from the handler's SQL. Include aliases in the scan check.
func TestHubPageQueriesDoNotScanObservationHistory(t *testing.T) {
	server, st := newServer(t)
	id := onlineMachine(t, st, "page-plan")
	var mu sync.Mutex
	var statements []pagePerfStatement
	if err := st.TraceSQL(func(q string, args []any, d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		statements = append(statements, pagePerfStatement{q, args, d})
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/machines", "/checks", "/machines/" + id, "/reports/software"} {
		t.Run(path, func(t *testing.T) {
			mu.Lock()
			statements = nil
			mu.Unlock()
			get(t, server, path)
			mu.Lock()
			captured := append([]pagePerfStatement(nil), statements...)
			mu.Unlock()
			if len(captured) == 0 {
				t.Fatal("no page queries captured")
			}
			seen := map[string]bool{}
			for _, q := range captured {
				if seen[q.query] {
					continue
				}
				seen[q.query] = true
				if !strings.Contains(strings.ToLower(q.query), "observed_state") {
					continue
				}
				rows, err := st.DB().Query("EXPLAIN QUERY PLAN "+q.query, q.args...)
				if err != nil {
					t.Fatal(err)
				}
				names := map[string]bool{"observed_state": true}
				for _, match := range regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s+observed_state\s+(?:AS\s+)?([a-zA-Z_]\w*)`).FindAllStringSubmatch(q.query, -1) {
					names[strings.ToLower(match[1])] = true
				}
				for rows.Next() {
					var id, parent, unused int
					var detail string
					if err = rows.Scan(&id, &parent, &unused, &detail); err != nil {
						t.Fatal(err)
					}
					t.Logf("PLAN page=%s %s", path, detail)
					fields := strings.Fields(strings.ToLower(detail))
					if len(fields) >= 2 && fields[0] == "scan" && names[fields[1]] {
						t.Errorf("page query scans observed_state history: %s\nSQL: %s", detail, q.query)
					}
				}
				if err = rows.Err(); err != nil {
					t.Fatal(err)
				}
				rows.Close()
			}
		})
	}
}
