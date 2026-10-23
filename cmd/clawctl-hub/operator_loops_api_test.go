package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperatorLoopsAPI(t *testing.T) {
	st := boundaryStore(t)
	mux := http.NewServeMux()
	(&hub{store: st}).operatorRoutes(mux)
	for _, path := range []string{"/v1/operator/loops", "/v1/operator/loops?machine_id=example-device"} {
		w := operatorRequest(t, mux, "GET", path, "", "")
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), `"items":[]`) {
			t.Fatal("invalid empty read", w.Code)
		}
	}
	for _, q := range []string{"?unknown=x", "?machine_id=a&machine_id=b", "?machine_id=%zz"} {
		w := operatorRequest(t, mux, "GET", "/v1/operator/loops"+q, "", "")
		if w.Code != 400 {
			t.Fatal("invalid filter accepted", q, w.Code)
		}
	}
	auth := &boundaryAuthorizer{allow: false}
	boundary := newOperatorBoundary(mux, auth, st, operatorRoutePolicies, testOperatorAuthority)
	r := httptest.NewRequest(http.MethodGet, "http://"+testOperatorAuthority+"/v1/operator/loops", nil)
	w := httptest.NewRecorder()
	boundary.ServeHTTP(w, r)
	if w.Code == 200 {
		t.Fatal("unauthorized loop read")
	}
}
