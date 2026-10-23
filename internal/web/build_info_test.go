package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildInformationFooter(t *testing.T) {
	s, _ := newServer(t)
	s.SetBuildInfo("test-release", "test-commit")
	w := httptest.NewRecorder()
	s.render(w, httptest.NewRequest("GET", "/", nil), "dashboard.html", page{})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Hub test-release") || !strings.Contains(w.Body.String(), "test-commit") || !strings.Contains(w.Body.String(), `href="/version"`) {
		t.Fatal("footer missing build provenance")
	}
}
