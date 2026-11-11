package web

import (
	"bytes"
	"io/fs"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
)

func TestPrimaryNavigationTracksNestedPages(t *testing.T) {
	s, _ := newServer(t)
	for _, tc := range []struct{ path, href string }{
		{"/machines/compliance", "/machines#machines"},
		{"/reports/software", "/reports"}, {"/reports/enrollment", "/reports"},
		{"/reports/install", "/reports"}, {"/reports/profile", "/reports"},
		{"/tenant/schedules", "/tenant/maintenance"}, {"/tenant/certificates", "/tenant/maintenance"},
		{"/tenant/disk-alerts", "/tenant/maintenance"}, {"/tenant/offline-alerts", "/tenant/maintenance"},
		{"/readiness", "/readiness"}, {"/signins", "/signins"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			body := get(t, s, tc.path)
			start := strings.Index(body, `<aside class="sidebar">`)
			end := strings.Index(body[start:], `</aside>`)
			nav := body[start : start+end]
			if strings.Count(nav, `aria-current="page"`) != 1 {
				t.Fatal("primary navigation must have exactly one current workload")
			}
			if !strings.Contains(nav, `href="`+tc.href+`" class="nav-item on" aria-current="page"`) {
				t.Fatalf("wrong selected workload for %s", tc.path)
			}
		})
	}
}

func TestAccountLayoutPreservesEscapingAndFormState(t *testing.T) {
	s, _ := newServer(t)
	for _, setup := range []bool{false, true} {
		rec := httptest.NewRecorder()
		s.RenderAccountForm(rec, setup, `/machines?name=<script>`, `<script>alert("error")</script>`)
		body := rec.Body.String()
		for _, want := range []string{`name="viewport"`, `id="main-content"`, `class="account-content"`, `role="alert"`, `name="next" value="/machines?name=&lt;script&gt;"`, `&lt;script&gt;alert`, `</main></body></html>`} {
			if !strings.Contains(body, want) {
				t.Errorf("setup=%t missing %s", setup, want)
			}
		}
		if strings.Contains(body, `<script>alert`) {
			t.Fatal("account error was not escaped")
		}
	}
	tmpl := NewAccountTemplate("test", `{{template "account-head" .Title}}<h1>{{.Title}}</h1>{{template "account-foot" .}}`)
	var b bytes.Buffer
	if err := tmpl.Execute(&b, struct{ Title string }{`<script>title</script>`}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), `<script>title`) {
		t.Fatal("account title was not escaped")
	}
}

// Unstyled aliases can pass empty-page smoke tests and break populated layouts.
func TestTemplatesUseSharedLayoutClasses(t *testing.T) {
	paths, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	aliases := regexp.MustCompile(`class="(?:card|page-header|kpis|kpi|n|l|bad|badge)(?:"|\s)`)
	for _, path := range paths {
		raw, err := templateFS.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if aliases.Match(raw) {
			t.Errorf("%s uses an unstyled layout alias; use the shared panel/metric/status classes", path)
		}
	}
}

func TestChannelBindingFormRequiresAvailableChannels(t *testing.T) {
	s, _ := newServer(t)
	for _, admin := range []bool{false, true} {
		for _, populated := range []bool{false, true} {
			view := &channelsView{}
			if populated {
				view.Rows = []channelRow{{ID: "review", Kind: "webhook", Status: "ready"}}
			}
			req := operatorauth.WithPrincipal(httptest.NewRequest("GET", "/channels", nil), diskWebPrincipal(admin, true, "fixture"))
			rec := httptest.NewRecorder()
			s.render(rec, req, "channels.html", page{Title: "Channels", Nav: "channels", Channels: view})
			body := rec.Body.String()
			if !strings.Contains(body, "</html>") {
				t.Fatal("incomplete channels page")
			}
			if got := strings.Contains(body, `action="/channels/bind"`); got != (admin && populated) {
				t.Errorf("admin=%t populated=%t binding form=%t", admin, populated, got)
			}
			if !admin && strings.Contains(body, `action="/channels/`) {
				t.Fatal("viewer has channel mutation actions")
			}
		}
	}
}
