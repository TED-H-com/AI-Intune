package main

import (
	"bytes"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccountPagesShareResponsiveLayout(t *testing.T) {
	cases := []struct {
		name string
		tmpl *template.Template
		data any
	}{
		{"mfa", mfaForm, struct{ Error string }{""}},
		{"security", securityForm, map[string]any{"Enabled": true, "Required": true, "Warning": "", "Secret": "", "Codes": []string{}}},
		{"users", usersForm, map[string]any{"Error": "", "Users": nil, "Actions": []string{"create", "email", "rename"}}},
		{"service-tokens", serviceTokenForm, serviceFormData{}},
		{"reauthentication", actionMFAForm, struct {
			Why, Error, Action string
			Fields             url.Values
		}{"Confirm your identity to continue.", "", "/example", url.Values{"reason": {"review"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := tc.tmpl.Execute(&b, tc.data); err != nil {
				t.Fatal(err)
			}
			body := b.String()
			for _, want := range []string{`name="viewport"`, `<main class="account-content"`, `id="main-content"`, `</main></body></html>`} {
				if !strings.Contains(body, want) {
					t.Errorf("missing layout contract %s", want)
				}
			}
			if dir := os.Getenv("CLAWCTL_INTERFACE_PREVIEW_DIR"); dir != "" {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "account-"+tc.name+".html"), b.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
