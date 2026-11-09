package web

import (
	"html/template"
	"net/http"
)

// RenderAccountForm deliberately does not require authenticated page data.
func (s *Server) RenderAccountForm(w http.ResponseWriter, setup bool, next, message string) {
	name := "login.html"
	if setup {
		name = "setup.html"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, name, struct{ Next, Error string }{next, message})
}

// NewAccountTemplate gives account and identity checks the shared interface layout.
// Source is a compile-time template; values remain escaped by html/template.
func NewAccountTemplate(name, source string) *template.Template {
	t := template.Must(template.New(name).ParseFS(templateFS, "templates/styles.html", "templates/account-layout.html"))
	return template.Must(t.Parse(source))
}
