package web

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/secrets"
)

// SetSecretProvider installs the configured registry for status and admin tests.
func (s *Server) SetSecretProvider(provider secrets.SecretProvider) { s.secretProvider = provider }

type secretStatus struct {
	Name   string `json:"name"`
	Ref    string `json:"ref"`
	Status string `json:"status"`
}

// Keep this check shared by HTML and JSON so future operator-admin scopes
// can be added at one boundary. Today's operator Admin capability is supported.
func canReadSecrets(r *http.Request) bool { return accessFromRequest(r).CanAdmin }
func (s *Server) secretsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !canReadSecrets(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rows := []secretStatus{}
	if s.secretProvider != nil {
		refs, err := s.secretProvider.List(r.Context(), "")
		if err != nil {
			http.Error(w, "secret status unavailable", http.StatusInternalServerError)
			return
		}
		for _, ref := range refs {
			status := "present"
			_, err := s.secretProvider.Get(r.Context(), ref.Ref)
			if err != nil {
				status = "error"
				if errors.Is(err, secrets.ErrMissing) {
					status = "missing"
				}
			}
			rows = append(rows, secretStatus{Name: ref.Name, Ref: ref.Ref, Status: status})
		}
	}
	if r.URL.Path == "/v1/operator/secrets" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rows)
		return
	}
	status := secrets.BackendStatus{LastErrorClass: "not_configured"}
	if p, ok := s.secretProvider.(interface{ BWSStatus() secrets.BackendStatus }); ok {
		status = p.BWSStatus()
	}
	s.render(w, r, "secrets.html", page{Title: "Secrets", Nav: "secrets", Secrets: rows, BWSStatus: status})
}

// secretTest accepts only references already present in the configured inventory.
func (s *Server) secretTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !canReadSecrets(r) {
		http.Error(w, "forbidden", 403)
		return
	}
	if r.Header.Get("Origin") == "" && r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		http.Error(w, "origin required", 403)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if r.ParseForm() != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	if s.secretProvider == nil {
		http.Error(w, "secret not found", 404)
		return
	}
	refs, e := s.secretProvider.List(r.Context(), "")
	if e != nil {
		http.Error(w, "secret status unavailable", 500)
		return
	}
	for _, ref := range refs {
		if ref.Ref != r.FormValue("ref") {
			continue
		}
		status, err := s.operator.TestSecret(r.Context(), ref, s.secretProvider, operator.ActorFromRequest(r, operator.SourceKindWeb))
		if err != nil {
			http.Error(w, "secret test unavailable", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(secretStatus{ref.Name, ref.Ref, status})
		return
	}
	http.Error(w, "secret not found", 404)
}
