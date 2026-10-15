package web

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/teddashh/AI-Intune/internal/secrets"
)

// SetSecretProvider installs reference-only configuration for read-only status.
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
	s.render(w, r, "secrets.html", page{Title: "Secrets", Nav: "secrets", Secrets: rows})
}
