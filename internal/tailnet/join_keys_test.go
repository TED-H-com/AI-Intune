package tailnet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJoinKeysOAuthAndOneOffTaggedKey(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/api/v2/oauth/token":
			r.ParseForm()
			if r.Method != "POST" || r.Form.Get("client_id") != "fixture-id" || r.Form.Get("client_secret") != "fixture-secret" || r.Form.Get("grant_type") != "client_credentials" {
				t.Error("invalid OAuth request")
			}
			w.Write([]byte(`{"access_token":"fixture-access"}`))
		case "/api/v2/tailnet/-/keys":
			if r.Header.Get("Authorization") != "Bearer fixture-access" {
				t.Error("invalid authorization")
			}
			var body struct {
				Expiry       int    `json:"expirySeconds"`
				Description  string `json:"description"`
				Capabilities struct {
					Devices struct {
						Create struct {
							Reusable      bool     `json:"reusable"`
							Ephemeral     bool     `json:"ephemeral"`
							Preauthorized bool     `json:"preauthorized"`
							Tags          []string `json:"tags"`
						} `json:"create"`
					} `json:"devices"`
				} `json:"capabilities"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("bad JSON")
			}
			c := body.Capabilities.Devices.Create
			if body.Expiry != 600 || body.Description != "clawctl join ABCD-2345" || c.Reusable || c.Ephemeral || !c.Preauthorized || len(c.Tags) != 1 || c.Tags[0] != "tag:fleet" {
				t.Error("wrong key capabilities")
			}
			w.Write([]byte(`{"key":"fixture-key"}`))
		default:
			t.Error("unexpected request")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := &JoinKeys{ClientID: "fixture-id", ClientSecret: "fixture-secret", BaseURL: server.URL}
	key, err := c.Mint(context.Background(), "ABCD-2345")
	if err != nil || key != "fixture-key" || calls != 2 {
		t.Fatal("mint failed", err)
	}
}
func TestJoinKeysBoundedErrorsAndNoRedirect(t *testing.T) {
	for _, mode := range []string{"error", "oversize", "redirect", "empty"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "error":
					w.WriteHeader(500)
					w.Write([]byte("fixture-secret"))
				case "oversize":
					w.Write([]byte(strings.Repeat("a", 16385)))
				case "redirect":
					w.Header().Set("Location", "/leak")
					w.WriteHeader(302)
				case "empty":
					w.Write([]byte(`{}`))
				}
			}))
			defer server.Close()
			c := &JoinKeys{ClientID: "id", ClientSecret: "fixture-secret", BaseURL: server.URL}
			_, err := c.Mint(context.Background(), "ABCD-2345")
			if err == nil || strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("unsafe error", err)
			}
		})
	}
	if (&JoinKeys{Tag: "tag:INVALID"}).Validate() == nil || (&JoinKeys{ClientID: "id"}).Validate() == nil {
		t.Fatal("invalid configuration accepted")
	}
	c := &JoinKeys{}
	if c.Validate() != nil || c.Configured() || c.Tag != "tag:fleet" {
		t.Fatal("optional configuration")
	}
}
