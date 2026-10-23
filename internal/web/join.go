package web

import (
	"bytes"
	"encoding/json"
	"errors"
	joinscript "github.com/teddashh/AI-Intune/ops/join"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/clientip"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorendpoint"
	"github.com/teddashh/AI-Intune/internal/store"
	"github.com/teddashh/AI-Intune/internal/tailnet"
)

func (s *Server) ConfigureJoinFromEnv() error {
	keys := &tailnet.JoinKeys{ClientID: os.Getenv("CLAWCTL_TAILSCALE_OAUTH_CLIENT_ID"), ClientSecret: os.Getenv("CLAWCTL_TAILSCALE_OAUTH_CLIENT_SECRET"), Tag: os.Getenv("CLAWCTL_TAILSCALE_JOIN_TAG")}
	if base := os.Getenv("CLAWCTL_TAILSCALE_API_BASE"); base != "" {
		// Never redirect production OAuth credentials through deployment env.
		if !strings.HasSuffix(os.Args[0], ".test") {
			return errors.New("Tailscale API base override is test-only")
		}
		keys.BaseURL = base
	}
	if err := keys.Validate(); err != nil {
		return err
	}
	s.operator.ConfigureJoinKeys(keys)
	return nil
}
func (s *Server) SetJoinClientIP(resolver clientip.Resolver) { s.joinClientIP = resolver }
func (s *Server) JoinPublicRoutes(mux *http.ServeMux) []string {
	patterns := []string{"GET /join.sh", "POST /v1/join/start", "POST /v1/join/poll", "GET /v1/join/bundle/{arch}", "GET /join.ps1"}
	mux.HandleFunc(patterns[4], s.joinPowerShell)
	mux.HandleFunc(patterns[0], s.joinScript)
	mux.HandleFunc(patterns[1], s.joinStart)
	mux.HandleFunc(patterns[2], s.joinPoll)
	mux.HandleFunc(patterns[3], s.joinBundle)
	return patterns
}
func (s *Server) joinRoutes(mux *http.ServeMux) []string {
	patterns := []string{"GET /machines/join", "POST /machines/join/decide", "GET /v1/operator/joins"}
	mux.HandleFunc(patterns[0], s.joinPage)
	mux.HandleFunc(patterns[1], s.joinDecide)
	mux.HandleFunc(patterns[2], s.joinList)
	return patterns
}
func validJoinHub(base string) bool {
	u, err := operatorendpoint.ParsePublicURL(base)
	return err == nil && u.Scheme() == "https"
}

func (s *Server) joinScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !validJoinHub(s.hubBase) {
		http.Error(w, "Configure a public HTTPS Hub URL first", 503)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.WriteString(w, strings.ReplaceAll(joinscript.Script, "@@CLAWCTL_PUBLIC_URL@@", s.hubBase))
}
func (s *Server) joinPowerShell(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !validJoinHub(s.hubBase) {
		http.Error(w, "Configure a public HTTPS Hub URL first", 503)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Quote for a PowerShell single-quoted string, including valid URL apostrophes.
	_, _ = io.WriteString(w, strings.ReplaceAll(joinscript.PowerShell, "@@CLAWCTL_PUBLIC_URL@@", strings.ReplaceAll(s.hubBase, "'", "''")))
}

func joinJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func joinDecode(w http.ResponseWriter, r *http.Request, out any) bool {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("Content-Type") != "application/json" {
		joinJSON(w, 415, map[string]string{"error": "JSON required"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	raw, err := io.ReadAll(r.Body)
	if err != nil || !joinObject(raw) {
		joinJSON(w, 400, map[string]string{"error": "Invalid request"})
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		joinJSON(w, 400, map[string]string{"error": "Invalid request"})
		return false
	}

	return true
}

// The device contract is a single object with unique, non-null fields.
func joinObject(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return false
		}
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') {
		return false
	}
	return d.Decode(&struct{}{}) == io.EOF
}
func (s *Server) joinStart(w http.ResponseWriter, r *http.Request) {
	var req operator.JoinStart
	if !joinDecode(w, r, &req) {
		return
	}
	if !validJoinHub(s.hubBase) || s.agentBundles == nil {
		joinJSON(w, 503, map[string]string{"error": "Joining is not configured"})
		return
	}
	result, err := s.operator.StartJoin(req, s.joinClientIP.Resolve(r))
	if err != nil {
		status := 500
		if errors.Is(err, operator.ErrJoinRate) || errors.Is(err, store.ErrJoinFull) {
			status = 429
			w.Header().Set("Retry-After", "60")
		}
		if errors.Is(err, operator.ErrJoinInput) {
			status = 400
		}
		joinJSON(w, status, map[string]string{"error": http.StatusText(status)})
		return
	}
	joinJSON(w, 200, result)
}
func (s *Server) joinPoll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Secret string `json:"device_secret"`
	}
	if !joinDecode(w, r, &req) {
		return
	}
	payload, status, err := s.operator.PollJoin(req.Secret)
	if err != nil {
		joinJSON(w, 500, map[string]string{"error": "Join unavailable"})
		return
	}
	if status != 200 {
		joinJSON(w, status, map[string]string{"state": payload.State})
		return
	}
	joinJSON(w, status, payload)
}
func (s *Server) joinBundle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	arch := r.PathValue("arch")
	secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	spec, found := lookupAgentBundleSpec(arch)
	if !ok || !found || !s.operator.JoinBundleAuthorized(secret, spec.OS, spec.Arch) {
		http.Error(w, "Download unavailable", 404)
		return
	}
	s.downloadAgentBundle(w, r)
}

type joinRow struct {
	store.JoinRequest
	DisplayName string
	Minutes     int
}
type joinView struct {
	Rows    []joinRow
	Command string
	Tailnet bool
}

func (s *Server) joinPage(w http.ResponseWriter, r *http.Request) {
	rows, err := s.operator.ListJoins()
	if err != nil {
		s.fail(w, "Waiting machines unavailable", err)
		return
	}
	view := &joinView{Command: "curl -fsSL " + s.hubBase + "/join.sh | sudo bash", Tailnet: s.operator.JoinKeysConfigured()}
	for _, j := range rows {
		view.Rows = append(view.Rows, joinRow{j, operator.JoinDisplayName(j.Hostname), int(time.Until(j.ExpiresAt).Minutes()) + 1})
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, "join.html", page{Title: "Waiting to join", Nav: "machines-enrollment", Join: view})
}
func (s *Server) joinList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.operator.ListJoins()
	if err != nil {
		joinJSON(w, 500, map[string]string{"error": "Waiting machines unavailable"})
		return
	}
	joinJSON(w, 200, operator.JoinRequestsResult{Requests: rows})
}
func (s *Server) joinDecide(w http.ResponseWriter, r *http.Request) {
	if !humanWebAdmin(r) {
		http.Error(w, "Admin access required", 403)
		return
	}
	if !operatorWebForm(w, r, map[string]bool{"join_id": true, "display_name": true}, "join_id", "display_name", "decision") {
		http.Error(w, "Invalid form", 400)
		return
	}
	ids, names := r.PostForm["join_id"], r.PostForm["display_name"]
	if len(ids) == 0 || len(ids) > 20 || len(ids) != len(names) || (r.PostForm.Get("decision") != "approve" && r.PostForm.Get("decision") != "reject") {
		http.Error(w, "Choose waiting machines and names", 400)
		return
	}
	rows, err := s.operator.ListJoins()
	if err != nil {
		http.Error(w, "Waiting machines unavailable", 503)
		return
	}
	for i, id := range ids {
		var bundle operator.JoinBundle
		for _, row := range rows {
			if row.Code == id && s.agentBundles != nil {
				key := row.OS + "-" + row.Arch
				b := s.agentBundles.items[key]
				bundle = operator.JoinBundle{URL: s.hubBase + "/v1/join/bundle/" + key, SHA256: b.SHA256}
			}
		}
		if err := s.operator.DecideJoin(r.Context(), id, names[i], r.PostForm.Get("decision") == "approve", s.hubBase, bundle, operator.ActorFromRequest(r, operator.SourceKindWeb)); err != nil {
			s.renderActionStatus(w, r, 409, "Waiting to join", "Could not approve this machine", "The request changed, its name is invalid, or enrollment is unavailable. Refresh and try again.", "/machines/join")
			return
		}
	}
	http.Redirect(w, r, "/machines/join", http.StatusSeeOther)
}
