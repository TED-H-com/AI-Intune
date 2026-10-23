package main

import (
	"bufio"
	"net"
	"net/http"
	"net/http/pprof"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
)

// Resolve every profile below one registered pattern, guarded by the same
// authority, human admin authentication, and security policy as admin UI routes.
func registerPprof(mux *http.ServeMux, policies map[string]operatorRoutePolicy) {
	const pattern = "GET /debug/pprof/"
	profiles := http.NewServeMux()
	profiles.HandleFunc("GET /debug/pprof/", pprof.Index)
	profiles.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	profiles.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	profiles.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	profiles.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profiles.ServeHTTP(w, r)
		r.Pattern = pattern
	}))
	policies[pattern] = operatorRoutePolicy{operatorauth.Admin, operatorHTML, operator.SourceKindWeb, operatorSecurityLocked, serviceIneligible}
}

// ResponseController preserves streaming and terminal/websocket upgrades through
// the status recorder. Direct interface users are supported as well.
type durationResponseWriter struct{ serviceResponseWriter }

func (w *durationResponseWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *durationResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil && w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	return conn, rw, err
}
