package web

import (
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"strconv"
)

type diskReportView struct {
	Admin                bool
	Decisions            map[string]string
	Report               store.DiskReportPage
	Category, Confidence string
}

func (s *Server) diskReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	for k, v := range q {
		if len(v) != 1 || (k != "cursor" && k != "limit" && k != "category" && k != "confidence") {
			s.diskFormError(w, r, "/")
			return
		}
	}
	limit := 100
	var err error
	if q.Has("limit") {
		limit, err = strconv.Atoi(q.Get("limit"))
	}
	if err != nil {
		s.diskFormError(w, r, "/")
		return
	}
	actor := operator.ActorFromRequest(r, operator.SourceKindWeb)
	if p, ok := operatorauth.PrincipalFromContext(r.Context()); ok && p.Has(operatorauth.Admin) {
		actor.AuthCapability = "admin"
	}
	out, err := s.operator.DiskReportHumanFiltered(r.PathValue("id"), q.Get("cursor"), limit, q.Get("category"), q.Get("confidence"), actor)
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	decisions, _ := s.operator.DiskReportDecisions(out.ID)
	s.render(w, r, "disk_report.html", page{Title: "Deep disk analysis", DiskReport: &diskReportView{Admin: humanWebAdmin(r), Decisions: decisions, Report: out, Category: q.Get("category"), Confidence: q.Get("confidence")}})
}
