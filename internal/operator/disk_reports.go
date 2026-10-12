package operator

import (
	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"strconv"
)

func (s *Service) DiskReports(machine string) ([]store.DiskReportSummary, error) {
	return s.store.DiskReports(machine)
}
func (s *Service) DiskReport(id, cursor string, limit int) (store.DiskReportPage, error) {
	return s.store.DiskReport(id, cursor, limit, false)
}
func (s *Service) DiskReportHuman(id, cursor string, limit int, actor Actor) (store.DiskReportPage, error) {
	private := actor.AuthDecision == string(operatorauth.Authorized) && actor.AuthSubject != "" && (actor.AuthMethod == operatorauth.AuthMethodLocalAccountSession || actor.AuthMethod == operatorauth.AuthMethodLocalAPI) && actor.AuthCapability == "admin"
	return s.store.DiskReport(id, cursor, limit, private)
}

// Human filters operate on the complete bounded report, before pagination.
func (s *Service) DiskReportHumanFiltered(id, cursor string, limit int, category, confidence string, actor Actor) (store.DiskReportPage, error) {
	if category != "" {
		valid := false
		for _, v := range []string{"app-update-backups", "installer-leftovers", "release-build-directories", "unused-docker-images", "caches-models", "orphaned-processes", "agent-session-stores", "duplicate-archives"} {
			valid = valid || v == category
		}
		if !valid {
			return store.DiskReportPage{}, &store.OperatorRequestError{Code: "BAD_REQUEST", Detail: "invalid category"}
		}
	}
	if confidence != "" && confidence != "high" && confidence != "medium" && confidence != "low" {
		return store.DiskReportPage{}, &store.OperatorRequestError{Code: "BAD_REQUEST", Detail: "invalid confidence"}
	}
	start := 0
	var err error
	if cursor != "" {
		start, err = strconv.Atoi(cursor)
	}
	if err != nil || start < 0 || start > 500 || limit < 1 || limit > 100 {
		return store.DiskReportPage{}, &store.OperatorRequestError{Code: "BAD_REQUEST", Detail: "invalid pagination"}
	}
	out, err := s.DiskReportHuman(id, "", 100, actor)
	if err != nil {
		return out, err
	}
	items := append([]diskreport.Item{}, out.Items...)
	next := out.NextCursor
	for n := 0; next != "" && n < 4; n++ {
		v, e := s.DiskReportHuman(id, next, 100, actor)
		if e != nil {
			return out, e
		}
		items = append(items, v.Items...)
		next = v.NextCursor
	}
	filtered := []diskreport.Item{}
	for _, i := range items {
		if (category == "" || i.Category == category) && (confidence == "" || i.Confidence == confidence) {
			filtered = append(filtered, i)
		}
	}
	out.Items = []diskreport.Item{}
	out.NextCursor = ""
	if start < len(filtered) {
		end := start + limit
		if end < len(filtered) {
			out.NextCursor = strconv.Itoa(end)
		} else {
			end = len(filtered)
		}
		out.Items = filtered[start:end]
	}
	return out, nil
}
