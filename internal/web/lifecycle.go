package web

import (
	"net/http"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
)

type lifecyclePageView struct {
	Rows      []lifecyclePageRow
	Truncated bool
	Limit     int
}

type lifecyclePageRow struct {
	operator.StaleMachineReviewItem
	AgeHours int64
}

func (s *Server) lifecycle(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	access := accessFromRequest(r)
	result, err := s.operator.ListStaleMachineCandidates(now, func(string) bool { return access.CanView })
	if err != nil {
		s.fail(w, "讀取名冊整理失敗", err)
		return
	}
	view := &lifecyclePageView{Rows: []lifecyclePageRow{}, Truncated: result.Truncated, Limit: result.Limit}
	for _, item := range result.Items {
		view.Rows = append(view.Rows, lifecyclePageRow{StaleMachineReviewItem: item, AgeHours: int64(now.Sub(item.CreatedAt) / time.Hour)})
	}
	s.render(w, r, "lifecycle.html", page{
		Title: "名冊整理", Nav: "machines-lifecycle",
		Now: now.Local().Format("2006-01-02 15:04"), Lifecycle: view,
	})
}
