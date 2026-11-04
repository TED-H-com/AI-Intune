package web

import (
	"net/http"
	"net/url"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
)

type lifecyclePageView struct {
	Rows      []lifecyclePageRow
	NextHref  string
	Continued bool
	Truncated bool
	Limit     int
}

type lifecyclePageRow struct {
	operator.StaleMachineReviewItem
	AgeHours int64
}

func (s *Server) lifecycle(w http.ResponseWriter, r *http.Request) {
	cursor, err := operator.ParseStaleMachineReviewQuery(r.URL.RawQuery, r.URL.ForceQuery)
	if err != nil {
		http.Error(w, "名冊整理查詢無效，請從第一頁重新開啟", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	access := accessFromRequest(r)
	result, err := s.operator.ListStaleMachineCandidates(now, cursor, func(string) bool { return access.CanView })
	if err != nil {
		s.fail(w, "讀取名冊整理失敗", err)
		return
	}
	view := &lifecyclePageView{Rows: []lifecyclePageRow{}, Continued: cursor != "", Truncated: result.Truncated, Limit: result.Limit}
	if result.NextCursor != nil {
		view.NextHref = "/machines/lifecycle?cursor=" + url.QueryEscape(*result.NextCursor)
	}
	for _, item := range result.Items {
		view.Rows = append(view.Rows, lifecyclePageRow{StaleMachineReviewItem: item, AgeHours: int64(now.Sub(item.CreatedAt) / time.Hour)})
	}
	s.render(w, r, "lifecycle.html", page{
		Title: "名冊整理", Nav: "machines-lifecycle",
		Now: now.Local().Format("2006-01-02 15:04"), Lifecycle: view,
	})
}
