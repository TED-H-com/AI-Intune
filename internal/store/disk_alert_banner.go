package store

// DiskAlertBannerCounts contains only the two counts needed by authenticated HTML.
type DiskAlertBannerCounts struct {
	OpenCritical int
	OpenWarn     int
}

const diskAlertBannerQuery = `SELECT COALESCE(SUM(severity='critical'),0),COALESCE(SUM(severity='warn'),0) FROM disk_alerts WHERE cleared_at IS NULL`

func (s *Store) DiskAlertBannerCounts() (DiskAlertBannerCounts, error) {
	var out DiskAlertBannerCounts
	err := s.rdb.QueryRow(diskAlertBannerQuery).Scan(&out.OpenCritical, &out.OpenWarn)
	return out, err
}
