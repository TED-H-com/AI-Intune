package operator

import (
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/store"
	"math"
	"regexp"
	"time"
)

type CheckMetric struct{ Label, Value string }
type ReadReport struct {
	ScriptID, Name, Status, Badge, Class, Summary, RanAt string
	Metrics                                              []CheckMetric
	Findings                                             []string
}

// MachineReadReports excludes all free text, identities and unreviewed metrics.
func (s *Service) MachineReadReports(machine string) ([]ReadReport, error) {
	receipts, err := s.store.LatestReadReports(machine)
	if err != nil {
		return nil, err
	}
	out := []ReadReport{}
	for _, v := range receipts {
		out = append(out, projectReadReport(v))
	}
	return out, nil
}

var checkVersion = regexp.MustCompile(`^v?[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}$`)

func projectReadReport(v store.ReadReportReceipt) ReadReport {
	names := map[string]string{"oci-cost-report-v1": "OCI costs / 雲端費用", "network-watch-v1": "Network / 網路", "bat-release-check-v1": "BAT updates / 版本更新"}
	out := ReadReport{ScriptID: v.ScriptID, Name: names[v.ScriptID], Status: "unknown", Badge: "Not run / 尚未執行", Class: "st dim", Summary: "No result has been received. / 尚未收到結果。"}
	if v.JobID == "" {
		return out
	}
	if at, err := time.Parse(time.RFC3339Nano, v.RanAt); err == nil {
		out.RanAt = at.UTC().Format(time.RFC3339)
	}
	if v.Output == "" && (v.State == "not_started" || v.State == "claimed" || v.State == "running" || v.State == "verifying") {
		out.Badge = "Awaiting result / 等待結果"
		out.Summary = "The latest run has not returned a report yet. / 最近一次執行尚未回傳報告。"
		return out
	}
	out.Status = "error"
	out.Badge = "Could not check / 無法檢查"
	out.Class = "st red"
	out.Summary = "The latest run did not return a complete report. / 最近一次未回傳完整報告。"
	var raw struct {
		Schema   int                        `json:"schema_version"`
		Status   string                     `json:"status"`
		Metrics  map[string]json.RawMessage `json:"metrics"`
		Findings []struct {
			Reason string `json:"reason"`
		} `json:"findings"`
	}
	if v.ProcessFailed || len(v.Output) > 65536 || json.Unmarshal([]byte(v.Output), &raw) != nil || raw.Schema != 1 || len(raw.Findings) > 128 {
		return out
	}
	switch raw.Status {
	case "ok":
		out.Badge = "No issues found / 未發現問題"
		out.Class = "st green"
		out.Summary = "The check found no issues in the measured items. / 已量測項目未發現問題。"
	case "warn":
		out.Badge = "Needs attention / 需要留意"
		out.Class = "st amber"
		out.Summary = "Review the findings below. / 請查看下方發現。"
	case "urgent":
		out.Badge = "Needs urgent attention / 需要立即處理"
		out.Class = "st red"
		out.Summary = "A configured urgent threshold was exceeded. / 已超過設定的緊急門檻。"
	case "error":
	default:
		return out
	}
	out.Status = raw.Status
	add := func(key, label, kind string) {
		value := "Unknown / 未知"
		b, ok := raw.Metrics[key]
		if ok && string(b) != "null" {
			switch kind {
			case "number", "count":
				var n float64
				if json.Unmarshal(b, &n) == nil && !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 0 && n <= 1e12 && (kind != "count" || math.Trunc(n) == n) {
					if kind == "number" {
						value = fmt.Sprintf("USD %.2f", n)
					} else {
						value = fmt.Sprintf("%.0f", n)
					}
				}
			case "bool":
				var yes bool
				if json.Unmarshal(b, &yes) == nil {
					if yes {
						value = "Yes / 是"
					} else {
						value = "No / 否"
					}
				}
			case "version":
				var text string
				if json.Unmarshal(b, &text) == nil && checkVersion.MatchString(text) {
					value = text
				}
			}
		}
		out.Metrics = append(out.Metrics, CheckMetric{label, value})
	}
	switch v.ScriptID {
	case "oci-cost-report-v1":
		add("mtd_usd", "Month to date / 本月至今", "number")
		add("running_instances", "Running instances / 執行中主機", "count")
	case "network-watch-v1":
		add("online_peer_count", "Peers online / 已連線節點", "count")
		add("peer_count", "Peers measured / 已量測節點", "count")
		add("expected_offline_count", "Expected peers offline / 預期節點未連線", "count")
		add("derp_only_count", "Relay only / 僅透過中繼連線", "count")
		add("dns_failure_count", "Name lookup failures / 名稱查詢失敗", "count")
		add("cloudflared_active", "Cloudflare tunnel running / 通道執行中", "bool")
		add("listen_baseline_available", "Port baseline available / 有連接埠比較基準", "bool")
		add("listen_ports_changed", "Listening ports changed / 監聽連接埠已變更", "bool")
	case "bat-release-check-v1":
		add("installed_version", "Installed / 已安裝", "version")
		add("latest_stable", "Latest stable / 最新穩定版", "version")
		add("newer_available", "Update available / 有可用更新", "bool")
	}
	seen := map[string]bool{}
	for _, f := range raw.Findings {
		text := checkFinding(f.Reason)
		if !seen[text] {
			out.Findings = append(out.Findings, text)
			seen[text] = true
		}
	}
	return out
}
func checkFinding(reason string) string {
	if text, ok := checkFindings[reason]; ok {
		return text
	}
	return "Part of the check could not be completed. Review the machine's local configuration. / 部分檢查未能完成，請檢查裝置本機設定。"
}

var checkFindings = map[string]string{
	"cost_above_warn_threshold":        "Month-to-date cost exceeds the warning limit. / 本月至今費用超過提醒門檻。",
	"cost_above_urgent_threshold":      "Month-to-date cost exceeds the urgent limit. / 本月至今費用超過緊急門檻。",
	"expected_peers_offline":           "One or more expected peers are offline. / 一個或多個預期節點未連線。",
	"derp_only_peers":                  "Some peers connect only through a relay. / 部分節點僅透過中繼連線。",
	"dns_resolution_failed":            "A configured name lookup failed. / 設定的名稱查詢失敗。",
	"cloudflared_inactive":             "The Cloudflare tunnel service is stopped. / Cloudflare 通道服務已停止。",
	"cloudflared_service_missing":      "The Cloudflare tunnel service is not installed. / 尚未安裝 Cloudflare 通道服務。",
	"cloudflared_status_failed":        "The Cloudflare tunnel status could not be read. / 無法讀取 Cloudflare 通道狀態。",
	"listen_ports_changed":             "Listening ports differ from the configured baseline. / 監聽連接埠與設定基準不同。",
	"listen_diff_unavailable":          "Port changes could not be compared with the baseline. / 無法與基準比較連接埠變更。",
	"baseline_digest_mismatch":         "The saved port baseline is inconsistent. / 儲存的連接埠基準不一致。",
	"security_coverage_incomplete":     "Router checks, internet performance, Cloudflare analytics and historical security checks are not covered. / 尚未涵蓋路由器、網際網路效能、Cloudflare 分析與歷史安全檢查。",
	"new_stable_available":             "A newer stable BAT version is available. / BAT 有新的穩定版本。",
	"github_rate_limited_or_forbidden": "The release service refused this request or reached its request limit. / 版本服務拒絕要求或已達查詢上限。",
	"profile_missing":                  "The selected cloud account is not configured locally. / 本機缺少選取的雲端帳戶設定。",
	"oci_cli_missing":                  "The OCI command-line tool is not installed. / 尚未安裝 OCI 工具。",
	"oci_auth_failed":                  "The cloud account could not sign in. / 雲端帳戶無法登入。",
	"oci_permission_denied":            "The cloud account cannot read the required information. / 雲端帳戶無權讀取所需資訊。",
	"tailscale_not_running":            "Tailscale is not running. / Tailscale 未執行。",
	"tailscale_health_warning":         "Tailscale reported a warning. / Tailscale 回報提醒。",
	"tailscale_config_missing":         "Tailscale is not configured. / Tailscale 缺少設定。",
	"default_route_missing":            "No default network route was found. / 未找到預設網路路徑。",
	"installed_version_missing":        "The installed BAT version could not be read. / 無法讀取已安裝的 BAT 版本。",
	"stable_release_unavailable":       "No stable release could be read. / 無法讀取穩定版本。",
	"cli_missing":                      "A required tool is not installed. / 尚未安裝所需工具。",
	"cli_unavailable":                  "A required tool could not be started. / 無法啟動所需工具。",
	"ip_cli_missing":                   "The network route tool is not installed. / 尚未安裝網路路徑工具。",
	"ss_cli_missing":                   "The listening-port tool is not installed. / 尚未安裝連接埠工具。",
	"systemctl_cli_missing":            "The service status tool is not installed. / 尚未安裝服務狀態工具。",
	"getent_cli_missing":               "The name lookup tool is not installed. / 尚未安裝名稱查詢工具。",
	"tailscale_cli_missing":            "Tailscale is not installed. / 尚未安裝 Tailscale。",
	"curl_cli_missing":                 "The release download tool is not installed. / 尚未安裝版本查詢工具。",
	"tailscale_status_failed":          "Tailscale status could not be read. / 無法讀取 Tailscale 狀態。",
	"default_route_check_failed":       "Network routes could not be read. / 無法讀取網路路徑。",
	"listen_check_failed":              "Listening ports could not be read. / 無法讀取監聽連接埠。",
	"oci_rate_limited":                 "The cloud service request limit was reached. / 已達雲端服務要求上限。",
	"oci_config_invalid":               "The local cloud configuration is invalid. / 本機雲端設定無效。",
	"oci_tenancy_unavailable":          "The selected cloud account could not be read. / 無法讀取選取的雲端帳戶。",
	"oci_request_failed":               "The cloud service request failed. / 雲端服務查詢失敗。",
	"oci_usage_pagination_invalid":     "The cloud usage response was incomplete. / 雲端用量回應不完整。",
	"oci_usage_page_limit":             "Cloud usage exceeded the check's read limit. / 雲端用量超過本次讀取上限。",
	"oci_compartment_scope_limit":      "There are too many cloud compartments to count safely. / 雲端區間超過本次安全計數上限。",
	"unexpected_currency":              "Cloud costs were returned in an unexpected currency. / 雲端費用幣別不符。",
	"invalid_cost_amount":              "The cloud cost amount could not be read. / 無法讀取雲端費用金額。",
	"invalid_instance_count":           "The running-instance count could not be read. / 無法讀取執行中主機數。",
	"bat_updater_config_missing":       "BAT update settings could not be read. / 無法讀取 BAT 更新設定。",
	"bat_install_dir_missing":          "The BAT installation could not be found. / 找不到 BAT 安裝位置。",
	"github_request_failed":            "The release service could not be reached. / 無法連線版本服務。",
	"github_http_error":                "The release service returned an error. / 版本服務回傳錯誤。",
	"invalid_version":                  "The BAT version format is invalid. / BAT 版本格式無效。",
	"invalid_release_date":             "The release date could not be read. / 無法讀取版本發布日期。",
	"invalid_cli_response":             "A required tool returned an unreadable response. / 所需工具回傳無法讀取的資料。",
	"invalid_tailscale_response":       "Tailscale returned an unreadable response. / Tailscale 回傳無法讀取的資料。",
	"invalid_route_response":           "The network route response could not be read. / 無法讀取網路路徑回應。",
	"invalid_listen_response":          "The listening-port response could not be read. / 無法讀取連接埠回應。",
	"invalid_args":                     "The check settings are invalid. / 檢查設定無效。",
	"invalid_thresholds":               "The cost thresholds are invalid. / 費用門檻無效。",
	"root_execution_forbidden":         "This check must run under the agent's regular account. / 此檢查必須使用代理程式的一般帳戶執行。",
	"invalid_response_or_config":       "The check configuration or response could not be read. / 無法讀取檢查設定或回應。",
	"output_limit":                     "The report exceeded the allowed size. / 報告超過允許大小。",
	"cli_timeout":                      "A required tool took too long to respond. / 所需工具回應逾時。",
	"cli_output_limit":                 "A required tool returned too much data. / 所需工具回傳資料超過上限。",
}
