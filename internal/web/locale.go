package web

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

type navigationLocale string

const (
	navigationLocaleTraditionalChinese navigationLocale = "zh-Hant"
	navigationLocaleEnglish            navigationLocale = "en"
	navigationLocaleCookie                              = "clawctl_navigation_locale"
	navigationLocaleCookieMaxAge                        = 365 * 24 * 60 * 60
	navigationReturnTargetMaxBytes                      = 4096
	// The longest valid switch form: the longer locale and a maximum-length
	// return_to with every byte percent-encoded.
	navigationLanguageFormMaxBytes = len("locale=zh-Hant&return_to=") + 3*navigationReturnTargetMaxBytes
)

type navigationLocaleView struct {
	SignoutLabel    string
	AccountLabel    string
	SecretsLabel    string
	ChannelsLabel   string
	AttentionLabel  string
	SigninsLabel    string
	ReadinessLabel  string
	Tag             string
	ContentTag      string
	PageTitle       string
	ToggleLocale    string
	ToggleReturnTo  string
	ToggleLabel     string
	ToggleTitle     string
	SkipLabel       string
	BrandAria       string
	BrandLabel      string
	VerifiedLabel   string
	UnverifiedLabel string
	MainNavAria     string
	NavGroupLabel   string
	DashboardLabel  string
	DevicesLabel    string
	AppsLabel       string
	EndpointLabel   string
	AgentsLabel     string
	ReportsLabel    string
	TenantLabel     string
	SupportLabel    string
	BreadcrumbAria  string
	BreadcrumbHome  string
}

func navigationLocaleFromRequest(r *http.Request) navigationLocale {
	if r == nil {
		return navigationLocaleTraditionalChinese
	}
	cookie, err := r.Cookie(navigationLocaleCookie)
	if err != nil {
		return navigationLocaleTraditionalChinese
	}
	locale, ok := parseNavigationLocale(cookie.Value)
	if !ok {
		return navigationLocaleTraditionalChinese
	}
	return locale
}

func parseNavigationLocale(raw string) (navigationLocale, bool) {
	switch navigationLocale(raw) {
	case navigationLocaleTraditionalChinese:
		return navigationLocaleTraditionalChinese, true
	case navigationLocaleEnglish:
		return navigationLocaleEnglish, true
	default:
		return navigationLocaleTraditionalChinese, false
	}
}

func navigationLocaleFor(r *http.Request, title string) navigationLocaleView {
	locale := navigationLocaleFromRequest(r)
	requestURI := "/"
	if r != nil && r.URL != nil && strings.HasPrefix(r.URL.RequestURI(), "/") {
		requestURI = r.URL.RequestURI()
	}
	target := navigationLocaleEnglish
	view := navigationLocaleView{
		SignoutLabel:    "登出",
		AccountLabel:    "帳號安全性",
		SecretsLabel:    "密鑰管理",
		ChannelsLabel:   "通知管道",
		AttentionLabel:  "待處理事項",
		SigninsLabel:    "登入狀態",
		ReadinessLabel:  "整備檢查",
		Tag:             string(navigationLocaleTraditionalChinese),
		ContentTag:      string(navigationLocaleTraditionalChinese),
		PageTitle:       traditionalNavigationText(title),
		ToggleLabel:     "English",
		ToggleTitle:     "將管理中心導覽切換為英文",
		SkipLabel:       "跳到主要內容",
		BrandAria:       "AI-Intune 管理中心首頁",
		BrandLabel:      "AI-Intune 系統管理中心",
		VerifiedLabel:   "Tailscale 已驗證",
		UnverifiedLabel: "Operator 未驗證",
		MainNavAria:     "主要導覽",
		NavGroupLabel:   "管理中心",
		DashboardLabel:  "儀表板",
		DevicesLabel:    "裝置",
		AppsLabel:       "應用程式",
		EndpointLabel:   "端點安全性",
		AgentsLabel:     "代理程式",
		ReportsLabel:    "報告",
		TenantLabel:     "租用戶管理",
		SupportLabel:    "疑難排解 + 支援",
		BreadcrumbAria:  "麵包屑",
		BreadcrumbHome:  "AI-Intune 管理中心",
	}
	if locale == navigationLocaleEnglish {
		target = navigationLocaleTraditionalChinese
		view = navigationLocaleView{
			SignoutLabel:    "Sign out",
			AccountLabel:    "Account security",
			SecretsLabel:    "Secrets",
			ChannelsLabel:   "Channels",
			AttentionLabel:  "Attention / Loops",
			SigninsLabel:    "Sign-ins",
			ReadinessLabel:  "Readiness",
			Tag:             string(navigationLocaleEnglish),
			ContentTag:      string(navigationLocaleTraditionalChinese),
			PageTitle:       englishNavigationText(title),
			ToggleLabel:     "繁體中文",
			ToggleTitle:     "Switch management-center navigation to Traditional Chinese",
			SkipLabel:       "Skip to main content",
			BrandAria:       "AI-Intune admin center home",
			BrandLabel:      "AI-Intune admin center",
			VerifiedLabel:   "Tailscale verified",
			UnverifiedLabel: "Operator not verified",
			MainNavAria:     "Primary navigation",
			NavGroupLabel:   "Admin center",
			DashboardLabel:  "Dashboard",
			DevicesLabel:    "Devices",
			AppsLabel:       "Apps",
			EndpointLabel:   "Endpoint security",
			AgentsLabel:     "Agents",
			ReportsLabel:    "Reports",
			TenantLabel:     "Tenant administration",
			SupportLabel:    "Troubleshooting + support",
			BreadcrumbAria:  "Breadcrumb",
			BreadcrumbHome:  "AI-Intune admin center",
		}
	}
	view.ToggleLocale = string(target)
	view.ToggleReturnTo = requestURI
	return view
}

var englishNavigationTexts = map[string]string{
	"總覽":                    "Overview",
	"裝置":                    "Devices",
	"裝置註冊":                  "Device enrollment",
	"裝置生命週期":                "Device lifecycle",
	"裝置組態":                  "Device configuration",
	"裝置合規性":                 "Device compliance",
	"診斷":                    "Diagnostics",
	"代理程式活動":                "Agent activity",
	"應用程式":                  "Apps",
	"部署":                    "Deployments",
	"新增部署":                  "New deployment",
	"更新":                    "Updates",
	"報告":                    "Reports",
	"變更":                    "Changes",
	"票證使用量":                 "Ticket usage",
	"註冊報告":                  "Enrollment report",
	"軟體清查":                  "Software inventory",
	"每機安裝狀態":                "Per-device installation status",
	"發佈與指派":                 "Published and assigned",
	"稽核記錄":                  "Audit log",
	"維護":                    "Maintenance",
	"還原演練":                  "Restore drill",
	"資料揭露":                  "Data disclosure",
	"確認建立 deployment":       "Confirm deployment creation",
	"確認繼續":                  "Confirm continuation",
	"確認部署動作":                "Confirm deployment action",
	"確認永久清理":                "Confirm permanent cleanup",
	"確認還原演練":                "Confirm restore drill",
	"確認註冊上限":                "Confirm enrollment limit",
	"確認派工":                  "Confirm assignment",
	"確認設定原則":                "Confirm configuration policy",
	"確認設定指派":                "Confirm configuration assignment",
	"確認合規性原則":               "Confirm compliance policy",
	"確認合規性指派":               "Confirm compliance assignment",
	"確認 Store package":      "Confirm Store package",
	"確認 Profile":            "Confirm profile",
	"確認 Profile Assignment": "Confirm profile assignment",
	"註冊上限已更新":               "Enrollment limit updated",
	"資料清理完成":                "Data cleanup completed",

	"裝置子選單":         "Devices navigation",
	"裝置詳細資料子選單":     "Device details navigation",
	"更新子選單":         "Updates navigation",
	"代理程式子選單":       "Agents navigation",
	"代理程式活動詳細資料子選單": "Agent activity details navigation",
	"疑難排解子選單":       "Troubleshooting navigation",
	"應用子選單":         "Apps navigation",
	"部署子選單":         "Deployments navigation",
	"部署詳細資料子選單":     "Deployment details navigation",
	"報告子選單":         "Reports navigation",
	"租用戶子選單":        "Tenant administration navigation",
	"代理程式":          "Agents",
	"疑難排解 + 支援":     "Troubleshooting + support",
	"租用戶管理":         "Tenant administration",
	"概觀":            "Overview",
	"所有裝置":          "All devices",
	"監視":            "Monitor",
	"註冊裝置":          "Enroll devices",
	"組態":            "Configuration",
	"合規性":           "Compliance",
	"生命週期":          "Lifecycle",
	"已退役":           "Retired",
	"裝置診斷":          "Device diagnostics",
	"活動":            "Activity",
	"設定檔":           "Profiles",
	"所有活動":          "All activity",
	"期望狀態":          "Desired state",
	"事件":            "Events",
	"驗證證據":          "Verification evidence",
	"屬性":            "Properties",
	"應用與憑證":         "Apps and credentials",
	"工作單":           "Jobs",
	"動作":            "Actions",
	"事件時間軸":         "Event timeline",
	"資料":            "Data",
	"應用程式目錄":        "App catalog",
	"指派":            "Assignments",
	"安裝套件":          "Installation packages",
	"套件擷取":          "Package fetches",
	"作業":            "Operations",
	"全部":            "All",
	"進行中":           "Active",
	"已暫停 / 卡住":      "Paused / stuck",
	"已完成":           "Finished",
	"監視與卡住":         "Monitoring and stuck",
	"目標與工作單":        "Targets and jobs",
	"設定":            "Settings",
	"更新概觀":          "Update overview",
	"報告總覽":          "Reports overview",
	"註冊":            "Enrollment",
	"安裝狀態":          "Installation status",
	"Checks / 檢查":   "Checks",
	"離線通知":          "Offline alerts",
	"確認 Tailnet 規則": "Confirm Tailnet rule",
	"確認指派使用者":       "Confirm assigned user",
	"Set up disabled schedules / 建立停用排程": "Set up disabled schedules",
	// Action results, the titles of the pages a form submission returns.
	"使用者不在名冊":                                        "User not in the roster",
	"來源不可用":                                          "Source unavailable",
	"已 abandon deployment":                           "Deployment abandoned",
	"已 continue deployment":                          "Deployment continued",
	"已 retry deployment":                             "Deployment retried",
	"已 skip failed batch":                            "Failed batch skipped",
	"已 skip_failed_batch deployment":                 "Failed batch skipped",
	"已建立 deployment":                                 "Deployment created",
	"已撤銷 pending enrollment ticket":                  "Pending enrollment ticket revoked",
	"已確認原本的 deployment abandon 結果（replay）":           "Deployment already abandoned",
	"已確認原本的 deployment continue 結果（replay）":          "Deployment already continued",
	"已確認原本的 deployment create 結果（replay）":            "Deployment already created",
	"已確認原本的 deployment retry 結果（replay）":             "Deployment already retried",
	"已確認原本的 deployment skip_failed_batch 結果（replay）": "Failed batch already skipped",
	"已確認原本的 pending enrollment ticket 撤銷結果（replay）":  "Pending enrollment ticket already revoked",
	"已確認原本的 skip failed batch 結果（replay）":            "Failed batch already skipped",
	"找不到機器":                                          "Device not found",
	"指派未完成":                                          "Assignment not completed",
	"指派版本已變更":                                        "Assignment revision changed",
	"排程操作失敗":                                         "Schedule action failed",
	"未建立 Tailnet 規則預覽":                               "Tailnet rule preview not created",
	"未建立上限預覽":                                        "Enrollment limit preview not created",
	"未建立合規性原則預覽":                                     "Compliance policy preview not created",
	"未建立指派預覽":                                        "Assignment preview not created",
	"未建立清理預覽":                                        "Cleanup preview not created",
	"未建立演練預覽":                                        "Restore drill preview not created",
	"未建立設定原則預覽":                                      "Configuration policy preview not created",
	"未建立還原演練":                                        "Restore drill not created",
	"未指派合規性原則":                                       "Compliance policy not assigned",
	"未指派設定原則":                                        "Configuration policy not assigned",
	"未更改上限":                                          "Enrollment limit not changed",
	"未清理資料":                                          "Data not cleaned up",
	"未發佈合規性原則":                                       "Compliance policy not published",
	"未發佈設定原則":                                        "Configuration policy not published",
	"未變更 Tailnet 規則":                                 "Tailnet rule not changed",
	"權限不足":                                           "Insufficient permissions",
	"沒有 abandon deployment":                          "Deployment not abandoned",
	"沒有 continue deployment":                         "Deployment not continued",
	"沒有 retry deployment":                            "Deployment not retried",
	"沒有 skip failed batch":                           "Failed batch not skipped",
	"沒有 skip_failed_batch deployment":                "Failed batch not skipped",
	"沒有執行 artifact fetch":                            "Artifact fetch not run",
	"沒有執行 deployment action":                         "Deployment action not run",
	"沒有執行這個動作":                                       "Action not run",
	"沒有建立 assignment preview":                        "Assignment preview not created",
	"沒有建立 deployment":                                "Deployment not created",
	"沒有建立 deployment action preview":                 "Deployment action preview not created",
	"沒有建立 deployment preview":                        "Deployment preview not created",
	"沒有建立 enroll 預覽":                                 "Enrollment preview not created",
	"沒有建立 fetch operation":                           "Fetch operation not created",
	"沒有建立 fetch preview":                             "Fetch preview not created",
	"沒有建立 package preview":                           "Package preview not created",
	"沒有建立 profile preview":                           "Profile preview not created",
	"沒有建立 skip failed batch preview":                 "Skip failed batch preview not created",
	"沒有建立名冊備註預覽":                                     "Registry notes preview not created",
	"沒有建立待兌換 enroll 票的撤銷預覽":                          "Pending enrollment ticket revocation preview not created",
	"沒有建立派工預覽":                                       "Assignment preview not created",
	"沒有建立生命週期預覽":                                     "Lifecycle preview not created",
	"沒有建立重新命名預覽":                                     "Rename preview not created",
	"沒有指派 profile":                                   "Profile not assigned",
	"沒有指派 verifier":                                  "Verifier not assigned",
	"沒有撤銷待兌換的 enroll 票":                              "Pending enrollment ticket not revoked",
	"沒有改 channel":                                    "Channel not changed",
	"沒有更新名冊備註":                                       "Registry notes not updated",
	"沒有發布 package":                                   "Package not published",
	"沒有發布 profile":                                   "Profile not published",
	"沒有確認機器生命週期結果":                                   "Device lifecycle result not confirmed",
	"沒有確認派工結果":                                       "Assignment result not confirmed",
	"沒有變更機器生命週期":                                     "Device lifecycle not changed",
	"沒有重新命名":                                         "Device not renamed",
	"沒有開 enroll 票":                                   "Enrollment ticket not issued",
	"沒有開啟終端":                                         "Terminal not opened",
	"沒有顯示 enroll 票":                                  "Enrollment ticket not shown",
	"無法讀取 fetch operation":                           "Fetch operation unavailable",
	"無法變更離線通知":                                       "Offline alerts not changed",
	"無法顯示 fetch operation":                           "Fetch operation unavailable",
	"無法驗證 artifact":                                  "Artifact not verified",
	"目前沒有資料需要清理":                                     "No data to clean up",
	"表單不合法":                                          "Invalid form",
	"診斷建立失敗":                                         "Diagnostics not created",
	"診斷預覽失敗":                                         "Diagnostics preview not created",
	"這台給不出可以連過去的位址":                                  "No reachable address for this device",
}

// englishNavigationPatterns translate titles that embed a name or an ID.
// The first pattern whose prefix and suffix both match wins, so a pattern
// must come before every shorter pattern that would also match its titles.
var englishNavigationPatterns = []struct{ zhPrefix, zhSuffix, enPrefix, enSuffix string }{
	{"確認撤銷 ", " 的待兌換 enroll 票", "Confirm revoking the pending enrollment ticket for ", ""},
	{"確認 ", " 的 enroll 票", "Confirm the enrollment ticket for ", ""},
	{"確認 ", " 的生命週期變更", "Confirm the lifecycle change for ", ""},
	{"確認 ", " 的診斷", "Confirm diagnostics for ", ""},
	{"代理程式活動 ", "", "Agent activity ", ""},
	{"確認重新命名 ", "", "Confirm rename ", ""},
	{"確認名冊備註 ", "", "Confirm registry notes ", ""},
	{"確認 fetch ", "", "Confirm fetch ", ""},
	{"確認 ", "", "Confirm ", ""},
	{"部署 ", "", "Deployment ", ""},
	{"", " 的資料", "", " data"},
	{"", " 事件時間軸", "", " event timeline"},
	{"", " 的終端", "", " terminal"},
	{"", " 的 enroll 票", "", " enrollment ticket"},
}

func englishNavigationText(value string) string {
	if translated, ok := englishNavigationTexts[value]; ok {
		return translated
	}
	for _, pattern := range englishNavigationPatterns {
		if len(value) > len(pattern.zhPrefix)+len(pattern.zhSuffix) &&
			strings.HasPrefix(value, pattern.zhPrefix) && strings.HasSuffix(value, pattern.zhSuffix) {
			name := strings.TrimSuffix(strings.TrimPrefix(value, pattern.zhPrefix), pattern.zhSuffix)
			return pattern.enPrefix + name + pattern.enSuffix
		}
	}
	return value
}

func localizeSubNavigation(nav *subNavigation, locale navigationLocale) {
	if nav == nil {
		return
	}
	translate := traditionalNavigationText
	if locale == navigationLocaleEnglish {
		translate = englishNavigationText
	}
	nav.Label = translate(nav.Label)
	nav.Title = translate(nav.Title)
	for index := range nav.Items {
		nav.Items[index].Label = translate(nav.Items[index].Label)
	}
}

func localizeAccessView(access *accessView, locale navigationLocale) {
	if access == nil || locale != navigationLocaleEnglish || !access.Known {
		return
	}
	access.Attribution = "Source device " + access.Device + "; Tailscale user " + access.Login
}

func (s *Server) setNavigationLanguage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, "導覽語言請求無效。", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(navigationLanguageFormMaxBytes))
	if err := r.ParseForm(); err != nil || len(r.PostForm) != 2 ||
		len(r.PostForm["locale"]) != 1 || len(r.PostForm["return_to"]) != 1 {
		http.Error(w, "導覽語言請求無效。", http.StatusBadRequest)
		return
	}
	locale, ok := parseNavigationLocale(r.PostForm.Get("locale"))
	if !ok {
		http.Error(w, "不支援的導覽語言。", http.StatusBadRequest)
		return
	}
	returnTarget, err := navigationReturnTarget(r.PostForm.Get("return_to"))
	if err != nil {
		http.Error(w, "導覽語言請求無效。", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: navigationLocaleCookie, Value: string(locale), Path: "/",
		MaxAge: navigationLocaleCookieMaxAge, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, returnTarget, http.StatusSeeOther)
}

func navigationReturnTarget(target string) (string, error) {
	if len(target) == 0 || len(target) > navigationReturnTargetMaxBytes ||
		strings.HasPrefix(target, "//") ||
		strings.ContainsAny(target, "\\#\r\n") {
		return "", errors.New("return target is not a bounded local path")
	}
	for _, character := range target {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return "", errors.New("return target contains control characters")
		}
	}
	parsed, err := url.ParseRequestURI(target)
	if err != nil || parsed.Host != "" || parsed.Path == "" {
		return "", errors.New("return target is not a local request URI")
	}
	return parsed.RequestURI(), nil
}

// navigationGroup keeps detail pages selected in their parent workload.
func navigationGroup(nav string) string {
	switch {
	case nav == "machines-diagnostics":
		return "support"
	case nav == "updates" || nav == "machines" || strings.HasPrefix(nav, "machines-"):
		return "machines"
	case strings.HasPrefix(nav, "tenant-"):
		return "tenant"
	case strings.HasSuffix(nav, "-report"):
		return "reports"
	}
	switch nav {
	case "reports", "checks", "changes", "tickets", "audit":
		return "reports"
	default:
		return nav
	}
}

func init() { funcs["navigationGroup"] = navigationGroup }

var traditionalNavigationTexts = map[string]string{
	"Waiting to join": "等待加入", "Schedules": "排程", "Disk policies": "磁碟原則",
	"Disk alerts": "磁碟警示", "Approvals": "核准", "Certificates": "憑證",
	"Checks / 檢查": "檢查", "Host readiness": "整備檢查", "Sign-ins": "登入狀態",
	"Channels": "通知管道", "Secrets": "密鑰管理", "Attention / Loops": "待處理事項",
	"Set up disabled schedules / 建立停用排程": "建立停用排程",
}

func traditionalNavigationText(value string) string {
	if translated, ok := traditionalNavigationTexts[value]; ok {
		return translated
	}
	return value
}
