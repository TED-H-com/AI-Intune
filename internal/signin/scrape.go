package signin

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var urlPattern = regexp.MustCompile(`https://[^\s<>"'\x1b]+`)
var devicePatterns = map[string]*regexp.Regexp{"codex": regexp.MustCompile(`\b[A-Z0-9]{4,5}-[A-Z0-9]{4,5}\b`), "gh": regexp.MustCompile(`\b[A-Z0-9]{4}-[A-Z0-9]{4}\b`)}

func ValidURL(cli, raw string) bool {
	if len(raw) == 0 || len(raw) > 8192 {
		return false
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	switch cli {
	case "codex":
		return h == "auth.openai.com"
	case "agy":
		return h == "accounts.google.com" || strings.HasSuffix(h, ".google.com")
	case "claude":
		return h == "claude.ai" || h == "claude.com" || h == "console.anthropic.com"
	case "grok":
		return h == "auth.x.ai" || h == "accounts.x.ai"
	case "gh":
		return h == "github.com"
	}
	return false
}
func ValidCode(cli, code string) bool {
	r := devicePatterns[cli]
	return r != nil && r.FindString(code) == code && code != ""
}
func Scrape(cli, text string) (link, code string, paste, browser bool) {
	for _, span := range urlPattern.FindAllStringIndex(text, -1) {
		if span[1] == len(text) {
			continue
		}
		v := text[span[0]:span[1]]
		v = strings.TrimRight(v, ".,)")
		if ValidURL(cli, v) {
			link = v
		}
	}
	if r := devicePatterns[cli]; r != nil {
		code = r.FindString(text)
	}
	low := strings.ToLower(text)
	paste = strings.Contains(low, "paste") || strings.Contains(low, "authorization code") || strings.Contains(low, "enter the code")
	browser = cli == "grok" && (strings.Contains(low, "localhost") || strings.Contains(low, "127.0.0.1")) && !paste
	return
}

func ValidPastedCode(code string) bool {
	if len(code) == 0 || len(code) > 4096 || !utf8.ValidString(code) {
		return false
	}
	for _, r := range code {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
