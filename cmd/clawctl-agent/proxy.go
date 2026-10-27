package main

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Leave the default transport untouched unless a config proxy was supplied.
func configureHTTPClient(client *http.Client, raw string) error {
	if raw == "" {
		return nil
	}
	proxy, err := url.Parse(raw)
	if err != nil || (proxy.Scheme != "http" && proxy.Scheme != "https") || proxy.Hostname() == "" || strings.ContainsAny(raw, " \t\r\n") || proxy.User != nil || proxy.RawQuery != "" || proxy.Fragment != "" {
		return fmt.Errorf("invalid proxy_url: expected an absolute HTTP or HTTPS proxy URL without credentials, query or fragment")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxy)
	client.Transport = transport
	return nil
}

// redactedProxyError preserves the error chain used by the retry classifier.
type redactedProxyError struct{ cause error }

var proxyUserinfo = regexp.MustCompile(`(?i)(https?://)[^/\s]*@`)

func (e redactedProxyError) Error() string {
	return proxyUserinfo.ReplaceAllString(e.cause.Error(), "${1}[REDACTED]@")
}
func (e redactedProxyError) Unwrap() error { return e.cause }
func redactProxyError(err error) error {
	if err == nil {
		return nil
	}
	return redactedProxyError{err}
}
