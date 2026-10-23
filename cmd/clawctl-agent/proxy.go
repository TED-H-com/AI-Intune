package main

import (
	"fmt"
	"net/http"
	"net/url"
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
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		envProxy, err := http.ProxyFromEnvironment(req)
		if err != nil || envProxy != nil {
			return envProxy, err
		}
		return proxy, nil
	}
	client.Transport = transport
	return nil
}
