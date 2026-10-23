package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"testing"
)

func TestProxyPolicy(t *testing.T) {
	// ProxyFromEnvironment caches the environment; isolate each case in a process.
	if os.Getenv("CLAWCTL_PROXY_TEST") == "1" {
		client := &http.Client{}
		if err := configureHTTPClient(client, os.Getenv("CONFIG_PROXY")); err != nil {
			t.Fatal(err)
		}
		transport := http.DefaultTransport.(*http.Transport)
		if client.Transport != nil {
			transport = client.Transport.(*http.Transport)
		}
		req, _ := http.NewRequest("GET", "https://hub.example.com", nil)
		proxy, err := transport.Proxy(req)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if proxy != nil {
			got = proxy.String()
		}
		if got != os.Getenv("WANT_PROXY") {
			t.Fatalf("proxy = %q, want %q", got, os.Getenv("WANT_PROXY"))
		}
		if os.Getenv("CONFIG_PROXY") == "" && client.Transport != nil {
			t.Fatal("default transport changed")
		}
		return
	}
	for _, tc := range []struct{ name, config, env, want string }{
		{"config", "http://config.example:8080", "", "http://config.example:8080"},
		{"default", "", "", ""},
		{"env", "http://config.example:8080", "http://env.example:8080", "http://env.example:8080"},
		{"env-only", "", "http://env.example:8080", "http://env.example:8080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestProxyPolicy$")
			cmd.Env = append(os.Environ(), "CLAWCTL_PROXY_TEST=1", "CONFIG_PROXY="+tc.config, "WANT_PROXY="+tc.want,
				"HTTPS_PROXY="+tc.env, "https_proxy=", "HTTP_PROXY=", "http_proxy=", "NO_PROXY=", "no_proxy=", "ALL_PROXY=", "all_proxy=")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, output)
			}
		})
	}
}

func TestInvalidProxyConfig(t *testing.T) {
	for _, raw := range []string{"relative", "socks5://proxy:8080", "http://", "http://user:password@proxy", "http://proxy?q=1", "http://proxy#fragment", " http://proxy"} {
		if err := configureHTTPClient(&http.Client{}, raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}

func TestProxyConfigJSON(t *testing.T) {
	for _, proxy := range []string{"", "http://proxy:8080"} {
		b, err := json.Marshal(config{ProxyURL: proxy})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(b, &fields); err != nil {
			t.Fatal(err)
		}
		if _, present := fields["proxy_url"]; present != (proxy != "") {
			t.Fatal("proxy_url omitempty changed")
		}
		var decoded config
		if err := json.Unmarshal(b, &decoded); err != nil || decoded.ProxyURL != proxy {
			t.Fatal("proxy_url did not round trip")
		}
	}
}
