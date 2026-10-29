package errlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSecretCorpus(t *testing.T) {
	// All credentials here are synthetic and deliberately short.
	corpus := []string{
		"Authorization: Bearer sample-value", "authorization=Basic c2FtcGxl", "Authorization: opaque-value",
		`{"Authorization":"Bearer sample-value"}`, "Bearer sample-value", "bEaReR sample-value",
		"https://host/path?token=sample-value&ok=yes", "password=sample-value", "SECRET=sample-value",
		`password="sample value"`, "secret='sample value'", `{"token":"sample-value"}`,
		"ACCESS_TOKEN=sample-value", "CF_API_TOKEN=sample-value", "CLOUDFLARE_API_KEY=sample-value",
		"https://user:sample-value@example.com/path", "postgres://user:sample-value@localhost/db",
		"https://user%40domain:sample%40value@localhost/path",
		"ghp_sample123", "gho_sample123", "ghu_sample123", "ghs_sample123", "ghr_sample123", "github_pat_sample_123",
		"-----BEGIN PRIVATE KEY-----\nsample-value\n-----END PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nsample-value\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----\nsample-value\n-----END EC PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nsample-value\n-----END OPENSSH PRIVATE KEY-----",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\nsample-value\n-----END ENCRYPTED PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----\nsample-value",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzYW1wbGUifQ.c2lnbmF0dXJl",
		"tskey-auth-sample123", "tskey-api-sample123", "tskey-client-sample123",
		"/home/person@example.com/log", `C:\Users\first.last+tag@example.co.uk\log`, "contact person@example.com",
	}
	for i, input := range corpus {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if !ContainsSecret(input) {
				t.Fatal("secret shape was not detected")
			}
			got := Redact("before " + input + " after")
			if got == "before "+input+" after" {
				t.Fatal("secret was not removed")
			}
			if ContainsSecret(got) {
				t.Fatal("secret remains after redaction")
			}
			if Redact(got) != got {
				t.Fatal("redaction is not idempotent")
			}
			if strings.Contains(got, "sample-value") {
				t.Fatal("credential payload remains")
			}
		})
	}
}

func TestRedactSafeAndMixed(t *testing.T) {
	for _, input := range []string{"", "request failed: status 503", "token expired", "password required", "[REDACTED]", "http://localhost:8080/path", "public key", "user@localhost"} {
		if ContainsSecret(input) || Redact(input) != input {
			t.Errorf("changed safe text %q", input)
		}
	}
	input := "failed token=sample-value&retry=1; Bearer another-value; ghp_example123"
	if got, want := Redact(input), "failed [REDACTED]&retry=1; [REDACTED]; [REDACTED]"; got != want {
		t.Errorf("mixed redaction = %q, want %q", got, want)
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct{ input, want string }{
		{"", ""}, {"  failed\n request\t timeout ", "failed request timeout"},
		{"attempt 123 took 4.5 seconds", "attempt <num> took <num> seconds"},
		{"id 550e8400-e29b-41d4-a716-446655440000", "id <uuid>"},
		{"address 0xAbCd and deadbeef", "address <hex> and <hex>"},
		{"open /var/log/agent.log failed", "open <path> failed"},
		{`open C:\Users\someone\agent.log failed`, "open <path> failed"},
		{`open \\server\share\agent.log failed`, "open <path> failed"},
		{"open ./agent.log and ../agent.log and ~/agent.log", "open <path> and <path> and <path>"},
		{"connect localhost:8080 failed", "connect localhost:<port> failed"},
		{"connect [::1]:443 failed", "connect [::<port>]:<port> failed"},
		{"stable failure message", "stable failure message"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := Normalize(tc.input)
			if got != tc.want {
				t.Errorf("Normalize = %q, want %q", got, tc.want)
			}
			if Normalize(got) != got {
				t.Fatal("normalization is not idempotent")
			}
		})
	}
}

func TestFingerprint(t *testing.T) {
	a := "open /var/a.log id 550e8400-e29b-41d4-a716-446655440000 addr 0xabc port localhost:8080 attempt 3"
	b := "open /tmp/b.log id 650e8400-e29b-41d4-a716-446655440001 addr 0xdef port localhost:9090 attempt 7"
	got := Fingerprint("intune-agent", "agent.open.failed", a)
	sum := sha256.Sum256([]byte("intune-agent|agent.open.failed|" + Normalize(a)))
	if got != hex.EncodeToString(sum[:])[:16] {
		t.Fatal("fingerprint does not follow hash contract")
	}
	if got != Fingerprint("intune-agent", "agent.open.failed", b) {
		t.Fatal("variable fields change fingerprint")
	}
	for _, other := range []string{
		Fingerprint("bat-server", "agent.open.failed", a),
		Fingerprint("intune-agent", "agent.other.failed", a),
		Fingerprint("intune-agent", "agent.open.failed", "different failure"),
	} {
		if other == got {
			t.Fatal("distinct error shares fingerprint")
		}
	}
}

func TestRecordJSON(t *testing.T) {
	record := Record{TS: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC), MachineID: "machine-1", Component: "intune-agent", Version: "1.2.3", Level: "error", Code: "agent.open.failed", Msg: "failed", Fingerprint: "0123456789abcdef", Count: 1, Context: map[string]any{"operation": "open"}}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	keys := []string{"ts", "machine_id", "component", "version", "level", "code", "msg", "fingerprint", "count", "context"}
	if len(fields) != len(keys) {
		t.Fatalf("unexpected JSON fields: %s", data)
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			t.Errorf("missing field %s", key)
		}
	}
	if fields["ts"] != "2026-10-29T12:00:00Z" {
		t.Errorf("timestamp = %v", fields["ts"])
	}
	var decoded Record
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(record, decoded) {
		t.Fatal("record did not round trip")
	}
}
