// Package scriptcatalog is the build-time allowlist shared by Hub and agent.
package scriptcatalog

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const Kind = "script_v1"

//go:embed fleet-probe-v1.sh
var probe []byte

//go:embed bat-sweep-report-v1.py
var batSweep []byte

//go:embed disk-safe-preview-v2.py
var diskPreview []byte

//go:embed disk-deep-report-v1.py
var diskDeep []byte

//go:embed disk-safe-clean-v2.py
var diskClean []byte

type Property struct {
	Items     *Property `json:"items,omitempty"`
	MinItems  int       `json:"minItems,omitempty"`
	MaxItems  int       `json:"maxItems,omitempty"`
	Type      string    `json:"type"`
	Enum      []string  `json:"enum,omitempty"`
	Pattern   string    `json:"pattern,omitempty"`
	MinLength int       `json:"minLength,omitempty"`
	MaxLength int       `json:"maxLength,omitempty"`
	Minimum   *int      `json:"minimum,omitempty"`
	Maximum   *int      `json:"maximum,omitempty"`
}
type Schema struct {
	Type                 string              `json:"type"`
	AdditionalProperties bool                `json:"additionalProperties"`
	Properties           map[string]Property `json:"properties"`
	Required             []string            `json:"required,omitempty"`
}

// CatalogResponse is the object envelope returned by the operator catalog API.
type CatalogResponse struct {
	Items []Entry `json:"items"`
}

type Entry struct {
	ID             string   `json:"id"`
	Version        string   `json:"version"`
	SHA256         string   `json:"sha256"`
	ArgsSchema     Schema   `json:"args_schema"`
	DefaultTimeout int      `json:"default_timeout_seconds"`
	MaxTimeout     int      `json:"max_timeout_seconds"`
	OutputCap      int      `json:"output_cap_bytes"`
	Mode           string   `json:"mode"`
	RunsAs         string   `json:"runs_as"`
	AllowedOS      []string `json:"allowed_os"`
	Bytes          []byte   `json:"-"`
}

// Each additional embedded script is one registry entry. Hashes are constants,
// never computed from potentially changed bytes when accepting a job.
func diskSchema() Schema {
	return Schema{Type: "object", Required: []string{"scope", "policy_id", "policy_digest"}, Properties: map[string]Property{
		"scope":         {Type: "string", Enum: []string{"user", "root"}, MinLength: 4, MaxLength: 4},
		"policy_id":     {Type: "string", Pattern: "^[a-zA-Z0-9_-]{1,128}$", MinLength: 1, MaxLength: 128},
		"policy_digest": {Type: "string", Pattern: "^sha256:[a-f0-9]{64}$", MinLength: 71, MaxLength: 71}}}
}
func IsDiskSafe(id string) bool { return id == "disk-safe-preview-v2" || id == "disk-safe-clean-v2" }

func IsDisk(id string) bool { return IsDiskSafe(id) || id == "disk-deep-report-v1" || IsDiskAction(id) }
func deepSchema() Schema {
	s := diskSchema()
	delete(s.Properties, "scope")
	lo, hi := 1, 500
	s.Properties["max_items"] = Property{Type: "integer", Minimum: &lo, Maximum: &hi}
	s.Required = []string{"policy_id", "policy_digest", "max_items"}
	return s
}

var registry = []Entry{
	{"disk-approved-quarantine-v1", "1", "3448c9557b1d19c3abb27d59032f7f12daa4c2e9ecc06e6a76e56d26a4d1d610", actionSchema(), 900, 900, 64 << 10, "write", "agent-user", []string{"linux"}, diskQuarantine},
	{"disk-approved-delete-v1", "1", "be7e7f0151deae217d64cfa41b4a9b44e0aa332f07602e5ed9f6224e6f3649de", actionSchema(), 900, 900, 64 << 10, "write", "agent-user", []string{"linux"}, diskDelete},
	{"disk-quarantine-expire-v1", "1", "90e65df65e198486fe6364f63b0dfe9fcb87f6cab310603daacac8a0ebfd5c59", expirySchema(), 600, 600, 64 << 10, "write", "agent-user", []string{"linux"}, diskExpire},
	{"disk-quarantine-restore-v1", "1", "ad1df04d1f5c16a63cdea4c843ddb00a38ed250a8da76aeb135375a256f74a44", actionSchema(), 600, 600, 64 << 10, "write", "agent-user", []string{"linux"}, diskRestore},
	{"disk-deep-report-v1", "1", "7ef5121158c2c23573aee0aa828deff7c0994c8b7a88d4eabcfb3b1cfc64bfce", deepSchema(), 600, 600, 64 << 10, "read", "agent-user", []string{"linux"}, diskDeep},
	{"disk-safe-preview-v2", "2", "95ae88877bb530293c3fb75b774b1ed5c274bb3397bfefec04117b7bd15b94fe", diskSchema(), 120, 600, 64 << 10, "read", "agent-user", []string{"linux"}, diskPreview},
	{"disk-safe-clean-v2", "2", "049158e13d64e0a9de03bb3697fad76c36faa19481a98bf0fdb9037abf362f96", diskSchema(), 600, 600, 64 << 10, "write", "agent-user", []string{"linux"}, diskClean},
	{"bat-sweep-report-v1", "1", "0e00340abb9083cc2ab358857309c2f6c9237d7397581881b91a45868cd425a2", Schema{Type: "object", Required: []string{"hosts", "connector_tree_sha256"}, Properties: map[string]Property{"hosts": {Type: "array", MinItems: 1, MaxItems: 8, Items: &Property{Type: "string", Pattern: "^[a-z0-9-]{1,32}$", MinLength: 1, MaxLength: 32}}, "connector_tree_sha256": {Type: "string", Pattern: "^[a-f0-9]{64}$", MinLength: 64, MaxLength: 64}, "include_excerpts": {Type: "boolean"}}}, 600, 600, 64 << 10, "write", "agent-user", []string{"linux"}, batSweep},
	{"fleet-probe-v1", "1", "0c242784f162df0489571fa0ac901e0e583f54afa3d121d0b033e8dff2bad924", Schema{Type: "object", Properties: map[string]Property{}}, 15, 60, 64 << 10, "read", "agent-user", []string{"linux"}, probe},
}

func List() []Entry {
	// Deep copy protects the immutable allowlist from callers.
	raw, _ := json.Marshal(registry)
	var out []Entry
	_ = json.Unmarshal(raw, &out)
	return out
}
func Lookup(id string) (Entry, bool) {
	for i, e := range registry {
		if e.ID == id {
			out := List()[i]
			out.Bytes = bytes.Clone(e.Bytes)
			return out, true
		}
	}
	return Entry{}, false
}
func Digest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func (e Entry) AllowsOS(os string) bool {
	for _, v := range e.AllowedOS {
		if v == os {
			return true
		}
	}
	return false
}

// Validate returns canonical args, rejecting duplicate and unknown fields.
// This deliberately small closed schema supports bounded scalars and string arrays.
func (e Entry) Validate(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > 4096 || !utf8.Valid(raw) {
		return nil, errors.New("args must be a JSON object of at most 4096 bytes")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("args must be an object")
	}
	values := map[string]any{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, errors.New("invalid args")
		}
		key, ok := t.(string)
		if !ok {
			return nil, errors.New("invalid args")
		}
		if _, ok := values[key]; ok {
			return nil, errors.New("duplicate args field")
		}
		p, ok := e.ArgsSchema.Properties[key]
		if !ok {
			return nil, errors.New("unknown args field")
		}
		var v any
		if d.Decode(&v) != nil {
			return nil, errors.New("invalid args")
		}
		switch p.Type {
		case "string":
			s, ok := v.(string)
			if !ok || utf8.RuneCountInString(s) < p.MinLength || p.MaxLength <= 0 || utf8.RuneCountInString(s) > p.MaxLength {
				return nil, errors.New("args string outside bounds")
			}
			if len(p.Enum) > 0 {
				found := false
				for _, x := range p.Enum {
					found = found || s == x
				}
				if !found {
					return nil, errors.New("args enum mismatch")
				}
			}
			if p.Pattern != "" {
				match, err := regexp.MatchString(p.Pattern, s)
				if err != nil || !match {
					return nil, errors.New("args pattern mismatch")
				}
			}
		case "array":
			a, ok := v.([]any)
			if !ok || len(a) < p.MinItems || p.MaxItems <= 0 || len(a) > p.MaxItems || p.Items == nil || p.Items.Type != "string" {
				return nil, errors.New("args array outside bounds")
			}
			for _, item := range a {
				str, ok := item.(string)
				if !ok || len(str) < p.Items.MinLength || len(str) > p.Items.MaxLength {
					return nil, errors.New("args array item outside bounds")
				}
				match, err := regexp.MatchString(p.Items.Pattern, str)
				if err != nil || !match {
					return nil, errors.New("args array item pattern mismatch")
				}
			}
		case "integer":
			n, ok := v.(json.Number)
			if !ok {
				return nil, errors.New("args integer required")
			}
			i, err := n.Int64()
			if err != nil || p.Minimum == nil || p.Maximum == nil || i < int64(*p.Minimum) || i > int64(*p.Maximum) {
				return nil, errors.New("args integer outside bounds")
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				return nil, errors.New("args boolean required")
			}
		default:
			return nil, errors.New("unsupported args schema")
		}
		values[key] = v
	}
	if _, err = d.Token(); err != nil {
		return nil, errors.New("invalid args")
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing args JSON")
	}
	for _, key := range e.ArgsSchema.Required {
		if _, ok := values[key]; !ok {
			return nil, errors.New("required args missing")
		}
	}
	return json.Marshal(values)
}

type Spec struct {
	Policy json.RawMessage `json:"policy,omitempty"`
	// ExecutionMode records the catalog mode approved when the job was created.
	// Optional for legacy agent execution; disclosure must not infer it later.
	ExecutionMode string          `json:"execution_mode,omitempty"`
	Kind          string          `json:"kind"`
	ScriptID      string          `json:"script_id"`
	ScriptSHA256  string          `json:"script_sha256"`
	Args          json.RawMessage `json:"args"`
}

func Decode(raw []byte) (Spec, error) {
	var s Spec
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return s, errors.New("invalid script spec")
	}
	if d.Decode(new(any)) != io.EOF || s.Kind != Kind {
		return s, errors.New("invalid script spec")
	}
	return s, nil
}

var secrets = regexp.MustCompile(`(?i)(bearer\s+[^\s"']+|(?:"?(?:token|password|secret|api[_-]?key)"?)\s*[:=]\s*"?[^\s"']+|(?:sk-|gh[pousr]_|github_pat_)[a-z0-9_-]+|eyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+|[a-z0-9_+/=-]{32,})`)

func Redact(s string) string {
	return secrets.ReplaceAllString(strings.ToValidUTF8(s, "�"), "[REDACTED]")
}

// Preserve validated evidence digests while redacting all other output strings.
func RedactDiskJSON(raw []byte) string {
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if len(raw) > 256<<10 || decoder.Decode(&document) != nil {
		return ""
	}
	var clean func(any, string) any
	clean = func(v any, key string) any {
		switch value := v.(type) {
		case string:
			if key == "schema" && (value == "fleet-disk-clean/v1" || value == "disk-safe/v2" || value == "disk-action-result/v1") {
				return value
			}
			if (key == "policy_id" || key == "manifest_id" || key == "item_id" || key == "job_id" || key == "approval_id") && regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`).MatchString(value) && !regexp.MustCompile(`^(sk-|gh[pousr]_|github_pat_)`).MatchString(value) {
				return value
			}
			if (key == "policy_digest" || key == "config_digest") && len(value) == 71 && strings.HasPrefix(value, "sha256:") {
				valid := true
				for _, c := range value[7:] {
					if !strings.ContainsRune("0123456789abcdef", c) {
						valid = false
					}
				}
				if valid {
					return value
				}
			}
			return Redact(value)
		case map[string]any:
			for k, x := range value {
				if k == "record" {
					delete(value, k)
					continue
				}
				value[k] = clean(x, k)
			}
			return value
		case []any:
			for i, x := range value {
				value[i] = clean(x, "")
			}
			return value
		default:
			return value
		}
	}
	b, _ := json.Marshal(clean(document, ""))
	return string(b)
}
