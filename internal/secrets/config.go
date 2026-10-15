package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
)

// Config is shared by Hub status and agent pull consumers. No secret values.
type Config struct {
	References []Reference `json:"references"`
	BWS        *BWSConfig  `json:"bws"`
}

func LoadConfig(path string, extra []Reference) (*Registry, error) {
	c := Config{}
	if path != "" {
		f, e := os.Open(path)
		if e != nil {
			return nil, errors.New("secrets configuration unavailable")
		}
		defer f.Close()
		d := json.NewDecoder(io.LimitReader(f, 1<<20))
		d.DisallowUnknownFields()
		if d.Decode(&c) != nil {
			return nil, errors.New("invalid secrets configuration")
		}
		var trailing any
		if d.Decode(&trailing) != io.EOF {
			return nil, errors.New("invalid secrets configuration")
		}
	}
	r := New(append(extra, c.References...))
	if c.BWS != nil {
		p, e := NewBWS(*c.BWS)
		if e != nil {
			return nil, e
		}
		r.Register("bws", p)
	}
	return r, nil
}

// BWSStatus returns only closed-vocabulary diagnostics, without a network call.
func (r *Registry) BWSStatus() BackendStatus {
	if p, ok := r.providers["bws"].(*BWS); ok {
		return p.Status()
	}
	return BackendStatus{LastErrorClass: "not_configured"}
}
func (r *Registry) TestFetch(ctx context.Context, ref string) (Secret, error) {
	u, e := url.Parse(ref)
	if e != nil {
		return Secret{}, errors.New("invalid secret reference")
	}
	if p, ok := r.providers[u.Scheme].(interface {
		TestFetch(context.Context, string) (Secret, error)
	}); ok {
		return p.TestFetch(ctx, ref)
	}
	return r.Get(ctx, ref)
}
