package operator

import (
	"context"
	"errors"

	"github.com/teddashh/AI-Intune/internal/secrets"
	"github.com/teddashh/AI-Intune/internal/store"
)

// TestSecret records intent before resolution and only a fixed-text outcome.
// The web adapter selects ref from the configured inventory before calling.
func (s *Service) TestSecret(ctx context.Context, ref secrets.Reference, resolver secrets.SecretProvider, actor Actor) (string, error) {
	a := store.AuditEntry{Action: store.AuditSecretTest, Subject: ref.Ref, Detail: "test requested"}
	ApplyActor(&a, actor)
	if s.store.RecordAudit(a) != nil {
		return "", errors.New("secret audit unavailable")
	}
	var err error
	if p, ok := resolver.(interface {
		TestFetch(context.Context, string) (secrets.Secret, error)
	}); ok {
		_, err = p.TestFetch(ctx, ref.Ref)
	} else {
		_, err = resolver.Get(ctx, ref.Ref)
	}
	status := "present"
	if errors.Is(err, secrets.ErrMissing) {
		status = "missing"
	} else if err != nil {
		status = "error"
	}
	a.OK = err == nil
	a.Detail = "test completed: " + status
	if s.store.RecordAudit(a) != nil {
		return "", errors.New("secret audit unavailable")
	}
	return status, nil
}
