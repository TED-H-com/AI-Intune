package operator

import (
	"context"
	"errors"

	"github.com/teddashh/AI-Intune/internal/channels"
	"github.com/teddashh/AI-Intune/internal/secrets"
	"github.com/teddashh/AI-Intune/internal/store"
)

// TestChannel records intent before delivery and a fixed-text outcome afterward.
// A pending intent after a crash means delivery is uncertain; never auto-retry it.
func (s *Service) TestChannel(ctx context.Context, c channels.Config, resolver secrets.SecretProvider, actor Actor) error {
	a := store.AuditEntry{Action: store.AuditChannelTest, Subject: c.ID, Detail: "test requested"}
	ApplyActor(&a, actor)
	if e := s.store.RecordAudit(a); e != nil {
		return errors.New("channel audit unavailable")
	}
	e := channels.New(c, resolver).Send(ctx, channels.Message{Kind: "test", Text: "Hub channel test message"})
	a.OK = e == nil
	a.Detail = "test completed"
	if auditErr := s.store.RecordAudit(a); auditErr != nil {
		return errors.New("channel audit unavailable")
	}
	if e != nil {
		return errors.New("channel test delivery failed")
	}
	return nil
}
