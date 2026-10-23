package web

import (
	"context"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/channels"
	"github.com/teddashh/AI-Intune/internal/store"
	"time"
)

// RunSigninNotifications uses the existing channel providers and fixed-text audit.
func (s *Server) RunSigninNotifications(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.deliverSigninNotifications(ctx)
		}
	}
}
func (s *Server) deliverSigninNotifications(ctx context.Context) {
	id, e := s.store.SigninNotificationChannel()
	if e != nil || id == "" {
		return
	}
	configs, e := s.store.Channels()
	if e != nil {
		return
	}
	for _, c := range configs {
		if c.ID != id {
			continue
		}
		items, e := s.store.ClaimSigninNotifications()
		if e != nil {
			return
		}
		p := channels.New(c, s.secretProvider)
		for _, n := range items {
			s.sendSigninNotification(ctx, p, n)
		}
	}
}
func (s *Server) sendSigninNotification(ctx context.Context, p channels.Provider, n store.SigninNotification) {
	sendctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	text := fmt.Sprintf("%s: %s %s needs sign-in. %s/signins", n.DisplayName, n.CLI, n.Account, s.hubBase)
	e := p.Send(sendctx, channels.Message{Kind: "signin", Text: text})
	_ = s.store.RecordSigninNotificationResult(n.MachineID, p.Name(), e == nil)
}
