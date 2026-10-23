package main

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/probe"
	"github.com/teddashh/AI-Intune/internal/signin"
)

var agentSignins atomic.Pointer[signin.Runner]

func startSignins(ctx context.Context, cfg config) {
	home, e := os.UserHomeDir()
	if e != nil {
		return
	}
	runner := signin.NewRunner(home, nil, func(u model.SigninUpdate) {
		sendctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		// Sanitized fields only, never the PTY stream or submitted code.
		_ = postJSON(sendctx, cfg.HubURL+"/v1/agent/signins", cfg.AgentToken, u, nil)
	}, func(ctx context.Context) []model.AuthHealth { return probe.AuthHealth(ctx, home, time.Now().UTC()) })
	agentSignins.Store(runner)
	go func() { <-ctx.Done(); runner.Shutdown() }()
}
func handleSigninCommand(ctx context.Context, c model.SigninCommand) {
	if runner := agentSignins.Load(); runner != nil {
		runner.Handle(ctx, c)
	}
}
