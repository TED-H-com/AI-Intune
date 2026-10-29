package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/teddashh/AI-Intune/internal/errorissues"
)

// startErrorIssues returns without starting any job when the flag is off.
func (h *hub) startErrorIssues(ctx context.Context) error {
	c, err := errorissues.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	if !c.Enabled {
		return nil
	}
	client := &errorissues.Client{}
	if !c.DryRun {
		client.Token, err = errorissues.ReadToken(c.TokenFile, errorissues.OwnerRootOrSelf)
		if err != nil {
			return err
		}
	}
	if err = h.store.InitIssueFiler(ctx); err != nil {
		return err
	}
	f := &errorissues.Filer{Config: c, Store: h.store, GitHub: client}
	go func() {
		ticker := time.NewTicker(c.Interval)
		defer ticker.Stop()
		for {
			if err := f.Run(ctx, time.Now()); err != nil && ctx.Err() == nil {
				log.Print("error issues: run failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}
