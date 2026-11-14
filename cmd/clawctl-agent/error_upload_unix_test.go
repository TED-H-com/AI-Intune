//go:build !windows

package main

import (
	"context"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestErrorUploadSkipsFIFO(t *testing.T) {
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- u.upload(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		cancel()
		// Release a blocking FIFO open before failing, including on the old
		// implementation, so the regression leaves no goroutine behind.
		f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0600)
		if err != nil {
			t.Fatal(err)
		}
		<-done
		_ = f.Close()
		t.Fatal("non-regular source blocked the uploader")
	}
	if len(u.state.Cursors) != 0 {
		t.Fatal("non-regular source acquired a cursor")
	}
}
