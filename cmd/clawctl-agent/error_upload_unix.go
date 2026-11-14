//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

func openErrorUploadFile(path string) (*os.File, error) {
	// Opening a FIFO for reading otherwise waits for a writer before the
	// caller can check that the source is regular or observe cancellation.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func errorFileIdentity(_ *os.File, info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", os.ErrInvalid
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), nil
}
