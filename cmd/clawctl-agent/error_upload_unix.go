//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

func errorFileIdentity(_ *os.File, info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", os.ErrInvalid
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), nil
}
