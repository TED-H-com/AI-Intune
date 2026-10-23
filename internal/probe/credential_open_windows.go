//go:build windows

package probe

import (
	"errors"
	"os"
)

// These POSIX fleet credentials cannot pass the ownership contract on Windows.
// Fail closed without opening a path that might be a reparse point or pipe.
func openPrivateCredential(string) (*os.File, error) {
	return nil, errors.New("POSIX private credential inspection unsupported on Windows")
}
func credentialBlockingRead(*os.File) error { return nil }
