//go:build !linux

package signin

import (
	"context"
	"errors"
	"github.com/teddashh/AI-Intune/internal/model"
	"regexp"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

func Launch(context.Context, model.SigninCommand, string) (Process, error) {
	return nil, errors.New("Hub sign-in requires Linux")
}
