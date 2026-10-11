//go:build !linux

package scriptcatalog

import (
	"context"
	"encoding/json"
	"errors"
)

func Run(context.Context, Entry, []byte, int) (Result, error) {
	return Result{}, errors.New("script catalog execution is unsupported on this OS")
}

func RunPolicy(ctx context.Context, e Entry, args []byte, timeout int, _ json.RawMessage) (Result, error) {
	return Run(ctx, e, args, timeout)
}
