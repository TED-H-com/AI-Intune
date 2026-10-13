package main

import (
	"fmt"
	"strconv"

	"github.com/teddashh/AI-Intune/internal/store"
)

func parseUsageToolCallLimit(raw string) (int, error) {
	if raw == "" {
		return store.DefaultUsageToolCallLimit, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("usage-tool-call-limit must be a positive integer")
	}
	return limit, nil
}
