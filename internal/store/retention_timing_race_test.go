//go:build race

package store

import "time"

// The pure Go SQLite VM is heavily instrumented by the race detector.
const prunePerformanceLimit = 60 * time.Second
