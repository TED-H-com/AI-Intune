//go:build !race

package store

import "time"

const prunePerformanceLimit = 5 * time.Second
