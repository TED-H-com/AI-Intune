//go:build race

package store

// TestCredRefreshHistoryMatchesReference runs on one goroutine, and the race
// detector instruments every memory access of the pure Go SQLite VM. With
// -race the test checks the first rounds of its seeded sequence; without it,
// all of them. A statement that skips the first subject of a machine first
// differs from the reference in round 23.
const credRefreshHistoryRounds = 30
