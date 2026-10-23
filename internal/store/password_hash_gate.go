package store

import (
	"context"
	"sync"
	"time"
)

// passwordHashes bounds Argon2 memory use across all stores in this process.
var passwordHashes = struct {
	sync.Mutex
	active, limit int
	changed       chan struct{}
}{limit: 2, changed: make(chan struct{})}

// SetMaxConcurrentPasswordHashes sets the process-wide Argon2 limit.
// Non-positive values restore the default of two. Active hashes finish normally.
func SetMaxConcurrentPasswordHashes(n int) {
	if n <= 0 {
		n = 2
	}
	passwordHashes.Lock()
	passwordHashes.limit = n
	close(passwordHashes.changed)
	passwordHashes.changed = make(chan struct{})
	passwordHashes.Unlock()
}

func acquirePasswordHash(ctx context.Context) (func(), error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		passwordHashes.Lock()
		if passwordHashes.active < passwordHashes.limit {
			passwordHashes.active++
			passwordHashes.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					passwordHashes.Lock()
					passwordHashes.active--
					close(passwordHashes.changed)
					passwordHashes.changed = make(chan struct{})
					passwordHashes.Unlock()
				})
			}, nil
		}
		changed := passwordHashes.changed
		passwordHashes.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}
