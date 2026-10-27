package interfaces

import (
	"context"
	"time"

	"scanner-service/core/scanner/entities"
)

type ScanCacheRepository interface {
	// Lookup returns a cached entry for sha256/size when it is not older than
	// maxAge. Entries whose classifier error is older than errorMaxAge are
	// treated as misses so transient failures are retried.
	Lookup(ctx context.Context, sha256 string, size int64, maxAge time.Duration, errorMaxAge time.Duration, analyzerVersion int) (entities.CachedScan, bool, error)

	Store(ctx context.Context, entry entities.CachedScan) error

	// Prune removes expired entries and, when maxEntries > 0, the oldest
	// entries beyond that limit.
	Prune(ctx context.Context, maxEntries int, maxAge time.Duration) error
}
