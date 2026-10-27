package repo

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"scanner-service/analysis/classifier"
	"scanner-service/analysis/evidence"
	"scanner-service/core/scanner/entities"
	"scanner-service/core/scanner/interfaces"
	"scanner-service/infra/sqlite"
)

func newCacheRepo(t *testing.T) interfaces.ScanCacheRepository {
	t.Helper()

	db, err := sqlite.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return NewScanCacheRepo(db)
}

func sampleEntry(sha string) entities.CachedScan {
	confidence := 0.91
	return entities.CachedScan{
		SHA256:          sha,
		Size:            4096,
		AnalyzerVersion: 1,
		Analysis: evidence.StaticAnalysis{
			Supported:  true,
			Kind:       "pe",
			MaxEntropy: 7.94,
		},
		Classifier: &classifier.Result{
			Label:      "suspicious",
			Confidence: &confidence,
			Scores:     map[string]float64{"benign": 0.03, "suspicious": 0.91},
			Model:      "clef",
		},
		FirstSeenAt: time.Now(),
	}
}

func TestScanCacheStoreAndLookup(t *testing.T) {
	repo := newCacheRepo(t)
	ctx := context.Background()

	entry := sampleEntry("abc123")
	if err := repo.Store(ctx, entry); err != nil {
		t.Fatal(err)
	}

	got, ok, err := repo.Lookup(ctx, "abc123", 4096, time.Hour, time.Hour, 1)
	if err != nil || !ok {
		t.Fatalf("lookup failed: ok=%v err=%v", ok, err)
	}
	if got.Analysis.Kind != "pe" || got.Analysis.MaxEntropy != 7.94 {
		t.Fatalf("analysis mismatch: %+v", got.Analysis)
	}
	if got.Classifier == nil || got.Classifier.Label != "suspicious" || *got.Classifier.Confidence != 0.91 {
		t.Fatalf("classifier mismatch: %+v", got.Classifier)
	}
	if got.Classifier.Scores["suspicious"] != 0.91 {
		t.Fatalf("scores mismatch: %+v", got.Classifier.Scores)
	}

	if _, ok, _ := repo.Lookup(ctx, "abc123", 999, time.Hour, time.Hour, 1); ok {
		t.Fatal("size mismatch must miss")
	}
	if _, ok, _ := repo.Lookup(ctx, "abc123", 4096, time.Hour, time.Hour, 2); ok {
		t.Fatal("analyzer version mismatch must miss")
	}
}

func TestScanCacheHitCounter(t *testing.T) {
	repo := newCacheRepo(t)
	ctx := context.Background()

	if err := repo.Store(ctx, sampleEntry("counted")); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if _, ok, err := repo.Lookup(ctx, "counted", 4096, time.Hour, time.Hour, 1); err != nil || !ok {
			t.Fatalf("lookup %d failed: ok=%v err=%v", i, ok, err)
		}
	}

	got, _, _ := repo.Lookup(ctx, "counted", 4096, time.Hour, time.Hour, 1)
	// Lookup returns the counter value read before this call increments it, so
	// three prior hits are visible here.
	if got.Hits != 3 {
		t.Fatalf("hits = %d, want 3", got.Hits)
	}
}

func TestScanCacheTTLExpiry(t *testing.T) {
	repo := newCacheRepo(t)
	ctx := context.Background()

	entry := sampleEntry("stale")
	entry.FirstSeenAt = time.Now().Add(-2 * time.Hour)
	if err := repo.Store(ctx, entry); err != nil {
		t.Fatal(err)
	}
	// Store uses time.Now() for last_seen_at; force an old timestamp directly.
	db := repo.(*scanCacheRepo).db
	if _, err := db.Exec("UPDATE scan_cache SET last_seen_at = ?", time.Now().Add(-2*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	if _, ok, _ := repo.Lookup(ctx, "stale", 4096, time.Hour, time.Hour, 1); ok {
		t.Fatal("expired entry must miss")
	}
}

func TestScanCacheClassifierErrorCooldown(t *testing.T) {
	repo := newCacheRepo(t)
	ctx := context.Background()

	entry := sampleEntry("errored")
	entry.Classifier = nil
	entry.ClassifierError = "classifier timeout"
	if err := repo.Store(ctx, entry); err != nil {
		t.Fatal(err)
	}

	db := repo.(*scanCacheRepo).db
	if _, err := db.Exec("UPDATE scan_cache SET last_seen_at = ?", time.Now().Add(-time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	if _, ok, _ := repo.Lookup(ctx, "errored", 4096, time.Hour*24, 15*time.Minute, 1); ok {
		t.Fatal("stale classifier error must miss so it can be retried")
	}
	if _, ok, _ := repo.Lookup(ctx, "errored", 4096, time.Hour*24, time.Hour*2, 1); !ok {
		t.Fatal("fresh enough classifier error must hit")
	}
}

func TestScanCachePrune(t *testing.T) {
	repo := newCacheRepo(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		entry := sampleEntry(string(rune('a' + i)))
		entry.FirstSeenAt = time.Now().Add(time.Duration(i) * time.Minute)
		if err := repo.Store(ctx, entry); err != nil {
			t.Fatal(err)
		}
	}

	db := repo.(*scanCacheRepo).db
	for i := 0; i < 5; i++ {
		ts := time.Now().Add(time.Duration(i) * time.Minute).Format(time.RFC3339Nano)
		if _, err := db.Exec("UPDATE scan_cache SET last_seen_at = ? WHERE sha256 = ?", ts, string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}

	if err := repo.Prune(ctx, 3, 0); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM scan_cache").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("count = %d, want 3", count)
	}

	// The two oldest entries must be gone.
	if _, ok, _ := repo.Lookup(ctx, "a", 4096, 0, 0, 1); ok {
		t.Fatal("oldest entry should have been pruned")
	}
}
