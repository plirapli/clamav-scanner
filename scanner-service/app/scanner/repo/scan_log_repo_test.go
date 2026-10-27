package repo

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"scanner-service/core/scanner/entities"
	"scanner-service/core/scanner/interfaces"
	"scanner-service/infra/sqlite"
)

func newLogRepo(t *testing.T) interfaces.ScanLogRepository {
	t.Helper()

	db, err := sqlite.Open(filepath.Join(t.TempDir(), "logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return NewScanLogRepo(db)
}

func TestScanLogListSort(t *testing.T) {
	repo := newLogRepo(t)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	seed := []struct {
		name    string
		verdict string
		size    int64
	}{
		{"b.exe", "QUARANTINE", 300},
		{"c.exe", "ALLOW", 100},
		{"a.exe", "BLOCK", 200},
	}
	for i, s := range seed {
		err := repo.Insert(ctx, entities.ScanLog{
			RequestID: "req",
			Filename:  s.name,
			SHA256:    s.name,
			Size:      s.size,
			Verdict:   s.verdict,
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		sortBy string
		desc   bool
		want   []string
	}{
		{"", false, []string{"a.exe", "c.exe", "b.exe"}},
		{"filename", false, []string{"a.exe", "b.exe", "c.exe"}},
		{"size", true, []string{"b.exe", "a.exe", "c.exe"}},
		{"verdict", true, []string{"a.exe", "b.exe", "c.exe"}},
		{"verdict", false, []string{"c.exe", "b.exe", "a.exe"}},
		{"bogus; DROP TABLE scan_logs", false, []string{"a.exe", "c.exe", "b.exe"}},
	}
	for _, tt := range tests {
		logs, total, err := repo.List(ctx, interfaces.ScanLogFilter{SortBy: tt.sortBy, SortDesc: tt.desc, Limit: 10})
		if err != nil {
			t.Fatalf("sort %q: %v", tt.sortBy, err)
		}
		if total != len(seed) {
			t.Fatalf("sort %q: total = %d, want %d", tt.sortBy, total, len(seed))
		}
		got := make([]string, len(logs))
		for i, log := range logs {
			got[i] = log.Filename
		}
		for i := range tt.want {
			if got[i] != tt.want[i] {
				t.Fatalf("sort %q desc=%v: got %v, want %v", tt.sortBy, tt.desc, got, tt.want)
			}
		}
	}
}

func TestScanLogSummary(t *testing.T) {
	repo := newLogRepo(t)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	seed := []struct {
		app, virus, verdict string
	}{
		{"app-a", "Eicar-Signature", "BLOCK"},
		{"app-a", "Eicar-Signature", "BLOCK"},
		{"app-b", "Win.Trojan.Agent", "BLOCK"},
		{"app-b", "", "QUARANTINE"},
	}
	for i, s := range seed {
		err := repo.Insert(ctx, entities.ScanLog{
			RequestID:   "req",
			Application: s.app,
			Filename:    "f",
			SHA256:      string(rune('a' + i)),
			VirusName:   s.virus,
			Verdict:     s.verdict,
			CreatedAt:   base.Add(time.Duration(i) * time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	summary, err := repo.Summary(ctx, interfaces.ScanLogFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 4 {
		t.Fatalf("total = %d, want 4", summary.Total)
	}
	if len(summary.VirusNames) != 2 || summary.VirusNames[0].Value != "Eicar-Signature" || summary.VirusNames[0].Count != 2 {
		t.Fatalf("virus names = %+v", summary.VirusNames)
	}
	if !summary.VirusNames[0].LastSeen.Equal(base.Add(time.Minute)) {
		t.Fatalf("last seen = %v, want %v", summary.VirusNames[0].LastSeen, base.Add(time.Minute))
	}
	if len(summary.Applications) != 2 || summary.Applications[0].Count != 2 || summary.Applications[1].Count != 2 {
		t.Fatalf("applications = %+v", summary.Applications)
	}

	filtered, err := repo.Summary(ctx, interfaces.ScanLogFilter{Application: "app-b"})
	if err != nil {
		t.Fatal(err)
	}
	if filtered.Total != 2 || len(filtered.VirusNames) != 1 || filtered.VirusNames[0].Value != "Win.Trojan.Agent" {
		t.Fatalf("filtered summary = %+v", filtered)
	}
}
