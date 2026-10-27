package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"scanner-service/analysis/analyzer"
	"scanner-service/analysis/classifier"
	"scanner-service/analysis/evidence"
	"scanner-service/analysis/policy"
	"scanner-service/app/scanner/repo"
	"scanner-service/core/scanner/entities"
	"scanner-service/infra/clamav"
	"scanner-service/infra/sqlite"
)

type fakeUsecase struct{ detected bool }

func (u fakeUsecase) Scan(reader io.Reader) error {
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return err
	}
	if u.detected {
		return &clamav.VirusFoundError{Name: "Test.Virus"}
	}
	return nil
}

type fakePublisher struct{ entries []entities.ScanLog }

func (f *fakePublisher) Publish(_ context.Context, entry entities.ScanLog) error {
	f.entries = append(f.entries, entry)
	return nil
}

type fakeEngine struct{}

func (fakeEngine) Version() (int64, error) { return 1, nil }

type countingClassifier struct{ calls int32 }

func (c *countingClassifier) Classify(context.Context, evidence.FileEvidence) (classifier.Result, error) {
	atomic.AddInt32(&c.calls, 1)
	confidence := 0.42
	return classifier.Result{Label: "suspicious", Confidence: &confidence, Model: "fake-model"}, nil
}

type stubAnalyzer struct{}

func (stubAnalyzer) Name() string { return "text" }

func (stubAnalyzer) Supports(analyzer.Input) bool { return true }

func (stubAnalyzer) Analyze(analyzer.Input) (evidence.StaticAnalysis, error) {
	return evidence.StaticAnalysis{
		Supported: true,
		Kind:      "text",
		Generic:   evidence.GenericEvidence{MagicType: "text"},
	}, nil
}

type parsedScan struct {
	Data struct {
		Files []struct {
			Cached  bool   `json:"cached"`
			Verdict string `json:"verdict"`
		} `json:"files"`
	} `json:"data"`
}

func newTestHandler(t *testing.T, usecase fakeUsecase, fileClassifier classifier.Classifier) (*fiber.App, *fakePublisher) {
	t.Helper()

	db, err := sqlite.Open(filepath.Join(t.TempDir(), "handler.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	publisher := &fakePublisher{}
	handler := NewScannerHandler(ScannerHandlerDeps{
		Usecase:    usecase,
		ScanLog:    publisher,
		Engine:     fakeEngine{},
		AppName:    "test",
		Analyzer:   analyzer.NewRegistry(stubAnalyzer{}),
		Classifier: fileClassifier,
		Policy: policy.Config{
			BlockConfidence:     0.95,
			FailMode:            policy.Quarantine,
			AllowUnsupported:    true,
			GenericRulesEnabled: true,
		},
		Cache:              repo.NewScanCacheRepo(db),
		CacheTTL:           time.Hour,
		CacheErrorTTL:      time.Minute,
		CacheMaxEntries:    100,
		AnalyzerVersion:    analyzer.Version,
		MaxFilesPerRequest: 5,
	})

	app := fiber.New()
	app.Post("/scan", handler.Scan)

	return app, publisher
}

func scanOnce(t *testing.T, app *fiber.App, name string, data []byte) parsedScan {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("files", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest("POST", "/scan", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())

	response, err := app.Test(request, 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	var parsed parsedScan
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Data.Files) != 1 {
		t.Fatalf("expected 1 file result, got %+v", parsed)
	}

	return parsed
}

func TestScanCacheSkipsClassifierOnRepeat(t *testing.T) {
	fileClassifier := &countingClassifier{}
	app, _ := newTestHandler(t, fakeUsecase{}, fileClassifier)

	payload := []byte("identical bytes are scanned twice")
	first := scanOnce(t, app, "note.txt", payload)
	second := scanOnce(t, app, "note.txt", payload)

	if first.Data.Files[0].Cached {
		t.Fatal("first scan must not be served from cache")
	}
	if !second.Data.Files[0].Cached {
		t.Fatal("second scan must be served from cache")
	}
	if calls := atomic.LoadInt32(&fileClassifier.calls); calls != 1 {
		t.Fatalf("classifier calls = %d, want 1", calls)
	}
	if first.Data.Files[0].Verdict != second.Data.Files[0].Verdict {
		t.Fatalf("verdict changed between scans: %q vs %q", first.Data.Files[0].Verdict, second.Data.Files[0].Verdict)
	}
}

func TestScanCacheBypassedWhenClamAVDetects(t *testing.T) {
	fileClassifier := &countingClassifier{}
	app, publisher := newTestHandler(t, fakeUsecase{detected: true}, fileClassifier)

	payload := []byte("infected payload")
	scanOnce(t, app, "bad.bin", payload)
	scanOnce(t, app, "bad.bin", payload)

	if calls := atomic.LoadInt32(&fileClassifier.calls); calls != 0 {
		t.Fatalf("classifier must not run for ClamAV detections, calls = %d", calls)
	}
	if len(publisher.entries) != 2 {
		t.Fatalf("expected 2 published entries, got %d", len(publisher.entries))
	}
	for _, entry := range publisher.entries {
		if entry.Cached {
			t.Fatal("ClamAV detections must never be marked cached")
		}
	}
}
