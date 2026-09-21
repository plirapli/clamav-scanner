package classifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"scanner-service/analysis/evidence"
)

func testEvidence() evidence.FileEvidence {
	return evidence.FileEvidence{
		File: evidence.FileInfo{Name: "sample.exe", Size: 4096, MIME: "application/octet-stream", SHA256: "abc"},
		StaticAnalysis: evidence.StaticAnalysis{
			Supported:        true,
			FileType:         "PE32+",
			MaxEntropy:       7.94,
			HasPackedSection: true,
		},
	}
}

func TestClassifySuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("authorization header = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content type = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tier":"fast","model":"jev-1.13.0","results":[{"label":"suspicious","confidence":0.91,"scores":{"benign":0.03,"suspicious":0.91},"model":"jev-1.13.0"}]}`))
	}))
	defer server.Close()

	client := NewClassifierDev(server.URL, "test-key", "fast", []string{"benign", "suspicious"}, false, time.Second)
	result, err := client.Classify(context.Background(), testEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if result.Label != "suspicious" || result.Confidence == nil || *result.Confidence != 0.91 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Model != "jev-1.13.0" || result.Scores["benign"] != 0.03 {
		t.Fatalf("unexpected metadata: %+v", result)
	}
}

func TestClassifyNullConfidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"label":"suspicious","confidence":null,"scores":null}]}`))
	}))
	defer server.Close()

	client := NewClassifierDev(server.URL, "", "fast", []string{"benign", "suspicious"}, false, time.Second)
	result, err := client.Classify(context.Background(), testEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != nil {
		t.Fatalf("expected null confidence, got %v", *result.Confidence)
	}
}

func TestClassifyRetriesOn429(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited","code":"rate_limit_minute"}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"label":"benign","confidence":0.9}]}`))
	}))
	defer server.Close()

	client := NewClassifierDev(server.URL, "", "fast", []string{"benign", "suspicious"}, false, time.Second)
	result, err := client.Classify(context.Background(), testEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if result.Label != "benign" {
		t.Fatalf("unexpected label: %s", result.Label)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 calls, got %d", got)
	}
}

func TestClassifyDoesNotRetry401(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid api key","code":"invalid_api_key"}`))
	}))
	defer server.Close()

	client := NewClassifierDev(server.URL, "bad-key", "fast", []string{"benign", "suspicious"}, false, time.Second)
	if _, err := client.Classify(context.Background(), testEvidence()); err == nil {
		t.Fatal("expected error")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 call, got %d", got)
	}
}
