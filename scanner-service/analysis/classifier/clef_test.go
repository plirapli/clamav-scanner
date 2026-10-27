package classifier

import (
	"context"
	"encoding/json"
	"errors"
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

func newTestClef(url, apiKey string) *Clef {
	return NewClef(url, "acct", apiKey, "clef", []string{"benign", "suspicious", "custom"}, false, time.Second)
}

func TestClassifySuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/accounts/acct/ai/run/@cf/cloudflare/clef" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("authorization header = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content type = %q", got)
		}

		var body requestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		question := body.Questions[verdictQuestion]
		if body.Model != "clef" || body.State == "" || question.Type != "choice" {
			t.Errorf("unexpected request: %+v", body)
		}
		if len(question.Criteria) != 3 || question.Criteria["custom"] != nil || question.Criteria["benign"] == nil {
			t.Errorf("unexpected criteria: %+v", question.Criteria)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"model":"clef","answers":{"verdict":{"type":"choice","choice":"suspicious","probabilities":{"benign":0.03,"suspicious":0.91,"custom":0.06},"confidence":0.7}},"usage":{"input_tokens":120,"output_tokens":0}}}`))
	}))
	defer server.Close()

	result, err := newTestClef(server.URL, "test-key").Classify(context.Background(), testEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if result.Label != "suspicious" || result.Confidence == nil || *result.Confidence != 0.91 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Model != "clef" || result.Scores["benign"] != 0.03 {
		t.Fatalf("unexpected metadata: %+v", result)
	}
}

func TestClassifyNoProbabilities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":{"answers":{"verdict":{"type":"choice","choice":"suspicious"}}}}`))
	}))
	defer server.Close()

	result, err := newTestClef(server.URL, "test-key").Classify(context.Background(), testEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != nil {
		t.Fatalf("expected null confidence, got %v", *result.Confidence)
	}
	if result.Model != "clef" {
		t.Fatalf("expected configured model fallback, got %q", result.Model)
	}
}

func TestClassifyRetriesOn429(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":3040,"message":"Capacity temporarily exceeded"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"result":{"answers":{"verdict":{"type":"choice","choice":"benign","probabilities":{"benign":0.9,"suspicious":0.1}}}}}`))
	}))
	defer server.Close()

	result, err := newTestClef(server.URL, "test-key").Classify(context.Background(), testEvidence())
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
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
	}))
	defer server.Close()

	_, err := newTestClef(server.URL, "bad-key").Classify(context.Background(), testEvidence())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "10000" || apiErr.Message != "Authentication error" {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 call, got %d", got)
	}
}

func TestClassifyRequiresCredentials(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer server.Close()

	if _, err := newTestClef(server.URL, "").Classify(context.Background(), testEvidence()); !errors.Is(err, ErrMissingCredentials) {
		t.Fatalf("expected ErrMissingCredentials, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected no calls, got %d", got)
	}
}
