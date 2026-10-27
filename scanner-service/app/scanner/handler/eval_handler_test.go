package handler

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v2"

	"scanner-service/analysis/policy"
)

func newEvalApp(t *testing.T) (*fiber.App, string) {
	t.Helper()
	dir := t.TempDir()
	run := filepath.Join(dir, "run-a")
	if err := os.MkdirAll(run, 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `{"path":"malware/x.exe","expected":"malware","sha256":"aa","size":10,"clamav":{"detected":true,"signature":"Win.Test"},"analysis":{"supported":false}}
{"path":"benign/y.exe","expected":"benign","sha256":"bb","size":20,"clamav":{"detected":false},"analysis":{"supported":true,"kind":"pe","signer_subject":"Example","signature_status":"valid"},"classifier":{"label":"benign","confidence":0.9,"scores":{"benign":0.9}}}
not json
`
	if err := os.WriteFile(filepath.Join(run, "raw.jsonl"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run, "summary.json"), []byte(`{"samples":2,"models":["clef"],"evaluations":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A directory without raw.jsonl is not a run.
	if err := os.MkdirAll(filepath.Join(dir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}

	app := fiber.New()
	h := NewEvalHandler(dir, policy.Config{BlockConfidence: 0.95, FailMode: policy.Quarantine, AllowUnsupported: true})
	app.Get("/runs", h.Runs)
	app.Get("/runs/:name", h.Run)
	return app, dir
}

func getJSON(t *testing.T, app *fiber.App, path string, out any) int {
	t.Helper()
	response, err := app.Test(httptest.NewRequest("GET", path, nil), 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode
}

func TestEvalRunsListsOnlyRuns(t *testing.T) {
	app, _ := newEvalApp(t)
	var body struct {
		Data []evalRun `json:"data"`
	}
	if code := getJSON(t, app, "/runs", &body); code != 200 {
		t.Fatalf("status %d", code)
	}
	if len(body.Data) != 1 || body.Data[0].Name != "run-a" || body.Data[0].Samples != 2 || !body.Data[0].HasSummary {
		t.Fatalf("runs = %+v", body.Data)
	}
}

func TestEvalRunComputesVerdicts(t *testing.T) {
	app, _ := newEvalApp(t)
	var body struct {
		Data struct {
			Summary json.RawMessage `json:"summary"`
			Samples []evalSample    `json:"samples"`
		} `json:"data"`
	}
	if code := getJSON(t, app, "/runs/run-a", &body); code != 200 {
		t.Fatalf("status %d", code)
	}
	if len(body.Data.Samples) != 2 || len(body.Data.Summary) == 0 {
		t.Fatalf("data = %+v", body.Data)
	}
	if got := body.Data.Samples[0]; got.Verdict != policy.Block || got.ClamAVSignature != "Win.Test" {
		t.Fatalf("malware sample = %+v", got)
	}
	if got := body.Data.Samples[1]; got.Verdict != policy.Allow || got.Signer != "Example" || got.Label != "benign" {
		t.Fatalf("benign sample = %+v", got)
	}
}

func TestEvalRunRejectsUnknownAndTraversal(t *testing.T) {
	app, _ := newEvalApp(t)
	for _, path := range []string{"/runs/missing", "/runs/..", "/runs/%2e%2e", "/runs/..%2fetc"} {
		var body map[string]any
		if code := getJSON(t, app, path, &body); code != 404 {
			t.Fatalf("%s: status %d", path, code)
		}
	}
}
