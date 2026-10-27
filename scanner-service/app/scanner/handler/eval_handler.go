package handler

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"scanner-service/analysis/classifier"
	"scanner-service/analysis/evidence"
	"scanner-service/analysis/policy"
)

const maxEvalLine = 4 << 20

// EvalHandler serves the read-only results written by `cmd/eval collect` and
// `cmd/eval analyze` (one directory per run under ResultsDir).
type EvalHandler struct {
	resultsDir string
	policy     policy.Config
}

func NewEvalHandler(resultsDir string, policyConfig policy.Config) EvalHandler {
	return EvalHandler{resultsDir: resultsDir, policy: policyConfig}
}

type evalRun struct {
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	Samples    int       `json:"samples"`
	Models     []string  `json:"models,omitempty"`
	HasSummary bool      `json:"has_summary"`
}

// evalRecord mirrors the fields of cmd/eval's raw.jsonl that the dashboard uses.
type evalRecord struct {
	Path     string   `json:"path"`
	Expected string   `json:"expected"`
	Tags     []string `json:"tags"`
	Error    string   `json:"error"`
	SHA256   string   `json:"sha256"`
	Size     int64    `json:"size"`
	ClamAV   struct {
		Detected  bool   `json:"detected"`
		Signature string `json:"signature"`
		Error     string `json:"error"`
	} `json:"clamav"`
	Analysis        evidence.StaticAnalysis `json:"analysis"`
	Classifier      *classifier.Result      `json:"classifier"`
	ClassifierError string                  `json:"classifier_error"`
	DurationMS      struct {
		Total int64 `json:"total"`
	} `json:"duration_ms"`
}

type evalSample struct {
	Path            string             `json:"path"`
	Expected        string             `json:"expected"`
	Tags            []string           `json:"tags,omitempty"`
	SHA256          string             `json:"sha256,omitempty"`
	Size            int64              `json:"size"`
	Error           string             `json:"error,omitempty"`
	ClamAVDetected  bool               `json:"clamav_detected"`
	ClamAVSignature string             `json:"clamav_signature,omitempty"`
	Kind            string             `json:"kind,omitempty"`
	Signer          string             `json:"signer,omitempty"`
	SignatureStatus string             `json:"signature_status,omitempty"`
	Label           string             `json:"label,omitempty"`
	Confidence      *float64           `json:"confidence,omitempty"`
	Scores          map[string]float64 `json:"scores,omitempty"`
	ClassifierError string             `json:"classifier_error,omitempty"`
	Verdict         policy.Verdict     `json:"verdict,omitempty"`
	Reasons         []string           `json:"reasons,omitempty"`
	DurationMS      int64              `json:"duration_ms"`
}

type evalPolicy struct {
	BlockConfidence      float64 `json:"block_confidence"`
	SuspiciousImportsMin int     `json:"suspicious_imports_min"`
}

// Runs lists result directories, newest first.
func (h EvalHandler) Runs(c *fiber.Ctx) error {
	entries, err := os.ReadDir(h.resultsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return writeSuccess(c, fiber.StatusOK, "eval runs loaded", []evalRun{})
	}
	if err != nil {
		return writeError(c, fiber.StatusInternalServerError, "failed to read eval results", nil)
	}

	runs := []evalRun{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := os.Stat(filepath.Join(h.resultsDir, entry.Name(), "raw.jsonl"))
		if err != nil {
			continue
		}
		run := evalRun{Name: entry.Name(), CreatedAt: info.ModTime()}
		if summary, err := h.readSummary(entry.Name()); err == nil {
			run.HasSummary = true
			run.Samples = summary.Samples
			run.Models = summary.Models
		}
		runs = append(runs, run)
	}

	sort.Slice(runs, func(i, j int) bool { return runs[i].CreatedAt.After(runs[j].CreatedAt) })
	return writeSuccess(c, fiber.StatusOK, "eval runs loaded", runs)
}

// Run returns one run's summary.json (as written by cmd/eval analyze) plus every
// sample with the verdict the scanner's current policy would give it.
func (h EvalHandler) Run(c *fiber.Ctx) error {
	name := c.Params("name")
	dir, ok := h.runDir(name)
	if !ok {
		return writeError(c, fiber.StatusNotFound, "eval run not found", nil)
	}

	file, err := os.Open(filepath.Join(dir, "raw.jsonl"))
	if err != nil {
		return writeError(c, fiber.StatusNotFound, "eval run not found", nil)
	}
	defer file.Close()
	info, _ := file.Stat()

	samples := []evalSample{}
	lines := bufio.NewScanner(file)
	lines.Buffer(make([]byte, 64<<10), maxEvalLine)
	for lines.Scan() {
		var record evalRecord
		if err := json.Unmarshal(lines.Bytes(), &record); err != nil {
			continue
		}
		samples = append(samples, h.sample(record))
	}
	if err := lines.Err(); err != nil {
		return writeError(c, fiber.StatusInternalServerError, "failed to read eval run", nil)
	}

	var summary json.RawMessage
	if raw, err := os.ReadFile(filepath.Join(dir, "summary.json")); err == nil && json.Valid(raw) {
		summary = raw
	}

	return writeSuccess(c, fiber.StatusOK, "eval run loaded", fiber.Map{
		"name":       name,
		"created_at": info.ModTime(),
		"summary":    summary,
		"policy":     evalPolicy{BlockConfidence: h.policy.BlockConfidence, SuspiciousImportsMin: h.policy.SuspiciousImportsMin},
		"samples":    samples,
	})
}

func (h EvalHandler) sample(record evalRecord) evalSample {
	sample := evalSample{
		Path:            record.Path,
		Expected:        record.Expected,
		Tags:            record.Tags,
		SHA256:          record.SHA256,
		Size:            record.Size,
		Error:           record.Error,
		ClamAVDetected:  record.ClamAV.Detected,
		ClamAVSignature: record.ClamAV.Signature,
		Kind:            record.Analysis.Kind,
		Signer:          record.Analysis.SignerSubject,
		SignatureStatus: record.Analysis.SignatureStatus,
		ClassifierError: record.ClassifierError,
		DurationMS:      record.DurationMS.Total,
	}
	if record.Classifier != nil {
		sample.Label = record.Classifier.Label
		sample.Confidence = record.Classifier.Confidence
		sample.Scores = record.Classifier.Scores
	}
	if record.Error != "" {
		return sample
	}

	decision := policy.Decide(policy.Input{
		ClamAVDetected:  record.ClamAV.Detected,
		ClamAVSignature: record.ClamAV.Signature,
		ClamAVError:     record.ClamAV.Error,
		Analysis:        record.Analysis,
		Classifier:      record.Classifier,
		ClassifierError: record.ClassifierError,
	}, h.policy)
	sample.Verdict = decision.Verdict
	sample.Reasons = decision.Reasons
	return sample
}

type evalSummaryHeader struct {
	Samples int      `json:"samples"`
	Models  []string `json:"models"`
}

func (h EvalHandler) readSummary(name string) (evalSummaryHeader, error) {
	var summary evalSummaryHeader
	raw, err := os.ReadFile(filepath.Join(h.resultsDir, name, "summary.json"))
	if err != nil {
		return summary, err
	}
	return summary, json.Unmarshal(raw, &summary)
}

// runDir resolves a run name to its directory, rejecting anything that is not
// a plain directory name inside resultsDir.
func (h EvalHandler) runDir(name string) (string, bool) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) || filepath.Base(name) != name {
		return "", false
	}
	dir := filepath.Join(h.resultsDir, name)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return dir, true
}
