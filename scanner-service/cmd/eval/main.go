// Command eval runs the scan pipeline over a local corpus.
//
//	collect  run ClamAV + analyzers + classifier once per sample and write raw.jsonl
//	analyze  replay the deterministic policy over threshold grids and write
//	         summary.json + report.md (no classifier calls)
//	fetch-malware  add recent MalwareBazaar samples that the local ClamAV misses
//	fetch-benign   download the benign samples listed in eval/benign-sources.tsv
//
// Run from scanner-service/ so config/.env is picked up.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"scanner-service/analysis/analyzer"
	"scanner-service/analysis/classifier"
	"scanner-service/analysis/evidence"
	"scanner-service/analysis/policy"
	"scanner-service/config"
	"scanner-service/core/scanner/interfaces"
	"scanner-service/infra/clamav"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "collect":
		err = runCollect(os.Args[2:])
	case "analyze":
		err = runAnalyze(os.Args[2:])
	case "fetch-malware":
		err = runFetchMalware(os.Args[2:])
	case "fetch-benign":
		err = runFetchBenign(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  go run ./cmd/eval collect [flags]
  go run ./cmd/eval analyze [flags]
  go run ./cmd/eval fetch-malware [flags]
  go run ./cmd/eval fetch-benign [flags]

collect flags:
  -manifest  path to manifest.json   (default ../eval/manifest.json)
  -corpus    directory with samples  (default ../eval/corpus)
  -out       output directory        (default ../eval/results/<timestamp>)
  -limit     max samples, 0 = all
  -no-classifier  skip Clef calls

analyze flags:
  -in              results directory from collect (required)
  -block-confidence comma-separated values (default 0.80,0.85,0.90,0.95,0.99)
  -imports-min     comma-separated values (default 1,3,5)
  -max-fp          target false-positive rate for the recommendation (default 0.05)

fetch-malware flags (needs MALWAREBAZAAR_API_KEY, ClamAV and 7z):
  -types       MalwareBazaar file types (default `+defaultTypes+`)
  -per-type    ClamAV misses to keep per type (default 10)
  -candidates  recent samples to consider per type (default 100, max 1000)

fetch-benign flags (needs ClamAV):
  -sources     TSV of path, url, tags (default ../eval/benign-sources.tsv)

both fetch commands also take -manifest and -corpus and append to the manifest.`)
}

type manifest struct {
	Samples []manifestSample `json:"samples"`
}

type manifestSample struct {
	Path     string   `json:"path"`
	Expected string   `json:"expected"`
	Tags     []string `json:"tags,omitempty"`
}

type clamAVRecord struct {
	Detected  bool   `json:"detected"`
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

type durationRecord struct {
	ClamAV     int64 `json:"clamav"`
	Analysis   int64 `json:"analysis"`
	Classifier int64 `json:"classifier"`
	Total      int64 `json:"total"`
}

type rawRecord struct {
	Path            string                  `json:"path"`
	Expected        string                  `json:"expected"`
	Tags            []string                `json:"tags,omitempty"`
	Error           string                  `json:"error,omitempty"`
	SHA256          string                  `json:"sha256"`
	Size            int64                   `json:"size"`
	ClamAV          clamAVRecord            `json:"clamav"`
	Analysis        evidence.StaticAnalysis `json:"analysis"`
	Classifier      *classifier.Result      `json:"classifier,omitempty"`
	ClassifierError string                  `json:"classifier_error,omitempty"`
	DurationMS      durationRecord          `json:"duration_ms"`
}

func runCollect(args []string) error {
	flags := flag.NewFlagSet("collect", flag.ExitOnError)
	manifestPath := flags.String("manifest", "../eval/manifest.json", "manifest path")
	corpusDir := flags.String("corpus", "../eval/corpus", "corpus directory")
	outDir := flags.String("out", "", "output directory")
	limit := flags.Int("limit", 0, "max samples, 0 = all")
	noClassifier := flags.Bool("no-classifier", false, "skip Clef calls")
	_ = flags.Parse(args)

	cfg := config.Load()
	if *noClassifier {
		cfg.ClassifierEnabled = false
	}

	raw, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	var samples manifest
	if err := json.Unmarshal(raw, &samples); err != nil {
		return err
	}
	if *limit > 0 && len(samples.Samples) > *limit {
		samples.Samples = samples.Samples[:*limit]
	}

	out := *outDir
	if out == "" {
		out = filepath.Join("../eval/results", time.Now().Format("2006-01-02T15-04-05"))
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}

	output, err := os.Create(filepath.Join(out, "raw.jsonl"))
	if err != nil {
		return err
	}
	defer output.Close()
	encoder := json.NewEncoder(output)

	client := clamav.NewClient(cfg.ClamAVAddr)
	registry := buildRegistry(cfg)

	var fileClassifier classifier.Classifier
	if cfg.ClassifierEnabled {
		fileClassifier = classifier.NewClef(
			cfg.ClassifierBaseURL, cfg.ClassifierAccountID, cfg.ClassifierAPIToken, cfg.ClassifierModel,
			cfg.ClassifierLabels, cfg.ClassifierSendFilename, cfg.ClassifierTimeout,
		)
	}

	fmt.Printf("collecting %d samples (classifier=%v) -> %s\n", len(samples.Samples), cfg.ClassifierEnabled, out)

	for index, sample := range samples.Samples {
		path := filepath.Join(*corpusDir, sample.Path)
		data, err := os.ReadFile(path)
		if err != nil {
			record := rawRecord{Path: sample.Path, Expected: sample.Expected, Tags: sample.Tags, Error: err.Error()}
			_ = encoder.Encode(record)
			fmt.Printf("[%d/%d] %-48s ERROR %v\n", index+1, len(samples.Samples), sample.Path, err)
			continue
		}

		record := collectSample(cfg, client, registry, fileClassifier, sample, data)
		_ = encoder.Encode(record)

		label := "-"
		if record.Classifier != nil {
			label = record.Classifier.Label
		} else if record.ClassifierError != "" {
			label = "error"
		}
		fmt.Printf("[%d/%d] %-48s clamav=%-5v classifier=%-20s %dms\n",
			index+1, len(samples.Samples), sample.Path, record.ClamAV.Detected, label, record.DurationMS.Total)
	}

	fmt.Println("done:", filepath.Join(out, "raw.jsonl"))
	return nil
}

func collectSample(
	cfg config.Config,
	client clamav.Client,
	registry *analyzer.Registry,
	fileClassifier classifier.Classifier,
	sample manifestSample,
	data []byte,
) rawRecord {
	totalStart := time.Now()

	sum := sha256.Sum256(data)
	record := rawRecord{
		Path:     sample.Path,
		Expected: sample.Expected,
		Tags:     sample.Tags,
		SHA256:   hex.EncodeToString(sum[:]),
		Size:     int64(len(data)),
	}

	start := time.Now()
	scanErr := client.Scan(bytes.NewReader(data))
	record.DurationMS.ClamAV = time.Since(start).Milliseconds()

	if scanErr != nil {
		var virusErr interfaces.VirusFoundError
		if errors.As(scanErr, &virusErr) {
			record.ClamAV.Detected = true
			record.ClamAV.Signature = virusErr.VirusName()
		} else {
			record.ClamAV.Error = scanErr.Error()
		}
	}

	start = time.Now()
	if !record.ClamAV.Detected && record.ClamAV.Error == "" {
		record.Analysis = registry.Analyze(analyzer.Input{Data: data, Name: sample.Path})
	}
	record.DurationMS.Analysis = time.Since(start).Milliseconds()

	if fileClassifier != nil && record.Analysis.Supported && record.Analysis.Error == "" {
		fileEvidence := evidence.FileEvidence{
			File: evidence.FileInfo{
				Name:   sample.Path,
				Size:   int64(len(data)),
				SHA256: record.SHA256,
			},
			ClamAV:         evidence.ClamAVInfo{Detected: record.ClamAV.Detected, Signature: record.ClamAV.Signature},
			StaticAnalysis: record.Analysis,
		}

		ctx, cancel := context.WithTimeout(context.Background(), cfg.ClassifierTimeout)
		start = time.Now()
		result, err := fileClassifier.Classify(ctx, fileEvidence)
		cancel()
		record.DurationMS.Classifier = time.Since(start).Milliseconds()

		if err != nil {
			record.ClassifierError = err.Error()
		} else {
			record.Classifier = &result
		}
	}

	record.DurationMS.Total = time.Since(totalStart).Milliseconds()
	return record
}

func buildRegistry(cfg config.Config) *analyzer.Registry {
	return analyzer.NewRegistry(
		analyzer.NewPEAnalyzer(cfg.PackerEntropyThreshold),
		analyzer.NewPDFAnalyzer(),
		analyzer.NewOfficeAnalyzer(),
		analyzer.NewArchiveAnalyzer(),
		analyzer.NewScriptAnalyzer(),
		analyzer.NewGenericAnalyzer(),
	)
}

type variant struct {
	Name          string
	Rules         bool
	UseClassifier bool
}

type evaluation struct {
	Variant           string         `json:"variant"`
	BlockConfidence   float64        `json:"block_confidence"`
	ImportsMin        int            `json:"imports_min"`
	Samples           int            `json:"samples"`
	Verdicts          map[string]int `json:"verdicts"`
	MalwareTotal      int            `json:"malware_total"`
	MalwareDetected   int            `json:"malware_detected"`
	BenignTotal       int            `json:"benign_total"`
	BenignFlagged     int            `json:"benign_flagged"`
	ClamAVMisses      int            `json:"clamav_misses"`
	MissEscalated     int            `json:"clamav_misses_escalated"`
	TruePositive      int            `json:"true_positive"`
	FalsePositive     int            `json:"false_positive"`
	FalseNegative     int            `json:"false_negative"`
	Precision         float64        `json:"precision"`
	Recall            float64        `json:"recall"`
	F1                float64        `json:"f1"`
	FalsePositiveRate float64        `json:"false_positive_rate"`
	NullConfidence    int            `json:"null_confidence"`
	Labels            map[string]int `json:"labels"`
}

func runAnalyze(args []string) error {
	flags := flag.NewFlagSet("analyze", flag.ExitOnError)
	inDir := flags.String("in", "", "results directory from collect")
	blockConfidenceArg := flags.String("block-confidence", "0.80,0.85,0.90,0.95,0.99", "comma-separated values")
	importsMinArg := flags.String("imports-min", "1,3,5", "comma-separated values")
	maxFP := flags.Float64("max-fp", 0.05, "target false-positive rate")
	_ = flags.Parse(args)

	if *inDir == "" {
		return errors.New("-in is required")
	}

	records, err := readRecords(filepath.Join(*inDir, "raw.jsonl"))
	if err != nil {
		return err
	}

	blockConfidences, err := parseFloatList(*blockConfidenceArg)
	if err != nil {
		return err
	}
	importsMins, err := parseIntList(*importsMinArg)
	if err != nil {
		return err
	}

	var results []evaluation
	for _, blockConfidence := range blockConfidences {
		for _, importsMin := range importsMins {
			cfg := policy.Config{
				BlockConfidence:      blockConfidence,
				FailMode:             policy.Quarantine,
				AllowUnsupported:     true,
				StaticRulesEnabled:   true,
				StaticRuleVerdict:    policy.Quarantine,
				SuspiciousImportsMin: importsMin,
				GenericRulesEnabled:  true,
			}
			results = append(results, evaluate(fmt.Sprintf("combined"), records, cfg, variant{Rules: true, UseClassifier: true}))
		}
	}

	base := policy.Config{
		BlockConfidence:      0.95,
		FailMode:             policy.Quarantine,
		AllowUnsupported:     true,
		StaticRulesEnabled:   true,
		StaticRuleVerdict:    policy.Quarantine,
		SuspiciousImportsMin: 3,
		GenericRulesEnabled:  true,
	}
	results = append(results, evaluate("rule-only", records, base, variant{Rules: true, UseClassifier: false}))
	results = append(results, evaluate("classifier-only", records, base, variant{Rules: false, UseClassifier: true}))

	summary := map[string]any{
		"samples":     len(records),
		"latency":     latencyStats(records),
		"models":      modelVersions(records),
		"evaluations": results,
	}
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*inDir, "summary.json"), encoded, 0o644); err != nil {
		return err
	}

	report := buildReport(records, results, *maxFP)
	if err := os.WriteFile(filepath.Join(*inDir, "report.md"), []byte(report), 0o644); err != nil {
		return err
	}

	fmt.Println(report)
	fmt.Println("wrote summary.json and report.md in", *inDir)
	return nil
}

func evaluate(name string, records []rawRecord, cfg policy.Config, v variant) evaluation {
	result := evaluation{
		Variant:         name,
		BlockConfidence: cfg.BlockConfidence,
		ImportsMin:      cfg.SuspiciousImportsMin,
		Samples:         len(records),
		Verdicts:        map[string]int{"ALLOW": 0, "QUARANTINE": 0, "BLOCK": 0},
		Labels:          map[string]int{},
	}

	for _, record := range records {
		if record.Error != "" {
			continue
		}

		input := policy.Input{
			ClamAVDetected:  record.ClamAV.Detected,
			ClamAVSignature: record.ClamAV.Signature,
			ClamAVError:     record.ClamAV.Error,
			Analysis:        record.Analysis,
		}
		if v.UseClassifier {
			input.Classifier = record.Classifier
			input.ClassifierError = record.ClassifierError
		}

		effective := cfg
		effective.StaticRulesEnabled = v.Rules
		effective.GenericRulesEnabled = v.Rules

		decision := policy.Decide(input, effective)
		result.Verdicts[string(decision.Verdict)]++

		if record.Classifier != nil {
			result.Labels[record.Classifier.Label]++
			if record.Classifier.Confidence == nil {
				result.NullConfidence++
			}
		}

		if record.Expected == "malware" {
			result.MalwareTotal++
			miss := !record.ClamAV.Detected && record.ClamAV.Error == ""
			if miss {
				result.ClamAVMisses++
				if decision.Verdict != policy.Allow {
					result.MissEscalated++
				}
			}
			if decision.Verdict == policy.Allow {
				result.FalseNegative++
			} else {
				result.MalwareDetected++
				result.TruePositive++
			}
		}

		if record.Expected == "benign" {
			result.BenignTotal++
			if decision.Verdict != policy.Allow {
				result.BenignFlagged++
				result.FalsePositive++
			}
		}
	}

	if result.MalwareDetected > 0 || result.FalsePositive > 0 {
		result.Precision = float64(result.MalwareDetected) / float64(result.MalwareDetected+result.FalsePositive)
	}
	if result.MalwareTotal > 0 {
		result.Recall = float64(result.MalwareDetected) / float64(result.MalwareTotal)
	}
	if result.Precision+result.Recall > 0 {
		result.F1 = 2 * result.Precision * result.Recall / (result.Precision + result.Recall)
	}
	if result.BenignTotal > 0 {
		result.FalsePositiveRate = float64(result.BenignFlagged) / float64(result.BenignTotal)
	}

	return result
}

func readRecords(path string) ([]rawRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var records []rawRecord
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record rawRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("invalid JSONL line: %w", err)
		}
		records = append(records, record)
	}

	return records, scanner.Err()
}

func latencyStats(records []rawRecord) map[string]map[string]int64 {
	var clamav, analysis, class, total []int64
	for _, record := range records {
		if record.DurationMS.ClamAV > 0 {
			clamav = append(clamav, record.DurationMS.ClamAV)
		}
		if record.DurationMS.Analysis > 0 {
			analysis = append(analysis, record.DurationMS.Analysis)
		}
		if record.DurationMS.Classifier > 0 {
			class = append(class, record.DurationMS.Classifier)
		}
		total = append(total, record.DurationMS.Total)
	}

	return map[string]map[string]int64{
		"clamav":     {"p50": percentile(clamav, 50), "p95": percentile(clamav, 95)},
		"analysis":   {"p50": percentile(analysis, 50), "p95": percentile(analysis, 95)},
		"classifier": {"p50": percentile(class, 50), "p95": percentile(class, 95)},
		"total":      {"p50": percentile(total, 50), "p95": percentile(total, 95)},
	}
}

func percentile(values []int64, p int) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	index := (p * len(sorted)) / 100
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func modelVersions(records []rawRecord) []string {
	seen := map[string]bool{}
	var models []string
	for _, record := range records {
		if record.Classifier != nil && record.Classifier.Model != "" && !seen[record.Classifier.Model] {
			seen[record.Classifier.Model] = true
			models = append(models, record.Classifier.Model)
		}
	}
	sort.Strings(models)
	return models
}

func buildReport(records []rawRecord, results []evaluation, maxFP float64) string {
	var b strings.Builder

	b.WriteString("# Evaluation Report\n\n")

	expected := map[string]int{}
	errors := 0
	for _, record := range records {
		if record.Error != "" {
			errors++
			continue
		}
		expected[record.Expected]++
	}

	fmt.Fprintf(&b, "- Samples: %d (errors: %d)\n", len(records), errors)
	fmt.Fprintf(&b, "- Expected: malware=%d benign=%d suspicious=%d unknown=%d\n",
		expected["malware"], expected["benign"], expected["suspicious"], expected["unknown"])
	fmt.Fprintf(&b, "- Models: %s\n\n", strings.Join(modelVersions(records), ", "))

	b.WriteString("## Threshold grid (combined)\n\n")
	b.WriteString("| variant | block_conf | imports_min | malware recall | FP rate | F1 | misses escalated |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")

	bestIndex := -1
	bestScore := -1.0
	for index, result := range results {
		if result.Variant != "combined" {
			continue
		}
		fmt.Fprintf(&b, "| %s | %.2f | %d | %.2f | %.2f | %.2f | %d/%d |\n",
			result.Variant, result.BlockConfidence, result.ImportsMin,
			result.Recall, result.FalsePositiveRate, result.F1,
			result.MissEscalated, result.ClamAVMisses)

		if result.FalsePositiveRate <= maxFP && result.Recall > bestScore {
			bestScore = result.Recall
			bestIndex = index
		}
	}

	b.WriteString("\n## Variants (baseline thresholds)\n\n")
	b.WriteString("| variant | malware recall | FP rate | precision | F1 | verdicts (A/Q/B) |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	for _, result := range results {
		if result.Variant == "combined" {
			continue
		}
		fmt.Fprintf(&b, "| %s | %.2f | %.2f | %.2f | %.2f | %d/%d/%d |\n",
			result.Variant, result.Recall, result.FalsePositiveRate, result.Precision, result.F1,
			result.Verdicts["ALLOW"], result.Verdicts["QUARANTINE"], result.Verdicts["BLOCK"])
	}

	b.WriteString("\n## Recommendation\n\n")
	if bestIndex >= 0 {
		recommended := results[bestIndex]
		fmt.Fprintf(&b, "Highest malware recall with FP rate <= %.0f%%: `VERDICT_BLOCK_CONFIDENCE=%.2f`, `SUSPICIOUS_IMPORTS_MIN=%d` (recall %.2f, FP %.2f).\n",
			maxFP*100, recommended.BlockConfidence, recommended.ImportsMin, recommended.Recall, recommended.FalsePositiveRate)
	} else {
		fmt.Fprintf(&b, "No threshold combination reached FP rate <= %.0f%%. Treat thresholds as unresolved and expand the corpus.\n", maxFP*100)
	}

	latency := latencyStats(records)
	fmt.Fprintf(&b, "\nLatency p50/p95 (ms): clamav %d/%d, analysis %d/%d, classifier %d/%d, total %d/%d\n",
		latency["clamav"]["p50"], latency["clamav"]["p95"],
		latency["analysis"]["p50"], latency["analysis"]["p95"],
		latency["classifier"]["p50"], latency["classifier"]["p95"],
		latency["total"]["p50"], latency["total"]["p95"],
	)

	b.WriteString("\n> Corpus samples are local only. Suspected malware must never be committed to the repository.\n")
	return b.String()
}

func parseFloatList(value string) ([]float64, error) {
	var result []float64
	for _, item := range strings.Split(value, ",") {
		parsed, err := strconv.ParseFloat(strings.TrimSpace(item), 64)
		if err != nil {
			return nil, err
		}
		result = append(result, parsed)
	}
	return result, nil
}

func parseIntList(value string) ([]int, error) {
	var result []int
	for _, item := range strings.Split(value, ",") {
		parsed, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil {
			return nil, err
		}
		result = append(result, parsed)
	}
	return result, nil
}
