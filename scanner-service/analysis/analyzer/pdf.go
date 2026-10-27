package analyzer

import (
	"bytes"

	"scanner-service/analysis/evidence"
)

type PDFAnalyzer struct {
	Options GenericOptions
}

func NewPDFAnalyzer() *PDFAnalyzer {
	return &PDFAnalyzer{Options: DefaultGenericOptions()}
}

func (a *PDFAnalyzer) Name() string { return "pdf" }

func (a *PDFAnalyzer) Supports(in Input) bool {
	return bytes.HasPrefix(in.Data, []byte("%PDF"))
}

func (a *PDFAnalyzer) Analyze(in Input) (evidence.StaticAnalysis, error) {
	data := in.Data

	g := evidence.GenericEvidence{
		MagicType:   "pdf",
		FileEntropy: round2(entropy(data)),
	}

	g.HasJavaScript = bytes.Contains(data, []byte("/JavaScript")) || bytes.Contains(data, []byte("/JS"))
	g.AutoExec = bytes.Contains(data, []byte("/OpenAction")) || bytes.Contains(data, []byte("/AA"))

	var markers []string
	if g.HasJavaScript {
		markers = append(markers, "JavaScript")
	}
	if bytes.Contains(data, []byte("/OpenAction")) {
		markers = append(markers, "OpenAction")
	}
	if bytes.Contains(data, []byte("/AA")) {
		markers = append(markers, "Additional Actions")
	}
	if bytes.Contains(data, []byte("/Launch")) {
		markers = append(markers, "Launch action")
	}
	if bytes.Contains(data, []byte("/EmbeddedFile")) {
		markers = append(markers, "EmbeddedFile")
		g.EmbeddedTypes = append(g.EmbeddedTypes, "pdf-embedded-file")
	}
	if bytes.Contains(data, []byte("/RichMedia")) {
		markers = append(markers, "RichMedia")
	}
	if bytes.Contains(bytes.ToLower(data), []byte("/encrypt")) {
		g.Encrypted = true
	}

	g.SuspiciousStrings = markers
	g.URLs = extractURLs(data, a.Options.MaxURLs)

	return evidence.StaticAnalysis{Kind: "pdf", Generic: g}, nil
}
