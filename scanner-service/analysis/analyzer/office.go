package analyzer

import (
	"archive/zip"
	"bytes"
	"io"
	"path"
	"regexp"
	"strings"

	"scanner-service/analysis/evidence"
)

const maxOfficeEntries = 128

var officeExtensions = map[string]bool{
	".docx": true, ".docm": true, ".dotm": true,
	".xlsx": true, ".xlsm": true, ".xltm": true,
	".pptx": true, ".pptm": true,
	".vsdx": true,
}

var legacyOfficeExtensions = map[string]bool{".doc": true, ".xls": true, ".ppt": true}

var oleMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

var targetPattern = regexp.MustCompile(`Target="([^"]+)"`)

type OfficeAnalyzer struct {
	Options GenericOptions
}

func NewOfficeAnalyzer() *OfficeAnalyzer {
	return &OfficeAnalyzer{Options: DefaultGenericOptions()}
}

func (a *OfficeAnalyzer) Name() string { return "office" }

func (a *OfficeAnalyzer) Supports(in Input) bool {
	ext := strings.ToLower(path.Ext(in.Name))

	if bytes.HasPrefix(in.Data, []byte("PK\x03\x04")) {
		if officeExtensions[ext] {
			return true
		}

		reader, err := zip.NewReader(bytes.NewReader(in.Data), int64(len(in.Data)))
		if err != nil {
			return false
		}
		for _, file := range reader.File {
			name := strings.ToLower(file.Name)
			if name == "[content_types].xml" ||
				strings.HasPrefix(name, "word/") ||
				strings.HasPrefix(name, "xl/") ||
				strings.HasPrefix(name, "ppt/") {
				return true
			}
		}
		return false
	}

	return bytes.HasPrefix(in.Data, oleMagic) && legacyOfficeExtensions[ext]
}

func (a *OfficeAnalyzer) Analyze(in Input) (evidence.StaticAnalysis, error) {
	if bytes.HasPrefix(in.Data, oleMagic) {
		return a.analyzeOLE(in), nil
	}

	return a.analyzeOOXML(in)
}

func (a *OfficeAnalyzer) analyzeOOXML(in Input) (evidence.StaticAnalysis, error) {
	reader, err := zip.NewReader(bytes.NewReader(in.Data), int64(len(in.Data)))
	if err != nil {
		return evidence.StaticAnalysis{}, err
	}

	g := evidence.GenericEvidence{
		MagicType:   "ooxml",
		FileEntropy: round2(entropy(in.Data)),
	}

	var findings []string

	for index, file := range reader.File {
		if index >= maxOfficeEntries {
			break
		}

		name := strings.ToLower(file.Name)
		switch {
		case strings.Contains(name, "vbaproject.bin"):
			g.HasMacros = true
			findings = append(findings, "vbaProject.bin")
		case strings.HasSuffix(name, ".rels"):
			content := readZipFile(file, 1<<20)
			if bytes.Contains(content, []byte(`TargetMode="External"`)) {
				g.ExternalTargets = append(g.ExternalTargets, extractTargets(content)...)
			}
		case strings.HasSuffix(name, ".xml"):
			content := readZipFile(file, 2<<20)
			lower := bytes.ToLower(content)
			if bytes.Contains(lower, []byte("fldchar")) && bytes.Contains(lower, []byte("includetext")) {
				g.AutoExec = true
				findings = append(findings, "DDE field")
			}
		}
	}

	g.SuspiciousStrings = findings
	if len(g.ExternalTargets) > 0 {
		g.SuspiciousStrings = append(g.SuspiciousStrings, "external relationships")
	}
	g.URLs = extractURLs(in.Data, a.Options.MaxURLs)

	return evidence.StaticAnalysis{Kind: "office", Generic: g}, nil
}

func (a *OfficeAnalyzer) analyzeOLE(in Input) evidence.StaticAnalysis {
	data := in.Data

	g := evidence.GenericEvidence{
		MagicType:   "ole",
		FileEntropy: round2(entropy(data)),
	}

	var findings []string
	if bytes.Contains(data, []byte("_VBA_PROJECT")) || bytes.Contains(data, []byte("VBA")) {
		g.HasMacros = true
		findings = append(findings, "VBA project")
	}
	if bytes.Contains(data, []byte("AutoOpen")) || bytes.Contains(data, []byte("Document_Open")) {
		g.AutoExec = true
		findings = append(findings, "auto-open macro")
	}

	g.SuspiciousStrings = findings
	g.URLs = extractURLs(data, a.Options.MaxURLs)

	return evidence.StaticAnalysis{Kind: "office", Generic: g}
}

func readZipFile(file *zip.File, limit int64) []byte {
	reader, err := file.Open()
	if err != nil {
		return nil
	}
	defer reader.Close()

	content, _ := io.ReadAll(io.LimitReader(reader, limit))
	return content
}

func extractTargets(content []byte) []string {
	matches := targetPattern.FindAllSubmatch(content, 10)

	targets := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		target := string(match[1])
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") ||
			strings.HasPrefix(target, "file://") || strings.HasPrefix(target, "\\\\") {
			targets = append(targets, target)
		}
	}

	return targets
}
