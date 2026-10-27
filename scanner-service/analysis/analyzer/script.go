package analyzer

import (
	"bytes"
	"path"
	"strings"

	"scanner-service/analysis/evidence"
)

var scriptExtensions = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".vbs": true, ".vbe": true,
	".ps1": true, ".psm1": true, ".bat": true, ".cmd": true, ".hta": true,
	".sh": true, ".py": true, ".rb": true, ".php": true, ".pl": true,
}

type ScriptAnalyzer struct {
	Options GenericOptions
}

func NewScriptAnalyzer() *ScriptAnalyzer {
	return &ScriptAnalyzer{Options: DefaultGenericOptions()}
}

func (a *ScriptAnalyzer) Name() string { return "script" }

func (a *ScriptAnalyzer) Supports(in Input) bool {
	if scriptExtensions[strings.ToLower(path.Ext(in.Name))] {
		return true
	}

	lower := bytes.ToLower(in.Data)
	for _, marker := range []string{"wscript", "activexobject", "invoke-expression", "frombase64string", "shell.application"} {
		if bytes.Contains(lower, []byte(marker)) {
			return true
		}
	}

	return false
}

func (a *ScriptAnalyzer) Analyze(in Input) (evidence.StaticAnalysis, error) {
	data := in.Data
	lower := bytes.ToLower(data)

	g := evidence.GenericEvidence{
		MagicType:   "script",
		FileEntropy: round2(entropy(data)),
	}

	for _, marker := range scriptMarkers {
		if bytes.Contains(lower, []byte(marker.marker)) {
			g.SuspiciousStrings = append(g.SuspiciousStrings, marker.label)
			if len(g.SuspiciousStrings) >= a.Options.MaxStrings {
				break
			}
		}
	}

	lowerName := strings.ToLower(in.Name)
	g.HasJavaScript = strings.HasSuffix(lowerName, ".js") ||
		strings.HasSuffix(lowerName, ".mjs") ||
		strings.HasSuffix(lowerName, ".hta") ||
		bytes.Contains(lower, []byte("<script")) ||
		bytes.Contains(lower, []byte("xmlhttp"))

	g.AutoExec = strings.HasSuffix(lowerName, ".hta") ||
		bytes.Contains(lower, []byte("wscript.shell")) ||
		bytes.Contains(lower, []byte("document_open")) ||
		bytes.Contains(lower, []byte("autoopen"))

	if base64Pattern.Match(data) {
		g.ObfuscationHints = append(g.ObfuscationHints, "long base64 blob")
	}
	if longestLine(data) > 500 {
		g.ObfuscationHints = append(g.ObfuscationHints, "very long line")
	}

	g.URLs = extractURLs(data, a.Options.MaxURLs)

	return evidence.StaticAnalysis{Kind: "script", Generic: g}, nil
}
