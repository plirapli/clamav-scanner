package evidence

import (
	"fmt"
	"strings"
	"testing"
)

func sampleEvidence() FileEvidence {
	return FileEvidence{
		File:   FileInfo{Name: "sample.exe", Size: 4096, MIME: "application/octet-stream", SHA256: "abc"},
		ClamAV: ClamAVInfo{Detected: false},
		StaticAnalysis: StaticAnalysis{
			Supported:         true,
			FileType:          "PE32+",
			Architecture:      "x86_64",
			MaxEntropy:        7.94,
			HasPackedSection:  true,
			PackerHints:       []string{"section name resembles packer", "high-entropy executable section"},
			SuspiciousImports: []string{"WriteProcessMemory", "VirtualAlloc", "CreateRemoteThread"},
			ImportsCount:      7,
		},
	}
}

func TestToTextDeterministic(t *testing.T) {
	ev := sampleEvidence()

	first := ev.ToText(false)
	second := ev.ToText(false)
	if first != second {
		t.Fatal("expected deterministic output")
	}

	if strings.Contains(first, "sample.exe") {
		t.Fatal("filename must be omitted when sendFilename is false")
	}
	if !strings.Contains(ev.ToText(true), "sample.exe") {
		t.Fatal("filename must be included when sendFilename is true")
	}

	importsIndex := strings.Index(first, "- CreateRemoteThread")
	if importsIndex == -1 {
		t.Fatalf("expected sorted imports, got:\n%s", first)
	}
	if strings.Index(first, "- VirtualAlloc") > strings.Index(first, "- WriteProcessMemory") {
		t.Fatal("imports must be sorted alphabetically")
	}
	if !strings.Contains(first, "Maximum section entropy: 7.94.") {
		t.Fatal("expected entropy line")
	}
	if !strings.Contains(first, "ClamAV did not detect a known malware signature.") {
		t.Fatal("expected clamav line")
	}
}

func TestToTextIsBounded(t *testing.T) {
	var imports []string
	for i := 0; i < 500; i++ {
		imports = append(imports, fmt.Sprintf("VeryLongSuspiciousImportName%03d", i))
	}

	ev := FileEvidence{StaticAnalysis: StaticAnalysis{Supported: true, SuspiciousImports: imports}}
	if got := len([]rune(ev.ToText(false))); got > MaxTextLength {
		t.Fatalf("text length %d exceeds %d", got, MaxTextLength)
	}
}

func TestToTextUnsupported(t *testing.T) {
	ev := FileEvidence{StaticAnalysis: StaticAnalysis{Supported: false}}
	if !strings.Contains(ev.ToText(false), "No static analysis is available") {
		t.Fatal("expected unsupported notice")
	}
}
