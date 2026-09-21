package evidence

import (
	"fmt"
	"sort"
	"strings"
)

const MaxTextLength = 2000

type FileInfo struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	MIME   string `json:"mime"`
	SHA256 string `json:"sha256"`
}

type ClamAVInfo struct {
	Detected  bool   `json:"detected"`
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Section struct {
	Name        string  `json:"name"`
	Size        int64   `json:"size"`
	VirtualSize int64   `json:"virtual_size,omitempty"`
	Entropy     float64 `json:"entropy"`
	Writable    bool    `json:"writable"`
	Executable  bool    `json:"executable"`
}

type StaticAnalysis struct {
	Supported           bool      `json:"supported"`
	FileType            string    `json:"file_type,omitempty"`
	Architecture        string    `json:"architecture,omitempty"`
	IsDLL               bool      `json:"is_dll,omitempty"`
	EntryPointSection   string    `json:"entry_point_section,omitempty"`
	Sections            []Section `json:"sections,omitempty"`
	MaxEntropy          float64   `json:"max_entropy,omitempty"`
	HasPackedSection    bool      `json:"has_packed_section"`
	HasDigitalSignature bool      `json:"has_digital_signature"`
	PackerHints         []string  `json:"packer_hints,omitempty"`
	ImportsCount        int       `json:"imports_count,omitempty"`
	SuspiciousImports   []string  `json:"suspicious_imports,omitempty"`
	Error               string    `json:"error,omitempty"`
}

type FileEvidence struct {
	File           FileInfo       `json:"file"`
	ClamAV         ClamAVInfo     `json:"clamav"`
	StaticAnalysis StaticAnalysis `json:"static_analysis"`
}

func (e FileEvidence) ToText(sendFilename bool) string {
	var b strings.Builder
	sa := e.StaticAnalysis

	if sendFilename && e.File.Name != "" {
		fmt.Fprintf(&b, "File name: %s.\n", e.File.Name)
	}

	if sa.Supported {
		if sa.FileType != "" {
			fmt.Fprintf(&b, "File type: %s executable.\n", sa.FileType)
		}
		if sa.Architecture != "" {
			fmt.Fprintf(&b, "Architecture: %s.\n", sa.Architecture)
		}
		if sa.IsDLL {
			b.WriteString("The file is a dynamic-link library (DLL).\n")
		}
		if sa.ImportsCount > 0 {
			fmt.Fprintf(&b, "Number of imports: %d.\n", sa.ImportsCount)
		}

		b.WriteString("\n")

		if sa.MaxEntropy > 0 {
			fmt.Fprintf(&b, "Maximum section entropy: %.2f.\n", sa.MaxEntropy)
		}
		if sa.HasPackedSection {
			b.WriteString("A packed section is present.\n")
		}
		if sa.HasDigitalSignature {
			b.WriteString("The executable is digitally signed.\n")
		} else {
			b.WriteString("The executable is not digitally signed.\n")
		}

		if len(sa.PackerHints) > 0 {
			b.WriteString("\nPacking indicators:\n")
			for _, hint := range sortedUnique(sa.PackerHints) {
				fmt.Fprintf(&b, "- %s\n", hint)
			}
		}

		if len(sa.SuspiciousImports) > 0 {
			b.WriteString("\nSuspicious imports detected:\n")
			for _, name := range sortedUnique(sa.SuspiciousImports) {
				fmt.Fprintf(&b, "- %s\n", name)
			}
		}
	} else {
		b.WriteString("No static analysis is available for this file type.\n")
	}

	b.WriteString("\n")
	switch {
	case e.ClamAV.Detected:
		fmt.Fprintf(&b, "ClamAV detected a known malware signature: %s.\n", e.ClamAV.Signature)
	case e.ClamAV.Error != "":
		b.WriteString("ClamAV could not scan this file.\n")
	default:
		b.WriteString("ClamAV did not detect a known malware signature.\n")
	}

	return truncate(strings.TrimSpace(b.String()), MaxTextLength)
}

func sortedUnique(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func truncate(value string, max int) string {
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max])
}
