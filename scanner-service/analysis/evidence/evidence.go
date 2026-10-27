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

// GenericEvidence carries findings that are not specific to PE files. It is
// filled by every analyzer (as enrichment) and by the generic fallback analyzer
// for non-PE formats.
type GenericEvidence struct {
	MagicType         string   `json:"magic_type,omitempty"`
	FileEntropy       float64  `json:"file_entropy,omitempty"`
	EmbeddedPE        bool     `json:"embedded_pe,omitempty"`
	EmbeddedTypes     []string `json:"embedded_types,omitempty"`
	NestedExecutables []string `json:"nested_executables,omitempty"`
	URLs              []string `json:"urls,omitempty"`
	HasJavaScript     bool     `json:"has_javascript,omitempty"`
	HasMacros         bool     `json:"has_macros,omitempty"`
	Encrypted         bool     `json:"encrypted,omitempty"`
	ExternalTargets   []string `json:"external_targets,omitempty"`
	AutoExec          bool     `json:"auto_exec,omitempty"`
	SuspiciousStrings []string `json:"suspicious_strings,omitempty"`
	ObfuscationHints  []string `json:"obfuscation_hints,omitempty"`
}

func (g GenericEvidence) Empty() bool {
	return g.MagicType == "" &&
		g.FileEntropy == 0 &&
		!g.EmbeddedPE &&
		len(g.EmbeddedTypes) == 0 &&
		len(g.NestedExecutables) == 0 &&
		len(g.URLs) == 0 &&
		!g.HasJavaScript &&
		!g.HasMacros &&
		!g.Encrypted &&
		len(g.ExternalTargets) == 0 &&
		!g.AutoExec &&
		len(g.SuspiciousStrings) == 0 &&
		len(g.ObfuscationHints) == 0
}

// HasSignal reports whether the generic evidence is worth an assessment.
func (g GenericEvidence) HasSignal() bool {
	return g.EmbeddedPE ||
		len(g.NestedExecutables) > 0 ||
		len(g.URLs) > 0 ||
		g.HasJavaScript ||
		g.HasMacros ||
		g.Encrypted ||
		len(g.ExternalTargets) > 0 ||
		g.AutoExec ||
		len(g.ObfuscationHints) > 0
}

type StaticAnalysis struct {
	Supported           bool            `json:"supported"`
	Kind                string          `json:"kind,omitempty"`
	FileType            string          `json:"file_type,omitempty"`
	Architecture        string          `json:"architecture,omitempty"`
	IsDLL               bool            `json:"is_dll,omitempty"`
	IsDotNet            bool            `json:"is_dotnet,omitempty"`
	EntryPointSection   string          `json:"entry_point_section,omitempty"`
	Sections            []Section       `json:"sections,omitempty"`
	MaxEntropy          float64         `json:"max_entropy,omitempty"`
	OverlaySize         int64           `json:"overlay_size,omitempty"`
	OverlayEntropy      float64         `json:"overlay_entropy,omitempty"`
	HasPackedSection    bool            `json:"has_packed_section"`
	HasDigitalSignature bool            `json:"has_digital_signature"`
	SignerSubject       string          `json:"signer_subject,omitempty"`
	SignerIssuer        string          `json:"signer_issuer,omitempty"`
	SignatureStatus     string          `json:"signature_status,omitempty"`
	PackerHints         []string        `json:"packer_hints,omitempty"`
	ImportsCount        int             `json:"imports_count,omitempty"`
	SuspiciousImports   []string        `json:"suspicious_imports,omitempty"`
	Generic             GenericEvidence `json:"generic,omitempty"`
	Error               string          `json:"error,omitempty"`
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
		if kind := kindLabel(sa.Kind); kind != "" {
			fmt.Fprintf(&b, "File type: %s.\n", kind)
		}
		if sa.IsDLL {
			b.WriteString("The file is a dynamic-link library (DLL).\n")
		}
		if sa.IsDotNet {
			b.WriteString("The file is a .NET assembly (managed code): its native imports and section layout say little about its behaviour.\n")
		}
		if sa.Architecture != "" {
			fmt.Fprintf(&b, "Architecture: %s.\n", sa.Architecture)
		}
		if sa.ImportsCount > 0 {
			fmt.Fprintf(&b, "Number of imports: %d.\n", sa.ImportsCount)
		}

		b.WriteString("\n")

		if sa.MaxEntropy > 0 {
			fmt.Fprintf(&b, "Maximum section entropy: %.2f.\n", sa.MaxEntropy)
		}
		if sa.OverlaySize > 0 {
			fmt.Fprintf(&b, "Data appended after the last section (overlay): %d bytes", sa.OverlaySize)
			if e.File.Size > 0 {
				fmt.Fprintf(&b, " (%.0f%% of the file)", 100*float64(sa.OverlaySize)/float64(e.File.Size))
			}
			fmt.Fprintf(&b, ", entropy %.2f", sa.OverlayEntropy)
			// Authenticode hashes the overlay too, so a valid signature means the
			// payload was shipped by the signer rather than appended later.
			if sa.SignatureStatus == "valid" {
				b.WriteString("; it is covered by the valid signature")
			}
			b.WriteString(".\n")
		}
		if sa.HasPackedSection {
			b.WriteString("A packed section is present.\n")
		}
		if sa.Kind == "pe" {
			switch {
			case sa.SignatureStatus == "invalid":
				fmt.Fprintf(&b, "The executable carries an Authenticode signature naming signer %q, but it does NOT match the file contents (copied or tampered signature).\n", sa.SignerSubject)
			case sa.SignerSubject != "":
				if sa.SignatureStatus == "valid" {
					b.WriteString("The executable has a valid Authenticode signature (matches the file; certificate chain not checked)")
				} else {
					b.WriteString("The executable has an Authenticode signature that could not be verified")
				}
				fmt.Fprintf(&b, ". Signer: %s", sa.SignerSubject)
				if sa.SignerIssuer != "" {
					fmt.Fprintf(&b, "; issued by: %s", sa.SignerIssuer)
				}
				b.WriteString(".\n")
			case sa.HasDigitalSignature:
				b.WriteString("The executable has a signature block, but no signer certificate could be read.\n")
			default:
				b.WriteString("The executable is not digitally signed.\n")
			}
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
		} else if sa.Kind == "pe" && !sa.IsDotNet && sa.ImportsCount >= 10 {
			b.WriteString("None of the imports are on the suspicious API list.\n")
		}

		generic := sa.Generic
		if sa.Kind == "pe" {
			// Whole-file entropy mixes code, resources and overlay; section and
			// overlay entropy above are the meaningful numbers for executables.
			generic.FileEntropy = 0
		}
		writeGenericText(&b, generic)
	} else {
		b.WriteString("No static analysis is available for this file type.\n")
		if !sa.Generic.Empty() {
			writeGenericText(&b, sa.Generic)
		}
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

func writeGenericText(b *strings.Builder, g GenericEvidence) {
	if g.Empty() {
		return
	}

	b.WriteString("\n")

	if g.FileEntropy > 0 {
		fmt.Fprintf(b, "File entropy: %.2f.\n", g.FileEntropy)
	}
	if g.EmbeddedPE {
		b.WriteString("An embedded executable was detected in the file.\n")
	}
	if g.HasJavaScript {
		b.WriteString("The file contains JavaScript.\n")
	}
	if g.AutoExec {
		b.WriteString("The file has an auto-execution mechanism.\n")
	}
	if g.HasMacros {
		b.WriteString("The document contains macros.\n")
	}
	if g.Encrypted {
		b.WriteString("The file is encrypted or password-protected; its contents could not be inspected.\n")
	}
	if len(g.ExternalTargets) > 0 {
		fmt.Fprintf(b, "External targets: %d (%s).\n", len(g.ExternalTargets), strings.Join(head(g.ExternalTargets, 3), ", "))
	}
	if len(g.NestedExecutables) > 0 {
		fmt.Fprintf(b, "Nested executables: %s.\n", strings.Join(head(g.NestedExecutables, 5), ", "))
	}
	if len(g.URLs) > 0 {
		fmt.Fprintf(b, "URLs found: %d (%s).\n", len(g.URLs), strings.Join(head(g.URLs, 3), ", "))
	}
	if len(g.SuspiciousStrings) > 0 {
		fmt.Fprintf(b, "Suspicious strings: %s.\n", strings.Join(head(sortedUnique(g.SuspiciousStrings), 5), ", "))
	}
	if len(g.ObfuscationHints) > 0 {
		fmt.Fprintf(b, "Obfuscation indicators: %s.\n", strings.Join(sortedUnique(g.ObfuscationHints), ", "))
	}
}

func kindLabel(kind string) string {
	switch kind {
	case "pe":
		return "PE executable"
	case "pdf":
		return "PDF document"
	case "office":
		return "office document"
	case "archive":
		return "archive"
	case "script":
		return "script"
	case "text":
		return "text file"
	case "binary":
		return "binary file"
	case "generic":
		return "unclassified file"
	default:
		return ""
	}
}

func head(values []string, max int) []string {
	if len(values) <= max {
		return values
	}
	return values[:max]
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
