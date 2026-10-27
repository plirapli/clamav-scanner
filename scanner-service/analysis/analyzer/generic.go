package analyzer

import (
	"bytes"
	"debug/pe"
	"regexp"
	"strings"

	"scanner-service/analysis/evidence"
)

type GenericOptions struct {
	EmbeddedPEScanMax int
	MaxURLs           int
	MaxStrings        int
	MaxMZCandidates   int
	SkipEmbeddedPE    bool
	// Binary skips the text heuristics (long lines, base64 runs) that only
	// mean something in scripts and documents.
	Binary bool
}

func DefaultGenericOptions() GenericOptions {
	return GenericOptions{
		EmbeddedPEScanMax: 8 << 20,
		MaxURLs:           20,
		MaxStrings:        20,
		MaxMZCandidates:   16,
	}
}

var (
	urlPattern    = regexp.MustCompile(`https?://[^\s"'<>\\)\]]+`)
	base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{60,}={0,2}`)
)

var scriptMarkers = []struct {
	marker string
	label  string
}{
	{"wscript.shell", "WScript.Shell"},
	{"activexobject", "ActiveXObject"},
	{"shell.application", "Shell.Application"},
	{"xmlhttp", "XMLHTTP"},
	{"invoke-expression", "Invoke-Expression"},
	{"-encodedcommand", "-EncodedCommand"},
	{"frombase64string", "FromBase64String"},
	{"downloadstring", "DownloadString"},
	{"mshta", "mshta"},
	{"regsvr32 /s", "regsvr32 /s"},
	{"certutil -urlcache", "certutil -urlcache"},
	{"curl | sh", "curl | sh"},
	{"wget | sh", "wget | sh"},
	{"eval(", "eval"},
}

// ScanGeneric extracts format-independent evidence. It is used both as
// enrichment by specific analyzers and as the fallback for unknown formats.
func ScanGeneric(in Input, opts GenericOptions) evidence.GenericEvidence {
	opts = withDefaults(opts)

	data := in.Data
	result := evidence.GenericEvidence{
		MagicType:   DetectMagic(data),
		FileEntropy: round2(entropy(data)),
	}

	result.URLs = extractURLs(data, opts.MaxURLs)

	lower := bytes.ToLower(data)
	for _, marker := range scriptMarkers {
		if bytes.Contains(lower, []byte(marker.marker)) {
			result.SuspiciousStrings = append(result.SuspiciousStrings, marker.label)
			if len(result.SuspiciousStrings) >= opts.MaxStrings {
				break
			}
		}
	}

	if bytes.Contains(lower, []byte("encryptedpackage")) || bytes.Contains(lower, []byte("encryptioninfo")) {
		result.Encrypted = true
	}

	result.HasJavaScript = looksLikeJavaScript(in)

	if !opts.SkipEmbeddedPE {
		scanEmbeddedPE(data, opts, &result)
	}

	if !opts.Binary {
		if base64Pattern.Match(data) {
			result.ObfuscationHints = append(result.ObfuscationHints, "long base64 blob")
		}
		if longestLine(data) > 800 {
			result.ObfuscationHints = append(result.ObfuscationHints, "very long line")
		}
	}

	if strings.HasSuffix(strings.ToLower(in.Name), ".hta") {
		result.AutoExec = true
	}

	return result
}

func withDefaults(opts GenericOptions) GenericOptions {
	defaults := DefaultGenericOptions()
	if opts.EmbeddedPEScanMax == 0 {
		opts.EmbeddedPEScanMax = defaults.EmbeddedPEScanMax
	}
	if opts.MaxURLs == 0 {
		opts.MaxURLs = defaults.MaxURLs
	}
	if opts.MaxStrings == 0 {
		opts.MaxStrings = defaults.MaxStrings
	}
	if opts.MaxMZCandidates == 0 {
		opts.MaxMZCandidates = defaults.MaxMZCandidates
	}
	return opts
}

func extractURLs(data []byte, max int) []string {
	found := urlPattern.FindAll(data, max)
	if len(found) == 0 {
		return nil
	}

	seen := map[string]bool{}
	urls := make([]string, 0, len(found))
	for _, match := range found {
		url := strings.TrimRight(string(match), ".,;:")
		if url == "" || seen[url] || isNamespaceURL(url) {
			continue
		}
		seen[url] = true
		urls = append(urls, url)
	}

	return urls
}

// namespaceHosts serve XML namespace and schema identifiers (Windows manifests,
// OOXML, XMP, SVG). They appear in nearly every benign file and are never fetched.
var namespaceHosts = []string{
	"schemas.microsoft.com/",
	"schemas.openxmlformats.org/",
	"schemas.xmlsoap.org/",
	"www.w3.org/",
	"ns.adobe.com/",
	"purl.org/",
}

func isNamespaceURL(url string) bool {
	rest := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(url), "http://"), "https://")
	for _, host := range namespaceHosts {
		if strings.HasPrefix(rest, host) {
			return true
		}
	}
	return false
}

func looksLikeJavaScript(in Input) bool {
	lowerName := strings.ToLower(in.Name)
	if strings.HasSuffix(lowerName, ".js") || strings.HasSuffix(lowerName, ".mjs") || strings.HasSuffix(lowerName, ".hta") {
		return true
	}

	lower := bytes.ToLower(in.Data)
	return bytes.Contains(lower, []byte("<script")) ||
		bytes.Contains(lower, []byte("javascript:")) ||
		bytes.Contains(lower, []byte("xmlhttp")) ||
		bytes.Contains(lower, []byte("activexobject"))
}

func scanEmbeddedPE(data []byte, opts GenericOptions, result *evidence.GenericEvidence) {
	limit := len(data)
	if opts.EmbeddedPEScanMax > 0 && limit > opts.EmbeddedPEScanMax {
		limit = opts.EmbeddedPEScanMax
	}

	candidates := 0
	for i := 1; i+1 < limit; i++ {
		if data[i] != 'M' || data[i+1] != 'Z' {
			continue
		}
		candidates++
		if candidates > opts.MaxMZCandidates {
			return
		}

		file, err := pe.NewFile(bytes.NewReader(data[i:]))
		if err != nil {
			continue
		}
		_ = file.Close()

		result.EmbeddedPE = true
		if !containsString(result.EmbeddedTypes, "pe") {
			result.EmbeddedTypes = append(result.EmbeddedTypes, "pe")
		}
		return
	}
}

func DetectMagic(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte("%PDF")):
		return "pdf"
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		return "zip"
	case bytes.HasPrefix(data, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}):
		return "ole"
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		return "pe"
	case bytes.HasPrefix(data, []byte{0x7F, 'E', 'L', 'F'}):
		return "elf"
	case len(data) >= 2 && data[0] == 0x1F && data[1] == 0x8B:
		return "gzip"
	case bytes.HasPrefix(data, []byte("Rar!")):
		return "rar"
	case bytes.HasPrefix(data, []byte("7z\xBC\xAF\x27\x1C")):
		return "7z"
	case bytes.HasPrefix(data, []byte("MSCF")):
		return "cab"
	case bytes.HasPrefix(data, []byte{0xCA, 0xFE, 0xBA, 0xBE}):
		return "class"
	default:
		return ""
	}
}

func isTextLike(data []byte) bool {
	if len(data) < 8 || DetectMagic(data) != "" {
		return false
	}

	printable := 0
	for _, b := range data {
		if b == '\t' || b == '\n' || b == '\r' || (b >= 32 && b < 127) || b >= 0x80 {
			printable++
		}
	}

	return float64(printable)/float64(len(data)) >= 0.9
}

func longestLine(data []byte) int {
	longest := 0
	current := 0
	for _, b := range data {
		if b == '\n' || b == '\r' {
			if current > longest {
				longest = current
			}
			current = 0
			continue
		}
		current++
	}
	if current > longest {
		longest = current
	}
	return longest
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type GenericAnalyzer struct {
	Options GenericOptions
}

func NewGenericAnalyzer() *GenericAnalyzer {
	return &GenericAnalyzer{Options: DefaultGenericOptions()}
}

func (a *GenericAnalyzer) Name() string { return "generic" }

func (a *GenericAnalyzer) Supports(in Input) bool {
	if isTextLike(in.Data) {
		return true
	}

	switch ScanGeneric(in, GenericOptions{SkipEmbeddedPE: true}).MagicType {
	case "elf", "gzip", "rar", "7z", "cab", "class", "ole":
		return true
	default:
		return false
	}
}

func (a *GenericAnalyzer) Analyze(in Input) (evidence.StaticAnalysis, error) {
	generic := ScanGeneric(in, a.Options)
	kind := "binary"
	if isTextLike(in.Data) {
		kind = "text"
	}

	return evidence.StaticAnalysis{Kind: kind, Generic: generic}, nil
}
