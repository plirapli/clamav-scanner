package analyzer

import "scanner-service/analysis/evidence"

// Input is what analyzers receive: the file bytes and (sanitized) file name.
// The name matters for formats that can only be told apart by extension
// (docx vs zip, .ps1 vs text, ...).
type Input struct {
	Data []byte
	Name string
}

type Analyzer interface {
	Name() string
	Supports(in Input) bool
	Analyze(in Input) (evidence.StaticAnalysis, error)
}

// Version is stored with cached evidence. Bump it whenever the evidence format
// or analyzer heuristics change in a way that invalidates cached entries, and
// when the classifier model changes (v2: classifier.dev → Cloudflare Clef;
// v3: PE signer, import matching, binary-aware generic scan).
const Version = 3

type Registry struct {
	analyzers []Analyzer
	generic   GenericOptions
}

func NewRegistry(analyzers ...Analyzer) *Registry {
	return &Registry{analyzers: analyzers, generic: DefaultGenericOptions()}
}

// Analyze runs the first analyzer that supports the file. When no analyzer
// supports it, generic signals (embedded executables, URLs, obfuscation) are
// still extracted: files with signals are marked supported so the classifier
// can assess them, otherwise the result stays unsupported.
func (r *Registry) Analyze(in Input) evidence.StaticAnalysis {
	if r == nil {
		return evidence.StaticAnalysis{Kind: "unknown"}
	}

	for _, a := range r.analyzers {
		if !a.Supports(in) {
			continue
		}

		result, err := a.Analyze(in)
		result.Supported = true
		if result.Kind == "" {
			result.Kind = a.Name()
		}
		if err != nil {
			result.Error = err.Error()
		}

		return result
	}

	generic := ScanGeneric(in, r.generic)
	if generic.HasSignal() {
		return evidence.StaticAnalysis{Supported: true, Kind: "generic", Generic: generic}
	}

	return evidence.StaticAnalysis{Kind: "unknown", Generic: generic}
}
