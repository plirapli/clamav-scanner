package analyzer

import "scanner-service/analysis/evidence"

type Analyzer interface {
	Name() string
	Supports(data []byte) bool
	Analyze(data []byte) (evidence.StaticAnalysis, error)
}

type Registry struct {
	analyzers []Analyzer
}

func NewRegistry(analyzers ...Analyzer) *Registry {
	return &Registry{analyzers: analyzers}
}

// Analyze runs the first analyzer that supports the file. When no analyzer
// supports the file the result is marked as unsupported instead of failing.
func (r *Registry) Analyze(data []byte) evidence.StaticAnalysis {
	if r == nil {
		return evidence.StaticAnalysis{Supported: false}
	}

	for _, a := range r.analyzers {
		if !a.Supports(data) {
			continue
		}

		result, err := a.Analyze(data)
		result.Supported = true
		if err != nil {
			return evidence.StaticAnalysis{Supported: true, Error: err.Error()}
		}

		return result
	}

	return evidence.StaticAnalysis{Supported: false}
}
