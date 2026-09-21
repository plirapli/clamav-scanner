package policy

import (
	"testing"

	"scanner-service/analysis/classifier"
	"scanner-service/analysis/evidence"
)

func confidence(value float64) *float64 {
	return &value
}

func baseConfig() Config {
	return Config{
		BlockConfidence:      0.95,
		FailMode:             Quarantine,
		AllowUnsupported:     true,
		StaticRulesEnabled:   true,
		StaticRuleVerdict:    Quarantine,
		SuspiciousImportsMin: 3,
	}
}

func TestDecide(t *testing.T) {
	supported := evidence.StaticAnalysis{Supported: true}
	packed := evidence.StaticAnalysis{Supported: true, HasPackedSection: true}
	packedSigned := evidence.StaticAnalysis{Supported: true, HasPackedSection: true, HasDigitalSignature: true}
	imports := evidence.StaticAnalysis{Supported: true, SuspiciousImports: []string{"a", "b", "c"}}
	twoImports := evidence.StaticAnalysis{Supported: true, SuspiciousImports: []string{"a", "b"}}

	benign := &classifier.Result{Label: "benign", Confidence: confidence(0.99)}
	suspicious := &classifier.Result{Label: "suspicious", Confidence: confidence(0.91)}
	maliciousHigh := &classifier.Result{Label: "malicious", Confidence: confidence(0.97)}
	maliciousLow := &classifier.Result{Label: "malicious", Confidence: confidence(0.80)}
	unscored := &classifier.Result{Label: "malicious", Confidence: nil}
	insufficient := &classifier.Result{Label: "insufficient-evidence", Confidence: confidence(0.60)}
	unknown := &classifier.Result{Label: "weird", Confidence: confidence(0.99)}

	tests := []struct {
		name string
		in   Input
		cfg  Config
		want Verdict
	}{
		{"clamav detected", Input{ClamAVDetected: true, ClamAVSignature: "Eicar"}, baseConfig(), Block},
		{"clamav error fail closed", Input{ClamAVError: "timeout"}, baseConfig(), Quarantine},
		{"clamav error fail open", Input{ClamAVError: "timeout"}, Config{FailMode: Allow, AllowUnsupported: true}, Allow},
		{"unsupported allowed", Input{Analysis: evidence.StaticAnalysis{}}, baseConfig(), Allow},
		{"unsupported quarantined", Input{Analysis: evidence.StaticAnalysis{}}, Config{AllowUnsupported: false}, Quarantine},
		{"analysis error", Input{Analysis: evidence.StaticAnalysis{Supported: true, Error: "boom"}}, baseConfig(), Quarantine},
		{"classifier benign", Input{Analysis: supported, Classifier: benign}, baseConfig(), Allow},
		{"classifier malicious high confidence", Input{Analysis: supported, Classifier: maliciousHigh}, baseConfig(), Block},
		{"classifier malicious low confidence", Input{Analysis: supported, Classifier: maliciousLow}, baseConfig(), Quarantine},
		{"classifier suspicious", Input{Analysis: supported, Classifier: suspicious}, baseConfig(), Quarantine},
		{"classifier insufficient evidence", Input{Analysis: supported, Classifier: insufficient}, baseConfig(), Quarantine},
		{"classifier unscored", Input{Analysis: supported, Classifier: unscored}, baseConfig(), Quarantine},
		{"classifier unknown label", Input{Analysis: supported, Classifier: unknown}, baseConfig(), Quarantine},
		{"classifier error", Input{Analysis: supported, ClassifierError: "boom"}, baseConfig(), Quarantine},
		{"classifier disabled", Input{Analysis: supported}, baseConfig(), Allow},
		{"static rule packed unsigned", Input{Analysis: packed, Classifier: benign}, baseConfig(), Quarantine},
		{"static rule signed skips", Input{Analysis: packedSigned, Classifier: benign}, baseConfig(), Allow},
		{"static rule imports", Input{Analysis: imports, Classifier: benign}, baseConfig(), Quarantine},
		{"static rule imports below min", Input{Analysis: twoImports, Classifier: benign}, baseConfig(), Allow},
		{"static rule cannot downgrade", Input{Analysis: packed, Classifier: maliciousHigh}, baseConfig(), Block},
		{"static rules disabled", Input{Analysis: packed, Classifier: benign}, Config{BlockConfidence: 0.95, StaticRulesEnabled: false, AllowUnsupported: true}, Allow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := Decide(tt.in, tt.cfg)
			if decision.Verdict != tt.want {
				t.Fatalf("verdict = %s, want %s (reasons: %v)", decision.Verdict, tt.want, decision.Reasons)
			}
			if len(decision.Reasons) == 0 {
				t.Fatal("expected at least one reason")
			}
		})
	}
}

func TestParseVerdict(t *testing.T) {
	if _, err := ParseVerdict("NOPE"); err == nil {
		t.Fatal("expected error for unknown verdict")
	}
	if verdict, err := ParseVerdict("BLOCK"); err != nil || verdict != Block {
		t.Fatalf("unexpected result: %v %v", verdict, err)
	}
}
