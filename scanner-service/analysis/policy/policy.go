package policy

import (
	"errors"
	"fmt"
	"strings"

	"scanner-service/analysis/classifier"
	"scanner-service/analysis/evidence"
)

type Verdict string

const (
	Allow      Verdict = "ALLOW"
	Quarantine Verdict = "QUARANTINE"
	Block      Verdict = "BLOCK"
)

var ErrUnknownVerdict = errors.New("unknown verdict")

func ParseVerdict(value string) (Verdict, error) {
	switch Verdict(value) {
	case Allow:
		return Allow, nil
	case Quarantine:
		return Quarantine, nil
	case Block:
		return Block, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownVerdict, value)
	}
}

func (v Verdict) severity() int {
	switch v {
	case Block:
		return 3
	case Quarantine:
		return 2
	default:
		return 1
	}
}

type Config struct {
	BlockConfidence      float64
	FailMode             Verdict
	AllowUnsupported     bool
	StaticRulesEnabled   bool
	StaticRuleVerdict    Verdict
	SuspiciousImportsMin int
	GenericRulesEnabled  bool
	EncryptedVerdict     Verdict
}

type Input struct {
	ClamAVDetected  bool
	ClamAVSignature string
	ClamAVError     string

	Analysis evidence.StaticAnalysis

	Classifier      *classifier.Result
	ClassifierError string
}

type Decision struct {
	Verdict Verdict
	Reasons []string
}

// Decide combines independent signals into a single deterministic verdict.
// Each signal can escalate the verdict; none can downgrade it.
func Decide(in Input, cfg Config) Decision {
	if in.ClamAVDetected {
		signature := in.ClamAVSignature
		if signature == "" {
			signature = "unknown"
		}

		if isEncryptedHeuristic(signature) {
			return Decision{
				Verdict: encryptedVerdict(cfg),
				Reasons: []string{"clamav heuristic: " + signature},
			}
		}

		return Decision{Verdict: Block, Reasons: []string{"clamav: detected (" + signature + ")"}}
	}

	if in.ClamAVError != "" {
		return Decision{Verdict: failVerdict(cfg), Reasons: []string{"clamav error: " + in.ClamAVError}}
	}

	decision := Decision{Verdict: Allow, Reasons: []string{}}

	escalate := func(verdict Verdict, reason string) {
		if verdict.severity() > decision.Verdict.severity() {
			decision.Verdict = verdict
		}
		decision.Reasons = append(decision.Reasons, reason)
	}

	if !in.Analysis.Supported {
		if cfg.AllowUnsupported {
			decision.Reasons = append(decision.Reasons, "analysis skipped (unsupported type)")
		} else {
			escalate(Quarantine, "analysis skipped (unsupported type)")
		}
	} else if in.Analysis.Error != "" {
		escalate(Quarantine, "analysis error: "+in.Analysis.Error)
	}

	if in.Analysis.Supported && in.Analysis.Error == "" {
		switch {
		case in.ClassifierError != "":
			escalate(failVerdict(cfg), "classifier error: "+in.ClassifierError)
		case in.Classifier == nil:
			decision.Reasons = append(decision.Reasons, "classifier disabled")
		default:
			escalate(classifierVerdict(*in.Classifier, cfg), classifierReason(*in.Classifier))
		}
	}

	if cfg.StaticRulesEnabled && in.Analysis.Supported && in.Analysis.Error == "" {
		if in.Analysis.HasPackedSection && !in.Analysis.HasDigitalSignature {
			escalate(cfg.StaticRuleVerdict, "static rule: packed and unsigned")
		}
		if cfg.SuspiciousImportsMin > 0 &&
			len(in.Analysis.SuspiciousImports) >= cfg.SuspiciousImportsMin &&
			!in.Analysis.HasDigitalSignature {
			escalate(cfg.StaticRuleVerdict, fmt.Sprintf(
				"static rule: %d suspicious imports and unsigned",
				len(in.Analysis.SuspiciousImports),
			))
		}
	}

	if cfg.GenericRulesEnabled {
		generic := in.Analysis.Generic
		if generic.Encrypted {
			escalate(encryptedVerdict(cfg), "static rule: encrypted or password-protected file")
		}
		if generic.EmbeddedPE {
			escalate(cfg.StaticRuleVerdict, "static rule: embedded executable")
		}
		if generic.HasJavaScript && generic.AutoExec {
			escalate(cfg.StaticRuleVerdict, "static rule: active content with auto-open")
		}
		if generic.HasMacros && len(generic.ExternalTargets) > 0 {
			escalate(cfg.StaticRuleVerdict, "static rule: macros with external targets")
		}
		if len(generic.NestedExecutables) > 0 {
			escalate(cfg.StaticRuleVerdict, "static rule: archive contains executable")
		}
		if hasObfuscatedScript(generic) {
			escalate(cfg.StaticRuleVerdict, "static rule: obfuscated script")
		}
	}

	return decision
}

func hasObfuscatedScript(g evidence.GenericEvidence) bool {
	if len(g.ObfuscationHints) == 0 {
		return false
	}

	for _, value := range g.SuspiciousStrings {
		switch value {
		case "eval", "Invoke-Expression", "-EncodedCommand", "FromBase64String":
			return true
		}
	}

	return false
}

func failVerdict(cfg Config) Verdict {
	if cfg.FailMode == Allow {
		return Allow
	}
	return Quarantine
}

// encryptedVerdict returns the configured verdict for encrypted files. The
// default is QUARANTINE: password-protected archives are common in legitimate
// workflows and should be reviewed rather than blocked outright.
func encryptedVerdict(cfg Config) Verdict {
	switch cfg.EncryptedVerdict {
	case Allow, Quarantine, Block:
		return cfg.EncryptedVerdict
	default:
		return Quarantine
	}
}

func isEncryptedHeuristic(signature string) bool {
	return strings.HasPrefix(strings.ToLower(signature), "heuristics.encrypted")
}

func classifierVerdict(result classifier.Result, cfg Config) Verdict {
	if result.Confidence == nil {
		return Quarantine
	}

	switch result.Label {
	case "benign":
		return Allow
	case "malicious":
		if *result.Confidence >= cfg.BlockConfidence {
			return Block
		}
		return Quarantine
	case "suspicious", "insufficient-evidence":
		return Quarantine
	default:
		return Quarantine
	}
}

func classifierReason(result classifier.Result) string {
	if result.Confidence == nil {
		return fmt.Sprintf("classifier: %s (unscored)", result.Label)
	}
	return fmt.Sprintf("classifier: %s (%.2f)", result.Label, *result.Confidence)
}
