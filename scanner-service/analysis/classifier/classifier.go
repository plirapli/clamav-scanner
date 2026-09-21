package classifier

import (
	"context"

	"scanner-service/analysis/evidence"
)

type Result struct {
	Label      string             `json:"label"`
	Confidence *float64           `json:"confidence"`
	Scores     map[string]float64 `json:"scores,omitempty"`
	Model      string             `json:"model,omitempty"`
}

type Classifier interface {
	Classify(ctx context.Context, evidence evidence.FileEvidence) (Result, error)
}
