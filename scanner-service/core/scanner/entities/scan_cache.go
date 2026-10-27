package entities

import (
	"time"

	"scanner-service/analysis/classifier"
	"scanner-service/analysis/evidence"
)

type CachedScan struct {
	SHA256          string
	Size            int64
	AnalyzerVersion int

	Analysis        evidence.StaticAnalysis
	Classifier      *classifier.Result
	ClassifierError string

	FirstSeenAt time.Time
	LastSeenAt  time.Time
	Hits        int64
}
