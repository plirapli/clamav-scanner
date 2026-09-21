package handler

import (
	"scanner-service/analysis/classifier"
	"scanner-service/analysis/evidence"
	"scanner-service/analysis/policy"
)

type scanFilesResponse struct {
	Files []scanFileResponse `json:"files"`
}

type scanFileResponse struct {
	Name           string                   `json:"name,omitempty"`
	Size           int64                    `json:"size,omitempty"`
	MIME           string                   `json:"mime,omitempty"`
	SHA256         string                   `json:"sha256,omitempty"`
	Status         string                   `json:"status"`
	Scan           string                   `json:"scan,omitempty"`
	Error          string                   `json:"error,omitempty"`
	Verdict        policy.Verdict           `json:"verdict,omitempty"`
	VerdictReasons []string                 `json:"verdict_reasons,omitempty"`
	Quarantined    bool                     `json:"quarantined,omitempty"`
	ClamAV         clamAVResponse           `json:"clamav"`
	StaticAnalysis *evidence.StaticAnalysis `json:"static_analysis,omitempty"`
	Classifier     *classifier.Result       `json:"classifier,omitempty"`
}

type clamAVResponse struct {
	Detected  bool   `json:"detected"`
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}
