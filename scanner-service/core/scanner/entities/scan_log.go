package entities

import (
	"encoding/json"
	"time"
)

type ScanLog struct {
	ID          int64     `bson:"id,omitempty" json:"id,omitempty"`
	RequestID   string    `bson:"request_id" json:"request_id"`
	Application string    `bson:"application" json:"application"`
	SourceIP    string    `bson:"source_ip" json:"source_ip"`
	Filename    string    `bson:"filename" json:"filename"`
	SHA256      string    `bson:"sha256" json:"sha256"`
	MIMEType    string    `bson:"mime_type" json:"mime_type"`
	Size        int64     `bson:"size" json:"size"`
	Status      string    `bson:"status" json:"status"`
	VirusName   string    `bson:"virus_name" json:"virus_name"`
	ScanEngine  string    `bson:"scan_engine" json:"scan_engine"`
	DBVersion   int64     `bson:"db_version" json:"db_version"`
	DurationMS  int64     `bson:"duration_ms" json:"duration_ms"`
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`

	Verdict              string             `bson:"verdict,omitempty" json:"verdict,omitempty"`
	VerdictReasons       []string           `bson:"verdict_reasons,omitempty" json:"verdict_reasons,omitempty"`
	ClamAVDetected       bool               `bson:"clamav_detected" json:"clamav_detected"`
	ClamAVSignature      string             `bson:"clamav_signature,omitempty" json:"clamav_signature,omitempty"`
	AnalysisSupported    bool               `bson:"analysis_supported" json:"analysis_supported"`
	Evidence             json.RawMessage    `bson:"evidence,omitempty" json:"evidence,omitempty"`
	ClassifierLabel      string             `bson:"classifier_label,omitempty" json:"classifier_label,omitempty"`
	ClassifierConfidence *float64           `bson:"classifier_confidence,omitempty" json:"classifier_confidence,omitempty"`
	ClassifierScores     map[string]float64 `bson:"classifier_scores,omitempty" json:"classifier_scores,omitempty"`
	ClassifierModel      string             `bson:"classifier_model,omitempty" json:"classifier_model,omitempty"`
	ClassifierError      string             `bson:"classifier_error,omitempty" json:"classifier_error,omitempty"`
	Quarantined          bool               `bson:"quarantined" json:"quarantined"`
}
