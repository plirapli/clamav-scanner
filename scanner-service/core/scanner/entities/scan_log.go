package entities

import "time"

type ScanLog struct {
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
}
