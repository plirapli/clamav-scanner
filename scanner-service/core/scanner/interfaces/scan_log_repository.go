package interfaces

import (
	"context"
	"time"

	"scanner-service/core/scanner/entities"
)

type ScanLogPublisher interface {
	Publish(ctx context.Context, log entities.ScanLog) error
}

type ScanLogFilter struct {
	VirusName   string
	Application string
	Verdict     string
	// SortBy is a key of ScanLogSortKeys; empty means newest first.
	SortBy   string
	SortDesc bool
	Limit    int
	Skip     int
}

// ScanLogSortKeys lists the columns the scan log listing can be sorted by.
var ScanLogSortKeys = []string{
	"filename", "virus_name", "verdict", "classifier", "application",
	"source_ip", "size", "created_at",
}

// ScanLogGroup is one row of a summary breakdown: how many logs share Value
// and when the most recent one was written.
type ScanLogGroup struct {
	Value    string    `json:"value"`
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

// ScanLogSummary breaks the logs matching a filter down by ClamAV signature
// and by the application that received the upload. Logs without a signature
// are left out of VirusNames.
type ScanLogSummary struct {
	Total        int            `json:"total"`
	VirusNames   []ScanLogGroup `json:"virus_names"`
	Applications []ScanLogGroup `json:"applications"`
}

type ScanLogRepository interface {
	Insert(ctx context.Context, scanLog entities.ScanLog) error
	List(ctx context.Context, filter ScanLogFilter) ([]entities.ScanLog, int, error)
	// Summary ignores the sort and paging fields of filter.
	Summary(ctx context.Context, filter ScanLogFilter) (ScanLogSummary, error)
}
