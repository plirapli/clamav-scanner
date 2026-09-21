package interfaces

import (
	"context"

	"scanner-service/core/scanner/entities"
)

type ScanLogPublisher interface {
	Publish(ctx context.Context, log entities.ScanLog) error
}

type ScanLogFilter struct {
	VirusName   string
	Application string
	Verdict     string
	Limit       int
	Skip        int
}

type ScanLogRepository interface {
	Insert(ctx context.Context, scanLog entities.ScanLog) error
	List(ctx context.Context, filter ScanLogFilter) ([]entities.ScanLog, int, error)
}
