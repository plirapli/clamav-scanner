package interfaces

import (
	"context"

	"scanner-service/core/scanner/entities"
)

type ScanLogPublisher interface {
	Publish(ctx context.Context, log entities.ScanLog) error
}
