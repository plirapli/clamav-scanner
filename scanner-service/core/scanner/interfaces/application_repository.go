package interfaces

import (
	"context"

	"scanner-service/core/scanner/entities"
)

type ApplicationRepository interface {
	GetByClientID(ctx context.Context, clientID string) (entities.Application, error)
}
