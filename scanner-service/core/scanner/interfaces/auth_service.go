package interfaces

import (
	"context"

	"scanner-service/core/scanner/entities"
)

type AuthService interface {
	Authenticate(ctx context.Context, clientID string, token string) (entities.Application, error)
}
