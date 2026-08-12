package service

import (
	"context"
	"errors"

	"golang.org/x/crypto/bcrypt"

	"scanner-service/core/scanner/entities"
	"scanner-service/core/scanner/interfaces"
)

var ErrInvalidClient = errors.New("invalid client credentials")

type authService struct {
	repo interfaces.ApplicationRepository
}

func NewAuthService(repo interfaces.ApplicationRepository) interfaces.AuthService {
	return &authService{repo: repo}
}

func (s *authService) Authenticate(ctx context.Context, clientID string, token string) (entities.Application, error) {
	application, err := s.repo.GetByClientID(ctx, clientID)
	if err != nil {
		return entities.Application{}, err
	}
	if application.TokenHash == "" || !application.IsActive {
		return entities.Application{}, ErrInvalidClient
	}

	if err := bcrypt.CompareHashAndPassword([]byte(application.TokenHash), []byte(token)); err != nil {
		return entities.Application{}, ErrInvalidClient
	}

	return application, nil
}
