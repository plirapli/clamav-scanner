package repo

import (
	"context"

	"gorm.io/gorm"

	"scanner-service/core/scanner/entities"
	"scanner-service/core/scanner/interfaces"
)

type applicationRepo struct {
	db *gorm.DB
}

func NewApplicationRepo(db *gorm.DB) interfaces.ApplicationRepository {
	return &applicationRepo{db: db}
}

func (r *applicationRepo) GetByClientID(ctx context.Context, clientID string) (entities.Application, error) {
	var application entities.Application
	err := r.db.WithContext(ctx).
		Table("M_APPLICATION").
		Where("client_id = ?", clientID).
		Limit(1).
		Scan(&application).
		Error

	return application, err
}
