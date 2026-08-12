package entities

import "time"

type Application struct {
	ID        string    `json:"id"`
	AppName   string    `json:"app_name"`
	ClientID  string    `json:"client_id"`
	TokenHash string    `json:"-"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Application) TableName() string {
	return "M_APPLICATION"
}
