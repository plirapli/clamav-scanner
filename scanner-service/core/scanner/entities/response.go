package entities

const (
	StatusSuccess     = "success"
	StatusError       = "error"
	StatusClean       = "clean"
	StatusInfected    = "infected"
	StatusFailed      = "failed"
	StatusQuarantined = "quarantined"
	StatusBlocked     = "blocked"
)

type Response struct {
	Code      int         `json:"code"`
	Status    string      `json:"status"`
	Message   string      `json:"message"`
	RequestID string      `json:"request_id,omitempty"`
	Data      interface{} `json:"data,omitempty"`
}
