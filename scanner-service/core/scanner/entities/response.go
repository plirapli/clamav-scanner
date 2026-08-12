package entities

const (
	StatusSuccess  = "success"
	StatusError    = "error"
	StatusClean    = "clean"
	StatusInfected = "infected"
	StatusFailed   = "failed"
)

type Response struct {
	Code    int         `json:"code"`
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type ScanResult struct {
	Files []FileResult `json:"files,omitempty"`
}

type FileResult struct {
	Name   string `json:"name,omitempty"`
	Status string `json:"status"`
	Scan   string `json:"scan,omitempty"`
	Error  string `json:"error,omitempty"`
}
