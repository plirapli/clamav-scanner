package usecase

import (
	"io"

	"scanner-service/core/scanner/interfaces"
)

type ScannerUsecase struct {
	client interfaces.ScannerClient
}

func NewScannerUsecase(client interfaces.ScannerClient) ScannerUsecase {
	return ScannerUsecase{client: client}
}

func (u ScannerUsecase) Scan(reader io.Reader) error {
	return u.client.Scan(reader)
}
