package interfaces

import "io"

type ScannerClient interface {
	Scan(reader io.Reader) error
}

type ScannerUsecase interface {
	Scan(reader io.Reader) error
}

type VirusFoundError interface {
	error
	VirusName() string
}
