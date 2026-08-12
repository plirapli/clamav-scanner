package repo

import (
	"context"
	"encoding/json"
	"log"

	"scanner-service/core/scanner/entities"
	"scanner-service/core/scanner/interfaces"
	"scanner-service/infra/kafka"
)

type scanLogPublisher struct {
	producer *kafka.Producer
}

func NewScanLogPublisher(producer *kafka.Producer) interfaces.ScanLogPublisher {
	return &scanLogPublisher{producer: producer}
}

func (r *scanLogPublisher) Publish(ctx context.Context, scanLog entities.ScanLog) error {
	data, err := json.Marshal(scanLog)
	if err != nil {
		return err
	}

	if err := r.producer.Enqueue(data); err != nil {
		log.Printf("kafka queue full, dropping scan log: %v", err)
	}

	return nil
}
