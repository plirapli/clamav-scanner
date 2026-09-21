package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	kafkago "github.com/segmentio/kafka-go"

	"scanner-service/app/scanner/repo"
	"scanner-service/config"
	"scanner-service/core/scanner/entities"
	"scanner-service/infra/sqlite"
)

func main() {
	cfg := config.Load()

	db, err := sqlite.Open(cfg.SQLitePath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	scanLogRepo := repo.NewScanLogRepo(db)

	reader := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers:     strings.Split(cfg.KafkaBrokers, ","),
		GroupID:     cfg.KafkaGroupID,
		Topic:       cfg.KafkaTopic,
		StartOffset: kafkago.FirstOffset,
	})
	defer reader.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("logwriter started topic=%s group=%s sqlite=%s", cfg.KafkaTopic, cfg.KafkaGroupID, cfg.SQLitePath)

	for {
		message, err := reader.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				log.Print("logwriter stopped")
				return
			}
			log.Printf("read failed: %v", err)
			continue
		}

		var scanLog entities.ScanLog
		if err := json.Unmarshal(message.Value, &scanLog); err != nil {
			log.Printf("skip invalid message offset=%d: %v", message.Offset, err)
			continue
		}

		if err := scanLogRepo.Insert(ctx, scanLog); err != nil {
			log.Printf("insert failed offset=%d: %v", message.Offset, err)
			continue
		}

		log.Printf("saved filename=%q virus=%q offset=%d", scanLog.Filename, scanLog.VirusName, message.Offset)
	}
}
