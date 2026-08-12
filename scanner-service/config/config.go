package config

import (
	"bufio"
	"os"
	"strings"
)

type Config struct {
	AppPort      string
	DatabaseDSN  string
	KafkaBrokers string
	KafkaTopic   string
	ClamAVAddr   string
	MaxScanSize  int64
}

func Load() Config {
	loadEnvFile("config/.env")

	return Config{
		AppPort:      getEnv("APP_PORT", "8080"),
		DatabaseDSN:  getEnv("DATABASE_DSN", "postgres://postgres:postgres@localhost:5432/scanner_service?sslmode=disable"),
		KafkaBrokers: getEnv("KAFKA_BROKERS", "localhost:9092"),
		KafkaTopic:   getEnv("KAFKA_TOPIC", "scan-logs"),
		ClamAVAddr:   getEnv("CLAMAV_ADDR", "127.0.0.1:3310"),
		MaxScanSize:  getEnvInt64("MAX_SCAN_SIZE", 25<<20),
	}
}

func loadEnvFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if key != "" {
			_ = os.Setenv(key, value)
		}
	}
}

func getEnv(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getEnvInt64(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	var parsed int64
	for _, char := range value {
		if char < '0' || char > '9' {
			return fallback
		}
		parsed = parsed*10 + int64(char-'0')
	}

	return parsed
}
