package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppPort      string
	AppName      string
	KafkaBrokers string
	KafkaTopic   string
	KafkaGroupID string
	SQLitePath   string
	ClamAVAddr   string
	MaxScanSize  int64

	ClassifierEnabled      bool
	ClassifierURL          string
	ClassifierAPIKey       string
	ClassifierTier         string
	ClassifierTimeout      time.Duration
	ClassifierLabels       []string
	ClassifierSendFilename bool

	VerdictBlockConfidence float64
	FailMode               string
	AllowUnsupported       bool
	StaticRulesEnabled     bool
	StaticRuleVerdict      string
	SuspiciousImportsMin   int64

	PackerEntropyThreshold float64
	QuarantineDir          string
	QuarantineEnabled      bool
	PublishAllVerdicts     bool

	MaxFilesPerRequest int64
}

func Load() Config {
	loadEnvFile("config/.env")

	return Config{
		AppPort:      getEnv("APP_PORT", "8080"),
		AppName:      getEnv("APP_NAME", "scanner-service"),
		KafkaBrokers: getEnv("KAFKA_BROKERS", "localhost:9092"),
		KafkaTopic:   getEnv("KAFKA_TOPIC", "scan-logs"),
		KafkaGroupID: getEnv("KAFKA_GROUP_ID", "scan-log-sqlite-writer"),
		SQLitePath:   getEnv("SQLITE_PATH", "data/scanner.db"),
		ClamAVAddr:   getEnv("CLAMAV_ADDR", "127.0.0.1:3310"),
		MaxScanSize:  getEnvInt64("MAX_SCAN_SIZE", 25<<20),

		ClassifierEnabled:      getEnvBool("CLASSIFIER_ENABLED", true),
		ClassifierURL:          getEnv("CLASSIFIER_URL", "https://classifier.dev"),
		ClassifierAPIKey:       getEnv("CLASSIFIER_API_KEY", ""),
		ClassifierTier:         getEnv("CLASSIFIER_TIER", "fast"),
		ClassifierTimeout:      getEnvDuration("CLASSIFIER_TIMEOUT", 10*time.Second),
		ClassifierLabels:       getEnvList("CLASSIFIER_LABELS", []string{"benign", "suspicious", "malicious", "insufficient-evidence"}),
		ClassifierSendFilename: getEnvBool("CLASSIFIER_SEND_FILENAME", false),

		VerdictBlockConfidence: getEnvFloat("VERDICT_BLOCK_CONFIDENCE", 0.95),
		FailMode:               getEnv("FAIL_MODE", "quarantine"),
		AllowUnsupported:       getEnvBool("ALLOW_UNSUPPORTED", true),
		StaticRulesEnabled:     getEnvBool("STATIC_RULES_ENABLED", true),
		StaticRuleVerdict:      getEnv("STATIC_RULE_VERDICT", "QUARANTINE"),
		SuspiciousImportsMin:   getEnvInt64("SUSPICIOUS_IMPORTS_MIN", 3),

		PackerEntropyThreshold: getEnvFloat("PACKER_ENTROPY_THRESHOLD", 7.2),
		QuarantineDir:          getEnv("QUARANTINE_DIR", "data/quarantine"),
		QuarantineEnabled:      getEnvBool("QUARANTINE_ENABLED", true),
		PublishAllVerdicts:     getEnvBool("PUBLISH_ALL_VERDICTS", false),

		MaxFilesPerRequest: getEnvInt64("MAX_FILES_PER_REQUEST", 10),
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

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}

	return parsed
}

func getEnvFloat(key string, fallback float64) float64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}

	return parsed
}

func getEnvBool(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch value {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return fallback
	}
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}

	return parsed
}

func getEnvList(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	items := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}

	if len(items) == 0 {
		return fallback
	}

	return items
}
