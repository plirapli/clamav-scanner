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
	ClassifierBaseURL      string
	ClassifierAccountID    string
	ClassifierAPIToken     string
	ClassifierModel        string
	ClassifierTimeout      time.Duration
	ClassifierLabels       []string
	ClassifierSendFilename bool

	VerdictBlockConfidence float64
	FailMode               string
	AllowUnsupported       bool
	StaticRulesEnabled     bool
	StaticRuleVerdict      string
	SuspiciousImportsMin   int64
	GenericRulesEnabled    bool
	EncryptedVerdict       string

	PackerEntropyThreshold float64
	QuarantineDir          string
	QuarantineEnabled      bool
	PublishAllVerdicts     bool

	CacheEnabled    bool
	CacheTTL        time.Duration
	CacheErrorTTL   time.Duration
	CacheMaxEntries int64

	MaxFilesPerRequest int64

	EvalResultsDir string
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
		ClassifierBaseURL:      getEnv("CLASSIFIER_BASE_URL", "https://api.cloudflare.com/client/v4"),
		ClassifierAccountID:    getEnv("CLOUDFLARE_ACCOUNT_ID", ""),
		ClassifierAPIToken:     getEnv("CLOUDFLARE_API_TOKEN", ""),
		ClassifierModel:        getEnv("CLASSIFIER_MODEL", "clef"),
		ClassifierTimeout:      getEnvDuration("CLASSIFIER_TIMEOUT", 30*time.Second),
		ClassifierLabels:       getEnvList("CLASSIFIER_LABELS", []string{"benign", "suspicious", "malicious", "insufficient-evidence"}),
		ClassifierSendFilename: getEnvBool("CLASSIFIER_SEND_FILENAME", false),

		VerdictBlockConfidence: getEnvFloat("VERDICT_BLOCK_CONFIDENCE", 0.95),
		FailMode:               getEnv("FAIL_MODE", "quarantine"),
		AllowUnsupported:       getEnvBool("ALLOW_UNSUPPORTED", true),
		StaticRulesEnabled:     getEnvBool("STATIC_RULES_ENABLED", true),
		StaticRuleVerdict:      getEnv("STATIC_RULE_VERDICT", "QUARANTINE"),
		SuspiciousImportsMin:   getEnvInt64("SUSPICIOUS_IMPORTS_MIN", 3),
		GenericRulesEnabled:    getEnvBool("GENERIC_RULES_ENABLED", true),
		EncryptedVerdict:       getEnv("ENCRYPTED_VERDICT", "QUARANTINE"),

		PackerEntropyThreshold: getEnvFloat("PACKER_ENTROPY_THRESHOLD", 7.2),
		QuarantineDir:          getEnv("QUARANTINE_DIR", "data/quarantine"),
		QuarantineEnabled:      getEnvBool("QUARANTINE_ENABLED", true),
		PublishAllVerdicts:     getEnvBool("PUBLISH_ALL_VERDICTS", false),

		CacheEnabled:    getEnvBool("CACHE_ENABLED", true),
		CacheTTL:        getEnvDuration("CACHE_TTL", 168*time.Hour),
		CacheErrorTTL:   getEnvDuration("CACHE_ERROR_TTL", 15*time.Minute),
		CacheMaxEntries: getEnvInt64("CACHE_MAX_ENTRIES", 100000),

		MaxFilesPerRequest: getEnvInt64("MAX_FILES_PER_REQUEST", 10),

		EvalResultsDir: getEnv("EVAL_RESULTS_DIR", "../eval/results"),
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
	if err != nil || parsed < 0 {
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
