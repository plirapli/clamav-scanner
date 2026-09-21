package sqlite

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

const dsnTemplate = "file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"

const createTable = `CREATE TABLE IF NOT EXISTS scan_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_id TEXT NOT NULL,
		application TEXT NOT NULL DEFAULT '',
		source_ip TEXT NOT NULL DEFAULT '',
		filename TEXT NOT NULL DEFAULT '',
		mime_type TEXT NOT NULL DEFAULT '',
		sha256 TEXT NOT NULL DEFAULT '',
		size INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL,
		virus_name TEXT NOT NULL DEFAULT '',
		scan_engine TEXT NOT NULL DEFAULT '',
		db_version INTEGER NOT NULL DEFAULT 0,
		duration_ms INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL,
		verdict TEXT NOT NULL DEFAULT '',
		verdict_reasons TEXT NOT NULL DEFAULT '[]',
		clamav_detected INTEGER NOT NULL DEFAULT 0,
		clamav_signature TEXT NOT NULL DEFAULT '',
		analysis_supported INTEGER NOT NULL DEFAULT 0,
		evidence_json TEXT NOT NULL DEFAULT '',
		classifier_label TEXT NOT NULL DEFAULT '',
		classifier_confidence REAL,
		classifier_scores TEXT NOT NULL DEFAULT '',
		classifier_model TEXT NOT NULL DEFAULT '',
		classifier_error TEXT NOT NULL DEFAULT '',
		quarantined INTEGER NOT NULL DEFAULT 0
	)`

var indexStatements = []string{
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_logs_dedup ON scan_logs(request_id, filename, sha256)`,
	`CREATE INDEX IF NOT EXISTS idx_scan_logs_created_at ON scan_logs(created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_scan_logs_virus_name ON scan_logs(virus_name)`,
	`CREATE INDEX IF NOT EXISTS idx_scan_logs_application ON scan_logs(application)`,
	`CREATE INDEX IF NOT EXISTS idx_scan_logs_verdict ON scan_logs(verdict)`,
}

// addedColumns keeps existing databases in sync with the schema above.
var addedColumns = []struct {
	name string
	ddl  string
}{
	{"verdict", "ALTER TABLE scan_logs ADD COLUMN verdict TEXT NOT NULL DEFAULT ''"},
	{"verdict_reasons", "ALTER TABLE scan_logs ADD COLUMN verdict_reasons TEXT NOT NULL DEFAULT '[]'"},
	{"clamav_detected", "ALTER TABLE scan_logs ADD COLUMN clamav_detected INTEGER NOT NULL DEFAULT 0"},
	{"clamav_signature", "ALTER TABLE scan_logs ADD COLUMN clamav_signature TEXT NOT NULL DEFAULT ''"},
	{"analysis_supported", "ALTER TABLE scan_logs ADD COLUMN analysis_supported INTEGER NOT NULL DEFAULT 0"},
	{"evidence_json", "ALTER TABLE scan_logs ADD COLUMN evidence_json TEXT NOT NULL DEFAULT ''"},
	{"classifier_label", "ALTER TABLE scan_logs ADD COLUMN classifier_label TEXT NOT NULL DEFAULT ''"},
	{"classifier_confidence", "ALTER TABLE scan_logs ADD COLUMN classifier_confidence REAL"},
	{"classifier_scores", "ALTER TABLE scan_logs ADD COLUMN classifier_scores TEXT NOT NULL DEFAULT ''"},
	{"classifier_model", "ALTER TABLE scan_logs ADD COLUMN classifier_model TEXT NOT NULL DEFAULT ''"},
	{"classifier_error", "ALTER TABLE scan_logs ADD COLUMN classifier_error TEXT NOT NULL DEFAULT ''"},
	{"quarantined", "ALTER TABLE scan_logs ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0"},
}

func Open(path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}

	db, err := sql.Open("sqlite", fmt.Sprintf(dsnTemplate, path))
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(createTable); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	for _, statement := range indexStatements {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, err
		}
	}

	return db, nil
}

func migrate(db *sql.DB) error {
	existing, err := columns(db, "scan_logs")
	if err != nil {
		return err
	}

	for _, column := range addedColumns {
		if existing[column.name] {
			continue
		}
		if _, err := db.Exec(column.ddl); err != nil {
			return err
		}
	}

	return nil
}

func columns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]bool)
	for rows.Next() {
		var (
			cid        int
			name       string
			column     string
			notNull    int
			defaultV   sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &column, &notNull, &defaultV, &primaryKey); err != nil {
			return nil, err
		}
		result[name] = true
	}

	return result, rows.Err()
}
