package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"scanner-service/core/scanner/entities"
	"scanner-service/core/scanner/interfaces"
)

const scanLogColumns = `id, request_id, application, source_ip, filename, mime_type, sha256,
	size, status, virus_name, scan_engine, db_version, duration_ms, created_at,
	verdict, verdict_reasons, clamav_detected, clamav_signature, analysis_supported,
	evidence_json, classifier_label, classifier_confidence, classifier_scores,
	classifier_model, classifier_error, quarantined`

// effectiveVerdict falls back to the legacy status column for rows written
// before the verdict column existed.
const effectiveVerdict = `COALESCE(NULLIF(verdict, ''), CASE WHEN status = 'infected' THEN 'BLOCK' ELSE 'ALLOW' END)`

type scanLogRepo struct {
	db *sql.DB
}

func NewScanLogRepo(db *sql.DB) interfaces.ScanLogRepository {
	return &scanLogRepo{db: db}
}

func (r *scanLogRepo) Insert(ctx context.Context, scanLog entities.ScanLog) error {
	const query = `INSERT OR IGNORE INTO scan_logs (
		request_id, application, source_ip, filename, mime_type, sha256,
		size, status, virus_name, scan_engine, db_version, duration_ms, created_at,
		verdict, verdict_reasons, clamav_detected, clamav_signature, analysis_supported,
		evidence_json, classifier_label, classifier_confidence, classifier_scores,
		classifier_model, classifier_error, quarantined
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	reasons := "[]"
	if len(scanLog.VerdictReasons) > 0 {
		if encoded, err := json.Marshal(scanLog.VerdictReasons); err == nil {
			reasons = string(encoded)
		}
	}

	evidence := ""
	if len(scanLog.Evidence) > 0 {
		evidence = string(scanLog.Evidence)
	}

	var confidence any
	if scanLog.ClassifierConfidence != nil {
		confidence = *scanLog.ClassifierConfidence
	}

	scores := ""
	if len(scanLog.ClassifierScores) > 0 {
		if encoded, err := json.Marshal(scanLog.ClassifierScores); err == nil {
			scores = string(encoded)
		}
	}

	_, err := r.db.ExecContext(
		ctx,
		query,
		scanLog.RequestID,
		scanLog.Application,
		scanLog.SourceIP,
		scanLog.Filename,
		scanLog.MIMEType,
		scanLog.SHA256,
		scanLog.Size,
		scanLog.Status,
		scanLog.VirusName,
		scanLog.ScanEngine,
		scanLog.DBVersion,
		scanLog.DurationMS,
		scanLog.CreatedAt.Format(time.RFC3339Nano),
		scanLog.Verdict,
		reasons,
		boolToInt(scanLog.ClamAVDetected),
		scanLog.ClamAVSignature,
		boolToInt(scanLog.AnalysisSupported),
		evidence,
		scanLog.ClassifierLabel,
		confidence,
		scores,
		scanLog.ClassifierModel,
		scanLog.ClassifierError,
		boolToInt(scanLog.Quarantined),
	)

	return err
}

func (r *scanLogRepo) List(ctx context.Context, filter interfaces.ScanLogFilter) ([]entities.ScanLog, int, error) {
	conditions := []string{"1 = 1"}
	args := []any{}

	if filter.VirusName != "" {
		conditions = append(conditions, "virus_name LIKE ?")
		args = append(args, "%"+filter.VirusName+"%")
	}
	if filter.Application != "" {
		conditions = append(conditions, "application = ?")
		args = append(args, filter.Application)
	}
	if filter.Verdict != "" {
		conditions = append(conditions, effectiveVerdict+" = ?")
		args = append(args, filter.Verdict)
	}

	where := strings.Join(conditions, " AND ")

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_logs WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := "SELECT " + scanLogColumns + " FROM scan_logs WHERE " + where + " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, filter.Limit, filter.Skip)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	logs := make([]entities.ScanLog, 0)
	for rows.Next() {
		scanLog, err := scanRow(rows)
		if err != nil {
			return nil, 0, err
		}
		logs = append(logs, scanLog)
	}

	return logs, total, rows.Err()
}

func scanRow(rows *sql.Rows) (entities.ScanLog, error) {
	var (
		scanLog           entities.ScanLog
		createdAt         string
		reasonsJSON       string
		evidenceJSON      string
		confidence        sql.NullFloat64
		scoresJSON        string
		clamavDetected    int
		analysisSupported int
		quarantined       int
	)

	if err := rows.Scan(
		&scanLog.ID,
		&scanLog.RequestID,
		&scanLog.Application,
		&scanLog.SourceIP,
		&scanLog.Filename,
		&scanLog.MIMEType,
		&scanLog.SHA256,
		&scanLog.Size,
		&scanLog.Status,
		&scanLog.VirusName,
		&scanLog.ScanEngine,
		&scanLog.DBVersion,
		&scanLog.DurationMS,
		&createdAt,
		&scanLog.Verdict,
		&reasonsJSON,
		&clamavDetected,
		&scanLog.ClamAVSignature,
		&analysisSupported,
		&evidenceJSON,
		&scanLog.ClassifierLabel,
		&confidence,
		&scoresJSON,
		&scanLog.ClassifierModel,
		&scanLog.ClassifierError,
		&quarantined,
	); err != nil {
		return entities.ScanLog{}, err
	}

	if parsed, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
		scanLog.CreatedAt = parsed
	}
	if reasonsJSON != "" {
		_ = json.Unmarshal([]byte(reasonsJSON), &scanLog.VerdictReasons)
	}
	if evidenceJSON != "" {
		scanLog.Evidence = json.RawMessage(evidenceJSON)
	}
	if confidence.Valid {
		value := confidence.Float64
		scanLog.ClassifierConfidence = &value
	}
	if scoresJSON != "" {
		_ = json.Unmarshal([]byte(scoresJSON), &scanLog.ClassifierScores)
	}

	scanLog.ClamAVDetected = clamavDetected != 0
	scanLog.AnalysisSupported = analysisSupported != 0
	scanLog.Quarantined = quarantined != 0

	if scanLog.Verdict == "" {
		if scanLog.Status == entities.StatusInfected {
			scanLog.Verdict = "BLOCK"
		} else {
			scanLog.Verdict = "ALLOW"
		}
	}

	return scanLog, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
