package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"scanner-service/analysis/classifier"
	"scanner-service/core/scanner/entities"
	"scanner-service/core/scanner/interfaces"
)

type scanCacheRepo struct {
	db *sql.DB
}

func NewScanCacheRepo(db *sql.DB) interfaces.ScanCacheRepository {
	return &scanCacheRepo{db: db}
}

func (r *scanCacheRepo) Lookup(
	ctx context.Context,
	sha256 string,
	size int64,
	maxAge time.Duration,
	errorMaxAge time.Duration,
	analyzerVersion int,
) (entities.CachedScan, bool, error) {
	const query = `SELECT sha256, size, analyzer_version, analysis_supported, evidence_json,
		classifier_label, classifier_confidence, classifier_scores, classifier_model,
		classifier_error, first_seen_at, last_seen_at, hits
		FROM scan_cache WHERE sha256 = ? AND size = ? AND analyzer_version = ?`

	var (
		entry             entities.CachedScan
		analysisSupported int
		evidenceJSON      string
		label             string
		confidence        sql.NullFloat64
		scoresJSON        string
		model             string
		firstSeen         string
		lastSeen          string
	)

	err := r.db.QueryRowContext(ctx, query, sha256, size, analyzerVersion).Scan(
		&entry.SHA256,
		&entry.Size,
		&entry.AnalyzerVersion,
		&analysisSupported,
		&evidenceJSON,
		&label,
		&confidence,
		&scoresJSON,
		&model,
		&entry.ClassifierError,
		&firstSeen,
		&lastSeen,
		&entry.Hits,
	)
	if err == sql.ErrNoRows {
		return entities.CachedScan{}, false, nil
	}
	if err != nil {
		return entities.CachedScan{}, false, err
	}

	if parsed, err := time.Parse(time.RFC3339Nano, firstSeen); err == nil {
		entry.FirstSeenAt = parsed
	}
	if parsed, err := time.Parse(time.RFC3339Nano, lastSeen); err == nil {
		entry.LastSeenAt = parsed
	}

	now := time.Now()
	if maxAge > 0 && now.Sub(entry.LastSeenAt) > maxAge {
		return entities.CachedScan{}, false, nil
	}
	if entry.ClassifierError != "" && errorMaxAge > 0 && now.Sub(entry.LastSeenAt) > errorMaxAge {
		return entities.CachedScan{}, false, nil
	}

	if evidenceJSON != "" {
		_ = json.Unmarshal([]byte(evidenceJSON), &entry.Analysis)
	}
	if label != "" || model != "" {
		result := &classifier.Result{Label: label, Model: model}
		if confidence.Valid {
			value := confidence.Float64
			result.Confidence = &value
		}
		if scoresJSON != "" {
			_ = json.Unmarshal([]byte(scoresJSON), &result.Scores)
		}
		entry.Classifier = result
	}

	if _, err := r.db.ExecContext(
		ctx,
		"UPDATE scan_cache SET hits = hits + 1, last_seen_at = ? WHERE sha256 = ?",
		now.Format(time.RFC3339Nano),
		sha256,
	); err != nil {
		return entities.CachedScan{}, false, err
	}

	return entry, true, nil
}

func (r *scanCacheRepo) Store(ctx context.Context, entry entities.CachedScan) error {
	const query = `INSERT INTO scan_cache (
		sha256, size, analyzer_version, analysis_supported, evidence_json,
		classifier_label, classifier_confidence, classifier_scores, classifier_model,
		classifier_error, first_seen_at, last_seen_at, hits
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(sha256) DO UPDATE SET
		size = excluded.size,
		analyzer_version = excluded.analyzer_version,
		analysis_supported = excluded.analysis_supported,
		evidence_json = excluded.evidence_json,
		classifier_label = excluded.classifier_label,
		classifier_confidence = excluded.classifier_confidence,
		classifier_scores = excluded.classifier_scores,
		classifier_model = excluded.classifier_model,
		classifier_error = excluded.classifier_error,
		last_seen_at = excluded.last_seen_at`

	evidenceJSON := ""
	if encoded, err := json.Marshal(entry.Analysis); err == nil {
		evidenceJSON = string(encoded)
	}

	var confidence any
	var label, model, scores string
	if entry.Classifier != nil {
		label = entry.Classifier.Label
		model = entry.Classifier.Model
		if entry.Classifier.Confidence != nil {
			confidence = *entry.Classifier.Confidence
		}
		if len(entry.Classifier.Scores) > 0 {
			if encoded, err := json.Marshal(entry.Classifier.Scores); err == nil {
				scores = string(encoded)
			}
		}
	}

	now := time.Now()
	firstSeen := entry.FirstSeenAt
	if firstSeen.IsZero() {
		firstSeen = now
	}

	_, err := r.db.ExecContext(
		ctx,
		query,
		entry.SHA256,
		entry.Size,
		entry.AnalyzerVersion,
		boolToInt(entry.Analysis.Supported),
		evidenceJSON,
		label,
		confidence,
		scores,
		model,
		entry.ClassifierError,
		firstSeen.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
		entry.Hits,
	)

	return err
}

func (r *scanCacheRepo) Prune(ctx context.Context, maxEntries int, maxAge time.Duration) error {
	if maxAge > 0 {
		cutoff := time.Now().Add(-maxAge).Format(time.RFC3339Nano)
		if _, err := r.db.ExecContext(ctx, "DELETE FROM scan_cache WHERE last_seen_at < ?", cutoff); err != nil {
			return err
		}
	}

	if maxEntries <= 0 {
		return nil
	}

	var count int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_cache").Scan(&count); err != nil {
		return err
	}
	if count <= maxEntries {
		return nil
	}

	excess := count - maxEntries
	_, err := r.db.ExecContext(
		ctx,
		`DELETE FROM scan_cache WHERE sha256 IN (
			SELECT sha256 FROM scan_cache ORDER BY last_seen_at ASC LIMIT ?
		)`,
		excess,
	)

	return err
}
