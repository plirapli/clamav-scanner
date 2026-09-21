package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v2"

	"scanner-service/analysis/analyzer"
	"scanner-service/analysis/classifier"
	"scanner-service/analysis/evidence"
	"scanner-service/analysis/policy"
	"scanner-service/core/scanner/entities"
	"scanner-service/core/scanner/interfaces"
	"scanner-service/infra/quarantine"
)

const defaultMaxFilesPerRequest = 10

type ScannerHandler struct {
	usecase            interfaces.ScannerUsecase
	scanLog            interfaces.ScanLogPublisher
	engine             ScannerEngine
	appName            string
	analyzer           *analyzer.Registry
	classifier         classifier.Classifier
	classifierTimeout  time.Duration
	policyCfg          policy.Config
	quarantine         *quarantine.Store
	publishAllVerdicts bool
	maxFilesPerRequest int
}

type ScannerEngine interface {
	Version() (int64, error)
}

type ScannerHandlerDeps struct {
	Usecase            interfaces.ScannerUsecase
	ScanLog            interfaces.ScanLogPublisher
	Engine             ScannerEngine
	AppName            string
	Analyzer           *analyzer.Registry
	Classifier         classifier.Classifier
	ClassifierTimeout  time.Duration
	Policy             policy.Config
	Quarantine         *quarantine.Store
	PublishAllVerdicts bool
	MaxFilesPerRequest int
}

func NewScannerHandler(deps ScannerHandlerDeps) ScannerHandler {
	maxFiles := deps.MaxFilesPerRequest
	if maxFiles <= 0 {
		maxFiles = defaultMaxFilesPerRequest
	}

	return ScannerHandler{
		usecase:            deps.Usecase,
		scanLog:            deps.ScanLog,
		engine:             deps.Engine,
		appName:            deps.AppName,
		analyzer:           deps.Analyzer,
		classifier:         deps.Classifier,
		classifierTimeout:  deps.ClassifierTimeout,
		policyCfg:          deps.Policy,
		quarantine:         deps.Quarantine,
		publishAllVerdicts: deps.PublishAllVerdicts,
		maxFilesPerRequest: maxFiles,
	}
}

func (h ScannerHandler) Scan(c *fiber.Ctx) error {
	targets, err := h.scanTargets(c)
	if err != nil {
		return writeError(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	requestID := c.Get(fiber.HeaderXRequestID)
	if requestID == "" {
		requestID = randomID()
	}

	files := make([]scanFileResponse, 0, len(targets))
	for _, target := range targets {
		files = append(files, h.process(c, requestID, target))
	}

	return c.Status(fiber.StatusOK).JSON(entities.Response{
		Code:      fiber.StatusOK,
		Status:    entities.StatusSuccess,
		Message:   "scan completed",
		RequestID: requestID,
		Data:      scanFilesResponse{Files: files},
	})
}

func (h ScannerHandler) process(c *fiber.Ctx, requestID string, target scanTarget) scanFileResponse {
	start := time.Now()
	data := target.data

	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])

	result := scanFileResponse{
		Name:   target.name,
		Size:   int64(len(data)),
		MIME:   target.mime,
		SHA256: sha,
	}

	clamResult := evidence.ClamAVInfo{}
	scanErr := h.usecase.Scan(bytes.NewReader(data))

	var virusErr interfaces.VirusFoundError
	switch {
	case scanErr == nil:
	case errors.As(scanErr, &virusErr):
		clamResult.Detected = true
		clamResult.Signature = virusErr.VirusName()
	default:
		clamResult.Error = scanErr.Error()
	}

	staticAnalysis := evidence.StaticAnalysis{Supported: false}
	var classification *classifier.Result
	classifierErr := ""

	if !clamResult.Detected && clamResult.Error == "" {
		staticAnalysis = h.analyzer.Analyze(data)

		if h.classifier != nil && staticAnalysis.Supported && staticAnalysis.Error == "" {
			fileEvidence := evidence.FileEvidence{
				File: evidence.FileInfo{
					Name:   target.name,
					Size:   int64(len(data)),
					MIME:   target.mime,
					SHA256: sha,
				},
				ClamAV:         clamResult,
				StaticAnalysis: staticAnalysis,
			}

			ctx := c.UserContext()
			if h.classifierTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, h.classifierTimeout)
				defer cancel()
			}

			classified, err := h.classifier.Classify(ctx, fileEvidence)
			if err != nil {
				classifierErr = err.Error()
			} else {
				classification = &classified
			}
		}
	}

	decision := policy.Decide(policy.Input{
		ClamAVDetected:  clamResult.Detected,
		ClamAVSignature: clamResult.Signature,
		ClamAVError:     clamResult.Error,
		Analysis:        staticAnalysis,
		Classifier:      classification,
		ClassifierError: classifierErr,
	}, h.policyCfg)

	duration := time.Since(start).Milliseconds()

	result.ClamAV = clamAVResponse{
		Detected:  clamResult.Detected,
		Signature: clamResult.Signature,
		Error:     clamResult.Error,
	}
	if clamResult.Detected {
		result.Scan = clamResult.Signature
	}
	if staticAnalysis.Supported || staticAnalysis.Error != "" {
		staticAnalysisCopy := staticAnalysis
		result.StaticAnalysis = &staticAnalysisCopy
	}
	result.Classifier = classification
	result.Verdict = decision.Verdict
	result.VerdictReasons = decision.Reasons
	result.Status = scanStatus(decision.Verdict, clamResult)

	if (decision.Verdict == policy.Quarantine || decision.Verdict == policy.Block) && h.quarantine != nil {
		if _, err := h.quarantine.Save(sha, data); err != nil {
			log.Printf("failed to quarantine %s: %v", sha, err)
		} else {
			result.Quarantined = true
		}
	}

	if decision.Verdict != policy.Allow || h.publishAllVerdicts {
		h.publishLog(c, requestID, target, sha, duration, clamResult, staticAnalysis, classification, classifierErr, decision, result.Quarantined)
	}

	return result
}

func (h ScannerHandler) publishLog(
	c *fiber.Ctx,
	requestID string,
	target scanTarget,
	sha string,
	durationMS int64,
	clamResult evidence.ClamAVInfo,
	staticAnalysis evidence.StaticAnalysis,
	classification *classifier.Result,
	classifierErr string,
	decision policy.Decision,
	quarantined bool,
) {
	reasons := decision.Reasons
	if reasons == nil {
		reasons = []string{}
	}

	entry := entities.ScanLog{
		RequestID:         requestID,
		Application:       h.appName,
		SourceIP:          c.IP(),
		Filename:          target.name,
		MIMEType:          target.mime,
		SHA256:            sha,
		Size:              int64(len(target.data)),
		Status:            scanStatus(decision.Verdict, clamResult),
		VirusName:         clamResult.Signature,
		ScanEngine:        "ClamAV",
		DBVersion:         h.fetchDBVersion(),
		DurationMS:        durationMS,
		CreatedAt:         time.Now(),
		Verdict:           string(decision.Verdict),
		VerdictReasons:    reasons,
		ClamAVDetected:    clamResult.Detected,
		ClamAVSignature:   clamResult.Signature,
		AnalysisSupported: staticAnalysis.Supported,
		ClassifierError:   classifierErr,
		Quarantined:       quarantined,
	}

	if encoded, err := json.Marshal(evidence.FileEvidence{
		File: evidence.FileInfo{
			Name:   target.name,
			Size:   int64(len(target.data)),
			MIME:   target.mime,
			SHA256: sha,
		},
		ClamAV:         clamResult,
		StaticAnalysis: staticAnalysis,
	}); err == nil {
		entry.Evidence = encoded
	}

	if classification != nil {
		entry.ClassifierLabel = classification.Label
		entry.ClassifierConfidence = classification.Confidence
		entry.ClassifierScores = classification.Scores
		entry.ClassifierModel = classification.Model
	}

	if err := h.scanLog.Publish(c.UserContext(), entry); err != nil {
		log.Printf("failed to publish scan log: %v", err)
	}
}

func (h *ScannerHandler) fetchDBVersion() int64 {
	if h.engine == nil {
		return 0
	}
	version, err := h.engine.Version()
	if err != nil {
		return 0
	}
	return version
}

type scanTarget struct {
	name string
	mime string
	data []byte
}

func (h ScannerHandler) scanTargets(c *fiber.Ctx) ([]scanTarget, error) {
	contentType, _, _ := mime.ParseMediaType(c.Get(fiber.HeaderContentType))
	if contentType != fiber.MIMEMultipartForm {
		body := c.BodyRaw()
		if len(body) == 0 {
			return nil, errors.New("file or request body required")
		}
		return []scanTarget{{mime: contentType, data: body}}, nil
	}

	form, err := c.MultipartForm()
	if err != nil {
		return nil, err
	}

	targets := make([]scanTarget, 0)
	for _, fileHeaders := range form.File {
		for _, fileHeader := range fileHeaders {
			file, err := fileHeader.Open()
			if err != nil {
				return nil, err
			}
			data, readErr := io.ReadAll(file)
			_ = file.Close()
			if readErr != nil {
				return nil, readErr
			}

			targets = append(targets, scanTarget{
				name: filepath.Base(fileHeader.Filename),
				mime: mime.TypeByExtension(filepath.Ext(fileHeader.Filename)),
				data: data,
			})
		}
	}

	if len(targets) == 0 {
		return nil, errors.New("file field required")
	}
	if len(targets) > h.maxFilesPerRequest {
		return nil, fmt.Errorf("too many files: maximum %d per request", h.maxFilesPerRequest)
	}

	return targets, nil
}

func scanStatus(verdict policy.Verdict, clamResult evidence.ClamAVInfo) string {
	if clamResult.Error != "" && !clamResult.Detected {
		return entities.StatusFailed
	}

	switch verdict {
	case policy.Block:
		if clamResult.Detected {
			return entities.StatusInfected
		}
		return entities.StatusBlocked
	case policy.Quarantine:
		return entities.StatusQuarantined
	default:
		return entities.StatusClean
	}
}

func randomID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func writeSuccess(c *fiber.Ctx, code int, message string, data interface{}) error {
	return c.Status(code).JSON(entities.Response{
		Code:    code,
		Status:  entities.StatusSuccess,
		Message: message,
		Data:    data,
	})
}

func writeError(c *fiber.Ctx, code int, message string, data interface{}) error {
	return c.Status(code).JSON(entities.Response{
		Code:    code,
		Status:  entities.StatusError,
		Message: message,
		Data:    data,
	})
}
