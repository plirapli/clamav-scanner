package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"log"
	"mime"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v2"

	"scanner-service/app/midleware"
	"scanner-service/core/scanner/entities"
	"scanner-service/core/scanner/interfaces"
)

type ScannerHandler struct {
	usecase interfaces.ScannerUsecase
	scanLog interfaces.ScanLogPublisher
	engine  ScannerEngine
}

type ScannerEngine interface {
	Version() (int64, error)
}

func NewScannerHandler(usecase interfaces.ScannerUsecase, scanLog interfaces.ScanLogPublisher, engine ScannerEngine) ScannerHandler {
	return ScannerHandler{
		usecase: usecase,
		scanLog: scanLog,
		engine:  engine,
	}
}

func (h ScannerHandler) Scan(c *fiber.Ctx) error {
	files, body, err := h.scanTargets(c)
	if err != nil {
		return writeError(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	requestID := c.Get(fiber.HeaderXRequestID)
	if requestID == "" {
		requestID = randomID()
	}

	result := entities.ScanResult{}

	bodyMime := contentType(c)
	for _, file := range files {
		tracker := newTrackingReader(file.reader)
		start := time.Now()
		fileResult := h.scanReader(tracker, file.name)
		duration := time.Since(start).Milliseconds()
		_ = file.reader.Close()

		if fileResult.Status == entities.StatusInfected {
			h.logInfected(c, entities.ScanLog{
				RequestID:  requestID,
				Filename:   file.name,
				MIMEType:   file.mime,
				SHA256:     tracker.Sum(),
				Size:       tracker.size,
				VirusName:  fileResult.Scan,
				DurationMS: duration,
			})
		}

		result.Files = append(result.Files, fileResult)
	}

	if body != nil {
		tracker := newTrackingReader(body)
		start := time.Now()
		bodyResult := h.scanReader(tracker, "")
		duration := time.Since(start).Milliseconds()

		if bodyResult.Status == entities.StatusInfected {
			h.logInfected(c, entities.ScanLog{
				RequestID:  requestID,
				MIMEType:   bodyMime,
				SHA256:     tracker.Sum(),
				Size:       tracker.size,
				VirusName:  bodyResult.Scan,
				DurationMS: duration,
			})
		}

		result.Files = append(result.Files, bodyResult)
	}

	if hasProblem(result.Files) {
		return writeError(c, fiber.StatusBadRequest, "scan completed with issues", result)
	}

	return writeSuccess(c, fiber.StatusOK, "scan completed", result)
}

func (h ScannerHandler) scanReader(reader io.Reader, name string) entities.FileResult {
	if err := h.usecase.Scan(reader); err != nil {
		return classifyScanError(err, name)
	}

	return entities.FileResult{
		Name:   name,
		Status: entities.StatusClean,
	}
}

func (h *ScannerHandler) logInfected(c *fiber.Ctx, logEntry entities.ScanLog) {
	logEntry.Status = entities.StatusInfected
	logEntry.ScanEngine = "ClamAV"
	logEntry.SourceIP = c.IP()
	logEntry.CreatedAt = time.Now()
	logEntry.DBVersion = h.fetchDBVersion()

	if application, ok := c.Locals(midleware.LocalsApplicationKey).(entities.Application); ok {
		logEntry.Application = application.AppName
	}

	if err := h.scanLog.Publish(c.UserContext(), logEntry); err != nil {
		log.Printf("failed to save infected scan log: %v", err)
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

type scanFile struct {
	name   string
	mime   string
	reader io.ReadCloser
}

func (h ScannerHandler) scanTargets(c *fiber.Ctx) ([]scanFile, io.Reader, error) {
	contentType, _, _ := mime.ParseMediaType(c.Get(fiber.HeaderContentType))
	if contentType != fiber.MIMEMultipartForm {
		body := c.BodyRaw()
		if len(body) == 0 {
			return nil, nil, errors.New("file or request body required")
		}
		return nil, bytes.NewReader(body), nil
	}

	form, err := c.MultipartForm()
	if err != nil {
		return nil, nil, err
	}

	var files []scanFile
	for _, fileHeaders := range form.File {
		for _, fileHeader := range fileHeaders {
			file, err := fileHeader.Open()
			if err != nil {
				return nil, nil, err
			}
			files = append(files, scanFile{
				name:   filepath.Base(fileHeader.Filename),
				mime:   mime.TypeByExtension(filepath.Ext(fileHeader.Filename)),
				reader: file,
			})
		}
	}

	if len(files) == 0 {
		return nil, nil, errors.New("file field required")
	}

	return files, nil, nil
}

func contentType(c *fiber.Ctx) string {
	contentType, _, _ := mime.ParseMediaType(c.Get(fiber.HeaderContentType))
	return contentType
}

type trackingReader struct {
	reader io.Reader
	hash   hash.Hash
	size   int64
}

func newTrackingReader(reader io.Reader) *trackingReader {
	return &trackingReader{
		reader: reader,
		hash:   sha256.New(),
	}
}

func (t *trackingReader) Read(p []byte) (int, error) {
	n, err := t.reader.Read(p)
	if n > 0 {
		t.hash.Write(p[:n])
		t.size += int64(n)
	}
	return n, err
}

func (t *trackingReader) Sum() string {
	return hex.EncodeToString(t.hash.Sum(nil))
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

func classifyScanError(err error, name string) entities.FileResult {
	var virusErr interfaces.VirusFoundError
	if errors.As(err, &virusErr) {
		return entities.FileResult{
			Name:   name,
			Status: entities.StatusInfected,
			Scan:   virusErr.VirusName(),
		}
	}

	return entities.FileResult{
		Name:   name,
		Status: entities.StatusFailed,
		Error:  err.Error(),
	}
}

func hasProblem(files []entities.FileResult) bool {
	for _, file := range files {
		if file.Status == entities.StatusInfected || file.Status == entities.StatusFailed {
			return true
		}
	}
	return false
}
