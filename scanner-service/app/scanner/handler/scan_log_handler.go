package handler

import (
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"scanner-service/analysis/policy"
	"scanner-service/core/scanner/interfaces"
)

const (
	defaultLogLimit = 20
	maxLogLimit     = 100
)

type ScanLogHandler struct {
	logs interfaces.ScanLogRepository
}

func NewScanLogHandler(logs interfaces.ScanLogRepository) ScanLogHandler {
	return ScanLogHandler{logs: logs}
}

func (h ScanLogHandler) List(c *fiber.Ctx) error {
	limit, err := queryInt(c, "limit", defaultLogLimit)
	if err != nil || limit < 1 || limit > maxLogLimit {
		return writeError(c, fiber.StatusBadRequest, "invalid limit", nil)
	}

	skip, err := queryInt(c, "skip", 0)
	if err != nil || skip < 0 {
		return writeError(c, fiber.StatusBadRequest, "invalid skip", nil)
	}

	verdict := ""
	if raw := strings.TrimSpace(c.Query("verdict")); raw != "" {
		parsed, err := policy.ParseVerdict(strings.ToUpper(raw))
		if err != nil {
			return writeError(c, fiber.StatusBadRequest, "invalid verdict", nil)
		}
		verdict = string(parsed)
	}

	logs, total, err := h.logs.List(c.UserContext(), interfaces.ScanLogFilter{
		VirusName:   c.Query("virus_name"),
		Application: c.Query("application"),
		Verdict:     verdict,
		Limit:       limit,
		Skip:        skip,
	})
	if err != nil {
		return writeError(c, fiber.StatusInternalServerError, "failed to load scan logs", nil)
	}

	return writeSuccess(c, fiber.StatusOK, "scan logs loaded", fiber.Map{
		"total": total,
		"items": logs,
	})
}

func queryInt(c *fiber.Ctx, key string, fallback int) (int, error) {
	raw := c.Query(key)
	if raw == "" {
		return fallback, nil
	}
	return strconv.Atoi(raw)
}
