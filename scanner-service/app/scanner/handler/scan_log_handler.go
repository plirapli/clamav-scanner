package handler

import (
	"slices"
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

	verdict, err := queryVerdict(c)
	if err != nil {
		return writeError(c, fiber.StatusBadRequest, "invalid verdict", nil)
	}

	sortBy := strings.TrimSpace(c.Query("sort"))
	if sortBy != "" && !slices.Contains(interfaces.ScanLogSortKeys, sortBy) {
		return writeError(c, fiber.StatusBadRequest, "invalid sort", nil)
	}

	order := strings.ToLower(strings.TrimSpace(c.Query("order", "desc")))
	if order != "asc" && order != "desc" {
		return writeError(c, fiber.StatusBadRequest, "invalid order", nil)
	}

	logs, total, err := h.logs.List(c.UserContext(), interfaces.ScanLogFilter{
		VirusName:   c.Query("virus_name"),
		Application: c.Query("application"),
		Verdict:     verdict,
		SortBy:      sortBy,
		SortDesc:    order == "desc",
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

// Summary returns per-virus and per-application counts over every log that
// matches the filters, so the dashboard is not limited to the visible page.
func (h ScanLogHandler) Summary(c *fiber.Ctx) error {
	verdict, err := queryVerdict(c)
	if err != nil {
		return writeError(c, fiber.StatusBadRequest, "invalid verdict", nil)
	}

	summary, err := h.logs.Summary(c.UserContext(), interfaces.ScanLogFilter{
		VirusName:   c.Query("virus_name"),
		Application: c.Query("application"),
		Verdict:     verdict,
	})
	if err != nil {
		return writeError(c, fiber.StatusInternalServerError, "failed to load scan log summary", nil)
	}

	return writeSuccess(c, fiber.StatusOK, "scan log summary loaded", summary)
}

func queryVerdict(c *fiber.Ctx) (string, error) {
	raw := strings.TrimSpace(c.Query("verdict"))
	if raw == "" {
		return "", nil
	}
	parsed, err := policy.ParseVerdict(strings.ToUpper(raw))
	return string(parsed), err
}

func queryInt(c *fiber.Ctx, key string, fallback int) (int, error) {
	raw := c.Query(key)
	if raw == "" {
		return fallback, nil
	}
	return strconv.Atoi(raw)
}
