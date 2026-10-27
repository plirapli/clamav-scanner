package routes

import (
	"github.com/gofiber/fiber/v2"

	scannerHandler "scanner-service/app/scanner/handler"
)

func RegisterScannerRoutes(app *fiber.App, handler scannerHandler.ScannerHandler, logHandler scannerHandler.ScanLogHandler) {
	app.Post("/api/scanner/scan", handler.Scan)
	app.Get("/api/scanner/logs", logHandler.List)
	app.Get("/api/scanner/logs/summary", logHandler.Summary)
}

// RegisterEvalRoutes exposes the local evaluation results (read-only).
func RegisterEvalRoutes(app *fiber.App, handler scannerHandler.EvalHandler) {
	app.Get("/api/eval/runs", handler.Runs)
	app.Get("/api/eval/runs/:name", handler.Run)
}
