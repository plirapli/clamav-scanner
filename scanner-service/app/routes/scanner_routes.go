package routes

import (
	"github.com/gofiber/fiber/v2"

	scannerHandler "scanner-service/app/scanner/handler"
)

func RegisterScannerRoutes(app *fiber.App, handler scannerHandler.ScannerHandler, logHandler scannerHandler.ScanLogHandler) {
	app.Post("/api/scanner/scan", handler.Scan)
	app.Get("/api/scanner/logs", logHandler.List)
}
