package routes

import (
	"github.com/gofiber/fiber/v2"

	"scanner-service/app/midleware"
	scannerHandler "scanner-service/app/scanner/handler"
)

func RegisterScannerRoutes(app *fiber.App, handler scannerHandler.ScannerHandler, auth midleware.AuthMiddleware) {
	app.Post("/api/scanner/scan", auth.Require(), handler.Scan)
}
