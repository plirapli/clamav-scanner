package app

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"scanner-service/app/midleware"
	"scanner-service/app/routes"
	scannerHandler "scanner-service/app/scanner/handler"
	"scanner-service/app/scanner/repo"
	"scanner-service/app/scanner/service"
	"scanner-service/config"
	"scanner-service/core/scanner/usecase"
	"scanner-service/infra/clamav"
	"scanner-service/infra/database"
	"scanner-service/infra/kafka"
)

type Server struct {
	app *fiber.App
}

func New(cfg config.Config) (Server, error) {
	db, err := database.NewPostgres(cfg.DatabaseDSN)
	if err != nil {
		return Server{}, err
	}

	producer := kafka.NewProducer(strings.Split(cfg.KafkaBrokers, ","), cfg.KafkaTopic)

	clamAVClient := clamav.NewClient(cfg.ClamAVAddr)
	scannerUsecase := usecase.NewScannerUsecase(clamAVClient)
	scanLogPublisher := repo.NewScanLogPublisher(producer)
	handler := scannerHandler.NewScannerHandler(scannerUsecase, scanLogPublisher, clamAVClient)

	applicationRepo := repo.NewApplicationRepo(db)
	authService := service.NewAuthService(applicationRepo)
	authMiddleware := midleware.NewAuthMiddleware(authService)

	fiberApp := fiber.New(fiber.Config{
		BodyLimit: int(cfg.MaxScanSize),
	})
	fiberApp.Static("/swagger", "./docs")
	routes.RegisterScannerRoutes(fiberApp, handler, authMiddleware)

	return Server{app: fiberApp}, nil
}

func (s Server) App() *fiber.App {
	return s.app
}
