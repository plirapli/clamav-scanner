package app

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

	"scanner-service/analysis/analyzer"
	"scanner-service/analysis/classifier"
	"scanner-service/analysis/policy"
	"scanner-service/app/routes"
	scannerHandler "scanner-service/app/scanner/handler"
	"scanner-service/app/scanner/repo"
	"scanner-service/config"
	"scanner-service/core/scanner/interfaces"
	"scanner-service/core/scanner/usecase"
	"scanner-service/infra/clamav"
	"scanner-service/infra/kafka"
	"scanner-service/infra/quarantine"
	"scanner-service/infra/sqlite"
)

type Server struct {
	app *fiber.App
}

func New(cfg config.Config) (Server, error) {
	db, err := sqlite.Open(cfg.SQLitePath)
	if err != nil {
		return Server{}, err
	}

	producer := kafka.NewProducer(strings.Split(cfg.KafkaBrokers, ","), cfg.KafkaTopic)

	clamAVClient := clamav.NewClient(cfg.ClamAVAddr)
	scannerUsecase := usecase.NewScannerUsecase(clamAVClient)
	scanLogPublisher := repo.NewScanLogPublisher(producer)
	logHandler := scannerHandler.NewScanLogHandler(repo.NewScanLogRepo(db))

	analyzerRegistry := analyzer.NewRegistry(
		analyzer.NewPEAnalyzer(cfg.PackerEntropyThreshold),
		analyzer.NewPDFAnalyzer(),
		analyzer.NewOfficeAnalyzer(),
		analyzer.NewArchiveAnalyzer(),
		analyzer.NewScriptAnalyzer(),
		analyzer.NewGenericAnalyzer(),
	)

	var fileClassifier classifier.Classifier
	if cfg.ClassifierEnabled {
		fileClassifier = classifier.NewClef(
			cfg.ClassifierBaseURL,
			cfg.ClassifierAccountID,
			cfg.ClassifierAPIToken,
			cfg.ClassifierModel,
			cfg.ClassifierLabels,
			cfg.ClassifierSendFilename,
			cfg.ClassifierTimeout,
		)
	}

	var quarantineStore *quarantine.Store
	if cfg.QuarantineEnabled {
		quarantineStore, err = quarantine.New(cfg.QuarantineDir)
		if err != nil {
			return Server{}, err
		}
	}

	var cacheRepo interfaces.ScanCacheRepository
	if cfg.CacheEnabled {
		cacheRepo = repo.NewScanCacheRepo(db)
	}

	failMode, err := policy.ParseVerdict(strings.ToUpper(cfg.FailMode))
	if err != nil {
		failMode = policy.Quarantine
	}
	staticRuleVerdict, err := policy.ParseVerdict(strings.ToUpper(cfg.StaticRuleVerdict))
	if err != nil {
		staticRuleVerdict = policy.Quarantine
	}
	encryptedVerdict, err := policy.ParseVerdict(strings.ToUpper(cfg.EncryptedVerdict))
	if err != nil {
		encryptedVerdict = policy.Quarantine
	}

	policyConfig := policy.Config{
		BlockConfidence:      cfg.VerdictBlockConfidence,
		FailMode:             failMode,
		AllowUnsupported:     cfg.AllowUnsupported,
		StaticRulesEnabled:   cfg.StaticRulesEnabled,
		StaticRuleVerdict:    staticRuleVerdict,
		SuspiciousImportsMin: int(cfg.SuspiciousImportsMin),
		GenericRulesEnabled:  cfg.GenericRulesEnabled,
		EncryptedVerdict:     encryptedVerdict,
	}

	handler := scannerHandler.NewScannerHandler(scannerHandler.ScannerHandlerDeps{
		Usecase:            scannerUsecase,
		ScanLog:            scanLogPublisher,
		Engine:             clamAVClient,
		AppName:            cfg.AppName,
		Analyzer:           analyzerRegistry,
		Classifier:         fileClassifier,
		ClassifierTimeout:  cfg.ClassifierTimeout,
		Policy:             policyConfig,
		Quarantine:         quarantineStore,
		Cache:              cacheRepo,
		CacheTTL:           cfg.CacheTTL,
		CacheErrorTTL:      cfg.CacheErrorTTL,
		CacheMaxEntries:    int(cfg.CacheMaxEntries),
		AnalyzerVersion:    analyzer.Version,
		PublishAllVerdicts: cfg.PublishAllVerdicts,
		MaxFilesPerRequest: int(cfg.MaxFilesPerRequest),
	})

	fiberApp := fiber.New(fiber.Config{
		BodyLimit: int(cfg.MaxScanSize),
	})
	fiberApp.Use(cors.New(cors.Config{
		AllowOrigins: "http://localhost:5173,http://localhost:5174",
		AllowHeaders: "Origin, Content-Type, Accept",
		AllowMethods: "GET, POST, OPTIONS",
	}))
	fiberApp.Static("/swagger", "./docs")
	routes.RegisterScannerRoutes(fiberApp, handler, logHandler)
	routes.RegisterEvalRoutes(fiberApp, scannerHandler.NewEvalHandler(cfg.EvalResultsDir, policyConfig))

	return Server{app: fiberApp}, nil
}

func (s Server) App() *fiber.App {
	return s.app
}
