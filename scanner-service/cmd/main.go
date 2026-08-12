package main

import (
	"log"

	"scanner-service/app"
	"scanner-service/config"
)

func main() {
	cfg := config.Load()

	server, err := app.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(server.App().Listen(":" + cfg.AppPort))
}
