package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"scanner-service/config"
	"scanner-service/core/scanner/entities"
	"scanner-service/infra/database"
)

func main() {
	appName := flag.String("app-name", "", "application name")
	dsn := flag.String("dsn", "", "postgres DSN (default: DATABASE_DSN env or config fallback)")
	flag.Parse()

	if *appName == "" {
		fail("app-name required")
	}

	cfg := config.Load()
	if *dsn == "" {
		*dsn = cfg.DatabaseDSN
	}

	db, err := database.NewPostgres(*dsn)
	if err != nil {
		fail("db connection failed: " + err.Error())
	}

	clientID, err := randomUUID()
	if err != nil {
		fail("client id generation failed: " + err.Error())
	}

	token, err := randomToken()
	if err != nil {
		fail("token generation failed: " + err.Error())
	}

	tokenHash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		fail("token hashing failed: " + err.Error())
	}

	id, err := randomUUID()
	if err != nil {
		fail("id generation failed: " + err.Error())
	}

	now := time.Now()
	application := entities.Application{
		ID:        id,
		AppName:   *appName,
		ClientID:  clientID,
		TokenHash: string(tokenHash),
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := db.Create(&application).Error; err != nil {
		fail("insert failed: " + err.Error())
	}

	output := struct {
		AppName  string `json:"app_name"`
		ClientID string `json:"client_id"`
		Token    string `json:"token"`
	}{
		AppName:  *appName,
		ClientID: clientID,
		Token:    token,
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))
	fmt.Println("\nsave the token now, it will not be shown again")
}

func randomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func randomUUID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16]), nil
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "error:", message)
	os.Exit(1)
}
