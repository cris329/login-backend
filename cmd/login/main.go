// Arranca la API: lee el .env, abre Postgres y escucha en el puerto 8080.
package main

import (
	"encoding/base64"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"

	"github.com/cris329/login/controller"
	"github.com/cris329/login/database"
	"github.com/cris329/login/router"
	"github.com/cris329/login/service"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	_ = godotenv.Load()
	key, err := base64.StdEncoding.DecodeString(os.Getenv("JWT_ENCRYPTION_KEY"))
	if err != nil || len(key) != 32 {
		slog.Error("JWT_ENCRYPTION_KEY debe ser base64 de 32 bytes")
		os.Exit(1)
	}
	conn, err := database.Open(os.Getenv("DATABASE_URL"))
	if err != nil {
		slog.Error("base de datos", "error", err.Error())
		os.Exit(1)
	}
	if err = database.Migrate(conn); err != nil {
		slog.Error("migracion", "error", err.Error())
		os.Exit(1)
	}
	app := service.App{
		DB: conn, Key: key,
		Tokens: service.NewToken(key, time.Duration(number("JWT_TTL_MINUTES", 1, 1440, 15))*time.Minute),
		Codes:  mail(),
	}
	port := text("PORT", "8080")
	slog.Info("login escuchando", "port", port)
	if err = router.New(controller.Handler{App: app}, os.Getenv("CORS_ALLOWED_ORIGIN")).Run(":" + port); err != nil {
		slog.Error("servidor", "error", err.Error())
		os.Exit(1)
	}
}

// mail arma el envío con Brevo y Twilio. Las claves se leen del .env.
func mail() service.Sender {
	return service.Sender{
		From: text("SMTP_FROM", "cj.deysdayr@gmail.com"), User: text("SMTP_USER", text("SMTP_FROM", "cj.deysdayr@gmail.com")),
		Password: os.Getenv("SMTP_PASSWORD"), Host: text("SMTP_HOST", "smtp.gmail.com"), Port: text("SMTP_PORT", "587"),
		APIKey:    os.Getenv("BREVO_API_KEY"),
		TwilioSID: os.Getenv("TWILIO_ACCOUNT_SID"), TwilioToken: os.Getenv("TWILIO_AUTH_TOKEN"),
		TwilioFrom: os.Getenv("TWILIO_FROM"), Minutes: number("OTP_TTL_MINUTES", 1, 15, 5),
	}
}

func text(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func number(key string, min, max, fallback int) int {
	n, err := strconv.Atoi(os.Getenv(key))
	if err != nil || n < min || n > max {
		return fallback
	}
	return n
}
