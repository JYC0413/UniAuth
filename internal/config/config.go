package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerPort         string
	AppEnv             string // "development" | "production"
	DatabaseURL        string // Full DSN takes priority over individual fields
	DBHost             string
	DBUser             string
	DBPassword         string
	DBName             string
	DBPort             string
	DBTimezone         string
	DBSSLMode          string
	JWTSecret          string
	CORSAllowedOrigins string // Comma-separated list; empty = no CORS
}

var AppConfig *Config

func LoadConfig() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Validate required variables before building config
	required := []string{"DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME", "JWT_SECRET"}
	for _, key := range required {
		if os.Getenv(key) == "" {
			log.Fatalf("required environment variable %s is not set", key)
		}
	}
	if len(os.Getenv("JWT_SECRET")) < 32 {
		log.Fatalf("JWT_SECRET must be at least 32 characters long")
	}

	appEnv := getEnv("APP_ENV", "development")

	// Default SSL mode based on environment (can be overridden explicitly)
	defaultSSL := "disable"
	if appEnv == "production" {
		defaultSSL = "require"
	}

	AppConfig = &Config{
		ServerPort:         getEnv("SERVER_PORT", "8080"),
		AppEnv:             appEnv,
		DatabaseURL:        getEnv("DATABASE_URL", ""),
		DBHost:             getEnv("DB_HOST", ""),
		DBUser:             getEnv("DB_USER", ""),
		DBPassword:         getEnv("DB_PASSWORD", ""),
		DBName:             getEnv("DB_NAME", ""),
		DBPort:             getEnv("DB_PORT", "5432"),
		DBTimezone:         getEnv("DB_TIMEZONE", "UTC"),
		DBSSLMode:          getEnv("DB_SSL_MODE", defaultSSL),
		JWTSecret:          getEnv("JWT_SECRET", ""),
		CORSAllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", ""),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	strValue := getEnv(key, "")
	if strValue == "" {
		return fallback
	}
	val, err := strconv.Atoi(strValue)
	if err != nil {
		log.Printf("Invalid integer for env %s: %v. Using fallback %d", key, err, fallback)
		return fallback
	}
	return val
}
