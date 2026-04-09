package config

import (
	"testing"
)

func TestLoadConfig_SetsAllFields(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("JWT_SECRET", "test-secret-32-chars-minimum-ok!!")
	t.Setenv("DB_HOST", "testhost")
	t.Setenv("DB_USER", "testuser")
	t.Setenv("DB_PASSWORD", "testpass")
	t.Setenv("DB_NAME", "testdb")
	t.Setenv("DB_TIMEZONE", "Asia/Shanghai")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com")

	LoadConfig()

	if AppConfig.AppEnv != "production" {
		t.Errorf("expected AppEnv=production, got %s", AppConfig.AppEnv)
	}
	if AppConfig.DBTimezone != "Asia/Shanghai" {
		t.Errorf("expected DBTimezone=Asia/Shanghai, got %s", AppConfig.DBTimezone)
	}
	if AppConfig.DBSSLMode != "require" {
		t.Errorf("expected DBSSLMode=require in production, got %s", AppConfig.DBSSLMode)
	}
	if AppConfig.CORSAllowedOrigins != "https://app.example.com" {
		t.Errorf("expected CORSAllowedOrigins set, got %s", AppConfig.CORSAllowedOrigins)
	}
	if AppConfig.JWTSecret != "test-secret-32-chars-minimum-ok!!" {
		t.Errorf("JWTSecret not loaded correctly")
	}
}

func TestLoadConfig_DevModeUsesDisableSSL(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret-that-is-32-chars-long!!")
	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_USER", "postgres")
	t.Setenv("DB_PASSWORD", "postgres")
	t.Setenv("DB_NAME", "uniauth")

	LoadConfig()

	if AppConfig.DBSSLMode != "disable" {
		t.Errorf("expected DBSSLMode=disable in development, got %s", AppConfig.DBSSLMode)
	}
}
