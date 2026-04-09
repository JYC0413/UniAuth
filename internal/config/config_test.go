package config

import (
	"os"
	"testing"
)

func TestLoadConfig_SetsAllFields(t *testing.T) {
	os.Setenv("APP_ENV", "production")
	os.Setenv("JWT_SECRET", "test-secret-32-chars-minimum-ok")
	os.Setenv("DB_HOST", "testhost")
	os.Setenv("DB_USER", "testuser")
	os.Setenv("DB_PASSWORD", "testpass")
	os.Setenv("DB_NAME", "testdb")
	os.Setenv("DB_TIMEZONE", "Asia/Shanghai")
	os.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com")
	defer func() {
		for _, k := range []string{"APP_ENV", "JWT_SECRET", "DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME", "DB_TIMEZONE", "CORS_ALLOWED_ORIGINS"} {
			os.Unsetenv(k)
		}
	}()

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
	if AppConfig.JWTSecret != "test-secret-32-chars-minimum-ok" {
		t.Errorf("JWTSecret not loaded correctly")
	}
}

func TestLoadConfig_DevModeUsesDisableSSL(t *testing.T) {
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_USER", "postgres")
	os.Setenv("DB_PASSWORD", "postgres")
	os.Setenv("DB_NAME", "uniauth")
	os.Unsetenv("APP_ENV")
	os.Unsetenv("DB_SSL_MODE")
	defer func() {
		for _, k := range []string{"JWT_SECRET", "DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME"} {
			os.Unsetenv(k)
		}
	}()

	LoadConfig()

	if AppConfig.DBSSLMode != "disable" {
		t.Errorf("expected DBSSLMode=disable in development, got %s", AppConfig.DBSSLMode)
	}
}
