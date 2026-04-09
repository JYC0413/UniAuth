package utils

import (
	"testing"

	"UniAuth/internal/config"
	"github.com/google/uuid"
)

func init() {
	config.AppConfig = &config.Config{
		JWTSecret: "test-secret-for-jwt-tests-minimum-32ch",
	}
}

func TestGeneratePreAuthToken_HasCorrectTokenType(t *testing.T) {
	userID := uuid.New()
	token, err := GeneratePreAuthToken(userID, "SELF")
	if err != nil {
		t.Fatalf("GeneratePreAuthToken failed: %v", err)
	}

	claims, err := ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}

	if claims.TokenType != "pre_auth" {
		t.Errorf("expected token_type=pre_auth, got %s", claims.TokenType)
	}
	if claims.UserID != userID {
		t.Errorf("UserID mismatch")
	}
	if claims.DataScope != "SELF" {
		t.Errorf("expected DataScope=SELF, got %s", claims.DataScope)
	}
}

func TestGenerateToken_HasEmptyTokenType(t *testing.T) {
	userID := uuid.New()
	token, err := GenerateToken(userID, "ALL")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	claims, err := ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}

	if claims.TokenType != "" {
		t.Errorf("expected empty token_type for regular token, got %s", claims.TokenType)
	}
}
