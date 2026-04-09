package utils

import (
	"time"

	"UniAuth/internal/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	UserID    uuid.UUID `json:"uid"`
	DataScope string    `json:"data_scope,omitempty"`
	TokenType string    `json:"token_type,omitempty"` // "pre_auth" for TOTP step; "" for full auth token
	jwt.RegisteredClaims
}

func GenerateToken(userID uuid.UUID, dataScope string) (string, error) {
	claims := &Claims{
		UserID:    userID,
		DataScope: dataScope,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			Issuer:    "auth.company.com",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.AppConfig.JWTSecret))
}

// GeneratePreAuthToken issues a 5-minute token used only for the TOTP verification step.
// It carries the DataScope so it can be forwarded to GenerateToken after TOTP passes.
func GeneratePreAuthToken(userID uuid.UUID, dataScope string) (string, error) {
	claims := &Claims{
		UserID:    userID,
		DataScope: dataScope,
		TokenType: "pre_auth",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			Issuer:    "auth.company.com",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.AppConfig.JWTSecret))
}

func ParseToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.AppConfig.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	return claims, nil
}
