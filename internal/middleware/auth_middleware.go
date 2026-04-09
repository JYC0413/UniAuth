package middleware

import (
	"net/http"
	"time"

	"UniAuth/internal/database"
	"UniAuth/internal/model"
	"UniAuth/internal/utils"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := extractToken(c)
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization required"})
			return
		}

		var count int64
		database.DB.Model(&model.SysTokenBlacklist{}).Where("token = ?", tokenString).Count(&count)
		if count > 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token invalidated"})
			return
		}

		claims, err := utils.ParseToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		if time.Now().After(claims.ExpiresAt.Time) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			return
		}

		// Pre-auth tokens are only valid on TOTP routes — reject them here
		if claims.TokenType == "pre_auth" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "TOTP verification required"})
			return
		}

		c.Set("userID", claims.UserID)
		c.Next()
	}
}

func extractToken(c *gin.Context) string {
	if token, err := c.Cookie("auth_token"); err == nil {
		return token
	}
	auth := c.GetHeader("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}
