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
		tokenString, err := c.Cookie("auth_token")
		if err != nil {
			// Try getting from Header
			tokenString = c.GetHeader("Authorization")
			if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
				tokenString = tokenString[7:]
			} else if tokenString == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization required"})
				return
			}
		}

		// Check Blacklist
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

		// Optional: Check if token is expired (ParseToken already does this, but double check logic if needed)
		if time.Now().After(claims.ExpiresAt.Time) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			return
		}

		c.Set("userID", claims.UserID)
		c.Next()
	}
}
