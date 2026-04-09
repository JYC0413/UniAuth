package middleware

import (
	"net/http"
	"time"

	"UniAuth/internal/utils"

	"github.com/gin-gonic/gin"
)

// PreAuthMiddleware validates tokens issued after password verification but before TOTP.
// Only accepts tokens with token_type == "pre_auth". Reads from Authorization header only
// (pre_auth tokens are never stored in cookies).
func PreAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if len(auth) <= 7 || auth[:7] != "Bearer " {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Pre-auth token required"})
			return
		}
		tokenString := auth[7:]

		claims, err := utils.ParseToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		if time.Now().After(claims.ExpiresAt.Time) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			return
		}

		if claims.TokenType != "pre_auth" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token type"})
			return
		}

		c.Set("userID", claims.UserID)
		c.Set("dataScope", claims.DataScope)
		c.Next()
	}
}
