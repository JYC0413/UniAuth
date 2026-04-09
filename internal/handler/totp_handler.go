package handler

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"
	"time"

	"UniAuth/internal/config"
	"UniAuth/internal/database"
	"UniAuth/internal/model"
	"UniAuth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

type TOTPCodeRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

// TOTPSetup generates a new TOTP secret and QR code for a user who has not yet enrolled.
// Requires: pre_auth_token in Authorization header (user must not have totp_secret set).
func TOTPSetup(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)

	var user model.SysUser
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.TOTPSecret != nil && user.TOTPEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP already configured, contact admin to reset"})
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "UniAuth",
		AccountName: user.Username,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate TOTP secret"})
		return
	}

	secret := key.Secret()
	if err := database.DB.Model(&user).Update("totp_secret", secret).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save TOTP secret"})
		return
	}

	img, err := key.Image(200, 200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
		return
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode QR code"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"qr_code_base64": "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
		"secret":         secret,
	})
}

// TOTPEnroll verifies the first TOTP code from the user, marks TOTP as enabled,
// and returns a full auth_token. Called after TOTPSetup.
func TOTPEnroll(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	dataScope := c.GetString("dataScope")

	var req TOTPCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user model.SysUser
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.TOTPSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Call /totp/setup first"})
		return
	}
	if user.TOTPEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP already enrolled"})
		return
	}

	if !totp.Validate(req.Code, *user.TOTPSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid TOTP code"})
		return
	}

	if err := database.DB.Model(&user).Update("totp_enabled", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable TOTP"})
		return
	}

	// Blacklist the pre_auth_token to prevent replay within its 5-minute window
	blacklistPreAuthToken(c)

	token, err := utils.GenerateToken(userID, dataScope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	setAuthCookie(c, token)
	c.JSON(http.StatusOK, gin.H{"message": "TOTP enrollment successful", "token": token})
}

// TOTPVerify validates a TOTP code for an already-enrolled user and issues a full auth_token.
func TOTPVerify(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	dataScope := c.GetString("dataScope")

	var req TOTPCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user model.SysUser
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !user.TOTPEnabled || user.TOTPSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP not enrolled"})
		return
	}

	if !totp.Validate(req.Code, *user.TOTPSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid TOTP code"})
		return
	}

	// Blacklist the pre_auth_token to prevent replay within its 5-minute window
	blacklistPreAuthToken(c)

	token, err := utils.GenerateToken(userID, dataScope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	setAuthCookie(c, token)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": token})
}

// TOTPReset clears a user's TOTP enrollment. Admin-only.
func TOTPReset(c *gin.Context) {
	userIDStr := c.Param("user_id")
	targetID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	result := database.DB.Model(&model.SysUser{}).Where("id = ?", targetID).
		Updates(map[string]interface{}{
			"totp_secret":  nil,
			"totp_enabled": false,
		})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset TOTP"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "TOTP reset successful"})
}

// setAuthCookie sets the auth_token cookie with Secure and SameSite=Strict.
func setAuthCookie(c *gin.Context, token string) {
	secure := config.AppConfig.AppEnv == "production"
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		MaxAge:   3600 * 24,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// blacklistPreAuthToken extracts the Bearer token from Authorization header and adds it to the blacklist.
func blacklistPreAuthToken(c *gin.Context) {
	raw := c.GetHeader("Authorization")
	if len(raw) <= 7 || raw[:7] != "Bearer " {
		return
	}
	rawToken := raw[7:]
	claims, err := utils.ParseToken(rawToken)
	if err != nil {
		return
	}
	database.DB.Create(&model.SysTokenBlacklist{
		Token:     rawToken,
		ExpiresAt: claims.ExpiresAt.Time,
		CreatedAt: time.Now(),
	})
}
