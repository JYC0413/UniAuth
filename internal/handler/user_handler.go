package handler

import (
	"math/big"
	"net/http"

	"UniAuth/internal/database"
	"UniAuth/internal/model"
	"UniAuth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func GetUserMask(c *gin.Context) {
	appCode := c.Query("app_code")
	if appCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app_code is required"})
		return
	}

	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userID := userIDStr.(uuid.UUID)

	var app model.SysApp
	if err := database.DB.Where("code = ?", appCode).First(&app).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
		return
	}

	var userRoles []model.SysUserRole
	// Preload Role, DataScope, and PermissionMasks
	if err := database.DB.Preload("Role.DataScope").Preload("Role.PermissionMasks").Where("user_id = ? AND app_id = ?", userID, app.ID).Find(&userRoles).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user roles"})
		return
	}

	finalMask := new(big.Int)
	var dataScopes []gin.H

	for _, ur := range userRoles {
		// Reconstruct mask from buckets
		for _, pm := range ur.Role.PermissionMasks {
			uVal := uint64(pm.Mask)
			bucketBig := new(big.Int).SetUint64(uVal)
			shift := uint(pm.BucketIndex) * 64
			bucketBig.Lsh(bucketBig, shift)
			finalMask.Or(finalMask, bucketBig)
		}

		if ur.Role.DataScope != nil {
			dataScopes = append(dataScopes, gin.H{
				"scope_type":    ur.Role.DataScope.ScopeType,
				"custom_config": ur.Role.DataScope.CustomConfig,
			})
		}
	}

	// Retrieve token to return to frontend so it can be passed to subsystems
	tokenString, err := c.Cookie("auth_token")
	if err != nil {
		tokenString = c.GetHeader("Authorization")
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": gin.H{
			"uid":          userID,
			"mask":         utils.MaskToHex(finalMask),
			"data_scopes":  dataScopes,
			"redirect_url": app.RedirectURL,
			"token":        tokenString,
		},
	})
}
