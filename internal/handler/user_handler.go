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
	// Preload Role to get PermissionMask
	if err := database.DB.Preload("Role").Where("user_id = ? AND app_id = ?", userID, app.ID).Find(&userRoles).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user roles"})
		return
	}

	finalMask := new(big.Int)
	for _, ur := range userRoles {
		roleMask := utils.ParseMask(ur.Role.PermissionMask)
		finalMask.Or(finalMask, roleMask)
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": gin.H{
			"uid":          userID,
			"mask":         utils.MaskToHex(finalMask),
			"redirect_url": app.RedirectURL,
		},
	})
}
