package handler

import (
	"net/http"

	"UniAuth/internal/database"
	"UniAuth/internal/model"

	"github.com/gin-gonic/gin"
)

func GetPermissions(c *gin.Context) {
	appCode := c.Query("app_code")
	if appCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app_code is required"})
		return
	}

	var app model.SysApp
	if err := database.DB.Where("code = ?", appCode).First(&app).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
		return
	}

	var permissions []model.SysPermission
	if err := database.DB.Where("app_id = ?", app.ID).Find(&permissions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch permissions"})
		return
	}

	var result []gin.H
	for _, p := range permissions {
		result = append(result, gin.H{
			"key": p.PermissionCode,
			"idx": p.BitIndex,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
		"data": result,
	})
}
