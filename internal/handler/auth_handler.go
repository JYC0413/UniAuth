package handler

import (
	"net/http"
	"time"

	"UniAuth/internal/config"
	"UniAuth/internal/database"
	"UniAuth/internal/model"
	"UniAuth/internal/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user model.SysUser
	if err := database.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Determine DataScope (highest scope across all user roles)
	maxScope := 1
	var userRoles []model.SysUserRole
	if err := database.DB.Preload("Role.DataScope").Where("user_id = ?", user.ID).Find(&userRoles).Error; err == nil {
		for _, ur := range userRoles {
			if ur.Role.DataScope != nil && ur.Role.DataScope.ScopeType > maxScope {
				maxScope = ur.Role.DataScope.ScopeType
			}
		}
	}
	scopeMap := map[int]string{1: "SELF", 2: "DEPT", 3: "ALL", 4: "CUSTOM"}
	dataScope := scopeMap[maxScope]

	// Issue a short-lived pre-auth token; TOTP verification issues the full token
	preAuthToken, err := utils.GeneratePreAuthToken(user.ID, dataScope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	if !user.TOTPEnabled {
		c.JSON(http.StatusOK, gin.H{
			"status":         "totp_setup_required",
			"pre_auth_token": preAuthToken,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"status":         "totp_required",
			"pre_auth_token": preAuthToken,
		})
	}
}

func Logout(c *gin.Context) {
	tokenString, err := c.Cookie("auth_token")
	if err != nil {
		tokenString = c.GetHeader("Authorization")
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}
	}

	if tokenString != "" {
		claims, err := utils.ParseToken(tokenString)
		if err == nil {
			blacklistEntry := model.SysTokenBlacklist{
				Token:     tokenString,
				ExpiresAt: claims.ExpiresAt.Time,
				CreatedAt: time.Now(),
			}
			database.DB.Create(&blacklistEntry)
		}
	}

	secure := config.AppConfig.AppEnv == "production"
	c.SetCookie("auth_token", "", -1, "/", "", secure, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
}

func Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := model.SysUser{
		Username:  req.Username,
		Password:  string(hashedPassword),
		Email:     req.Email,
		Status:    1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := database.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully", "uid": user.ID})
}
