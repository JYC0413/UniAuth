package handler

import (
	"net/http"
	"time"

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

	// Determine Data Scope (Simplified Logic: Take the highest scope from roles)
	// In a real system, you might merge scopes or return a list.
	// Here we just take the max scope_type found in user's roles for simplicity.
	var maxScope int = 1 // Default Self
	var userRoles []model.SysUserRole
	if err := database.DB.Preload("Role.DataScope").Where("user_id = ?", user.ID).Find(&userRoles).Error; err == nil {
		for _, ur := range userRoles {
			if ur.Role.DataScope != nil {
				if ur.Role.DataScope.ScopeType > maxScope {
					maxScope = ur.Role.DataScope.ScopeType
				}
			}
		}
	}

	scopeMap := map[int]string{
		1: "SELF",
		2: "DEPT",
		3: "ALL",
		4: "CUSTOM",
	}
	dataScopeStr := scopeMap[maxScope]

	token, err := utils.GenerateToken(user.ID, dataScopeStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Set HttpOnly Cookie
	c.SetCookie("auth_token", token, 3600*24, "/", "", false, true) // Secure should be true in production

	c.JSON(http.StatusOK, gin.H{
		"message":    "Login successful",
		"data_scope": dataScopeStr,
	})
}

func Logout(c *gin.Context) {
	c.SetCookie("auth_token", "", -1, "/", "", false, true)
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
