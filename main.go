package main

import (
	"log"
	"net/http"

	"UniAuth/internal/config"
	"UniAuth/internal/database"
	"UniAuth/internal/handler"
	"UniAuth/internal/middleware"

	"github.com/gin-gonic/gin"
)

func main() {
	// Load Config
	config.LoadConfig()

	// Connect Database
	database.ConnectDB()

	r := gin.Default()

	// Serve static files for frontend
	r.Static("/static", "./web")
	r.LoadHTMLGlob("web/*.html")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})
	r.GET("/dashboard", func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", nil)
	})
	r.GET("/admin", func(c *gin.Context) {
		c.HTML(http.StatusOK, "admin.html", nil)
	})

	// Public Routes
	r.POST("/api/v1/auth/login", handler.Login)
	// r.POST("/api/v1/auth/register", handler.Register) // Removed public registration
	r.POST("/api/v1/auth/logout", handler.Logout)
	r.GET("/api/v1/meta/permissions", handler.GetPermissions)

	// Protected Routes
	auth := r.Group("/api/v1/auth")
	auth.Use(middleware.AuthMiddleware())
	{
		auth.GET("/my-mask", handler.GetUserMask)
	}

	// Admin Routes
	admin := r.Group("/api/v1/admin")
	admin.Use(middleware.AuthMiddleware())
	admin.Use(handler.CheckAdminPermission) // Security: Enabled Admin Check
	{
		// Apps
		admin.GET("/apps", handler.ListApps)
		admin.POST("/apps", handler.CreateApp)

		// Permissions
		admin.GET("/apps/:app_id/permissions", handler.ListAppPermissions)
		admin.POST("/apps/:app_id/permissions", handler.CreateAppPermission)
		admin.POST("/apps/:app_id/permissions/batch", handler.BatchCreateAppPermissions) // Batch Import
		admin.PUT("/permissions/:perm_id", handler.UpdateAppPermission)
		admin.DELETE("/permissions/:perm_id", handler.DeleteAppPermission)

		// Roles
		admin.GET("/apps/:app_id/roles", handler.ListAppRoles)
		admin.POST("/apps/:app_id/roles", handler.CreateAppRole)
		admin.GET("/roles/:role_id", handler.GetRole)
		admin.PUT("/roles/:role_id", handler.UpdateRole)

		// Users
		admin.GET("/users", handler.ListUsers)
		admin.POST("/users", handler.CreateUser)                               // Admin creates user
		admin.GET("/users/:user_id/apps/:app_id/role", handler.GetUserAppRole) // Get current role
		admin.PUT("/users/:user_id/roles", handler.SetUserRole)                // Set/Update role
	}

	log.Printf("Server starting on port %s", config.AppConfig.ServerPort)
	if err := r.Run(":" + config.AppConfig.ServerPort); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}
