package main

import (
	"log"
	"net/http"
	"strings"

	"UniAuth/internal/config"
	"UniAuth/internal/database"
	"UniAuth/internal/handler"
	"UniAuth/internal/middleware"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadConfig()
	database.ConnectDB()
	database.StartBlacklistCleanup()

	r := gin.Default()

	// Request body size limit: 4MB
	r.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4<<20)
		c.Next()
	})

	// CORS — only enabled if CORS_ALLOWED_ORIGINS is configured
	if origins := config.AppConfig.CORSAllowedOrigins; origins != "" {
		corsConfig := cors.DefaultConfig()
		corsConfig.AllowOrigins = strings.Split(origins, ",")
		corsConfig.AllowCredentials = true
		corsConfig.AddAllowHeaders("Authorization")
		r.Use(cors.New(corsConfig))
	}

	// Static / HTML
	r.Static("/static", "./web")
	r.LoadHTMLGlob("web/*.html")
	r.GET("/", func(c *gin.Context) { c.HTML(http.StatusOK, "index.html", nil) })
	r.GET("/dashboard", func(c *gin.Context) { c.HTML(http.StatusOK, "dashboard.html", nil) })
	r.GET("/admin", func(c *gin.Context) { c.HTML(http.StatusOK, "admin.html", nil) })

	// Public routes
	r.POST("/api/v1/auth/login", middleware.LoginRateLimiter(), handler.Login)
	r.POST("/api/v1/auth/logout", handler.Logout)
	r.GET("/api/v1/meta/permissions", handler.GetPermissions)

	// TOTP routes — require pre_auth_token (issued by login, before full auth)
	totp := r.Group("/api/v1/auth/totp")
	totp.Use(middleware.PreAuthMiddleware())
	{
		totp.GET("/setup", handler.TOTPSetup)
		totp.POST("/enroll", handler.TOTPEnroll)
		totp.POST("/verify", handler.TOTPVerify)
	}

	// Protected routes — require full auth_token
	auth := r.Group("/api/v1/auth")
	auth.Use(middleware.AuthMiddleware())
	{
		auth.GET("/my-mask", handler.GetUserMask)
	}

	// Admin routes — require full auth_token + admin bit 0
	admin := r.Group("/api/v1/admin")
	admin.Use(middleware.AuthMiddleware())
	admin.Use(handler.CheckAdminPermission)
	{
		admin.GET("/apps", handler.ListApps)
		admin.POST("/apps", handler.CreateApp)

		admin.GET("/apps/:app_id/permissions", handler.ListAppPermissions)
		admin.POST("/apps/:app_id/permissions", handler.CreateAppPermission)
		admin.POST("/apps/:app_id/permissions/batch", handler.BatchCreateAppPermissions)
		admin.PUT("/permissions/:perm_id", handler.UpdateAppPermission)
		admin.DELETE("/permissions/:perm_id", handler.DeleteAppPermission)

		admin.GET("/apps/:app_id/roles", handler.ListAppRoles)
		admin.POST("/apps/:app_id/roles", handler.CreateAppRole)
		admin.GET("/roles/:role_id", handler.GetRole)
		admin.PUT("/roles/:role_id", handler.UpdateRole)

		admin.GET("/users", handler.ListUsers)
		admin.POST("/users", handler.CreateUser)
		admin.GET("/users/:user_id/apps/:app_id/role", handler.GetUserAppRole)
		admin.PUT("/users/:user_id/roles", handler.SetUserRole)
		admin.POST("/users/:user_id/totp/reset", handler.TOTPReset)
	}

	log.Printf("Server starting on port %s (env: %s)", config.AppConfig.ServerPort, config.AppConfig.AppEnv)
	if err := r.Run(":" + config.AppConfig.ServerPort); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}
