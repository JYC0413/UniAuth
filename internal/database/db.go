package database

import (
	"fmt"
	"log"
	"time"

	"UniAuth/internal/config"
	"UniAuth/internal/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDB() {
	var dsn string
	if config.AppConfig.DatabaseURL != "" {
		dsn = config.AppConfig.DatabaseURL
	} else {
		dsn = fmt.Sprintf(
			"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
			config.AppConfig.DBHost,
			config.AppConfig.DBUser,
			config.AppConfig.DBPassword,
			config.AppConfig.DBName,
			config.AppConfig.DBPort,
			config.AppConfig.DBSSLMode,
			config.AppConfig.DBTimezone,
		)
	}

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}

	log.Println("Database connected successfully")
}

// StartBlacklistCleanup deletes expired token blacklist entries.
// Runs once immediately on startup, then every 24 hours in a background goroutine.
func StartBlacklistCleanup() {
	cleanupOnce := func() {
		result := DB.Where("expires_at < ?", time.Now()).Delete(&model.SysTokenBlacklist{})
		if result.Error != nil {
			log.Printf("Blacklist cleanup error: %v", result.Error)
		} else {
			log.Printf("Blacklist cleanup: deleted %d expired entries", result.RowsAffected)
		}
	}

	cleanupOnce()

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cleanupOnce()
		}
	}()
}
