package database

import (
	"fmt"
	"log"

	"UniAuth/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDB() {
	var dsn string
	if config.AppConfig.DatabaseURL != "" {
		dsn = config.AppConfig.DatabaseURL
	} else {
		dsn = fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Shanghai",
			config.AppConfig.DBHost,
			config.AppConfig.DBUser,
			config.AppConfig.DBPassword,
			config.AppConfig.DBName,
			config.AppConfig.DBPort,
		)
	}

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}

	log.Println("Database connected successfully")

	// Auto Migrate
	//err = DB.AutoMigrate(
	//	&model.SysApp{},
	//	&model.SysPermission{},
	//	&model.SysRole{},
	//	&model.SysUser{},
	//	&model.SysUserRole{},
	//	&model.SysRoleDataScope{},
	//)
	//if err != nil {
	//	log.Fatal("Failed to migrate database: ", err)
	//}
}
