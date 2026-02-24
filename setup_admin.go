package main

import (
	"bufio"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"UniAuth/internal/config"
	"UniAuth/internal/database"
	"UniAuth/internal/model"
	"UniAuth/internal/utils"
)

func main() {
	// 1. 加载配置和连接数据库
	// 注意：这里假设 .env 文件在当前目录下
	config.LoadConfig()
	database.ConnectDB()

	fmt.Println("--- UniAuth Admin Bootstrap ---")

	// 2. 确保 'uniauth-admin' 应用存在
	var app model.SysApp
	if err := database.DB.Where("code = ?", "uniauth-admin").First(&app).Error; err != nil {
		log.Println("Creating 'uniauth-admin' app...")
		app = model.SysApp{
			Code:      "uniauth-admin",
			Name:      "UniAuth Admin Portal",
			SecretKey: "admin-secret-key", // 在生产环境中应生成随机字串
		}
		if err := database.DB.Create(&app).Error; err != nil {
			log.Fatal("Failed to create app:", err)
		}
	} else {
		log.Println("App 'uniauth-admin' already exists.")
	}

	// 3. 确保 'Super Admin' 角色存在
	// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF (32 chars) = 128 bits of 1
	fullMask := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"

	var role model.SysRole
	// Check if role exists
	result := database.DB.Where("app_id = ? AND name = ?", app.ID, "Super Admin").First(&role)

	if result.Error != nil {
		log.Println("Creating 'Super Admin' role...")
		role = model.SysRole{
			AppID: app.ID,
			Name:  "Super Admin",
		}
		if err := database.DB.Create(&role).Error; err != nil {
			log.Fatal("Failed to create role:", err)
		}

		// Create Data Scope for Super Admin (All Data)
		dataScope := model.SysRoleDataScope{
			RoleID:    role.ID,
			ScopeType: 3, // All
		}
		if err := database.DB.Create(&dataScope).Error; err != nil {
			log.Fatal("Failed to create data scope:", err)
		}

		// Create Permission Masks
		createPermissionMasks(role.ID, fullMask)

	} else {
		log.Println("Role 'Super Admin' already exists. Updating mask to full permissions...")
		// Update masks
		// First delete existing
		database.DB.Delete(&model.SysRolePermissionMask{}, "role_id = ?", role.ID)
		createPermissionMasks(role.ID, fullMask)

		// Ensure Data Scope exists
		var ds model.SysRoleDataScope
		if err := database.DB.Where("role_id = ?", role.ID).First(&ds).Error; err != nil {
			dataScope := model.SysRoleDataScope{
				RoleID:    role.ID,
				ScopeType: 3, // All
			}
			database.DB.Create(&dataScope)
		} else {
			database.DB.Model(&ds).Update("scope_type", 3)
		}
	}

	// 4. 获取要提升的用户
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\n请输入你刚才注册的用户名 (Username): ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	if username == "" {
		log.Fatal("Username cannot be empty.")
	}

	var user model.SysUser
	if err := database.DB.Where("username = ?", username).First(&user).Error; err != nil {
		log.Fatalf("User '%s' not found in database. Please make sure you have registered via the API or Web page first.", username)
	}

	// 5. 分配角色
	var userRole model.SysUserRole
	if err := database.DB.Where("user_id = ? AND role_id = ?", user.ID, role.ID).First(&userRole).Error; err != nil {
		log.Printf("Assigning 'Super Admin' role to user '%s'...", username)
		userRole = model.SysUserRole{
			UserID: user.ID,
			RoleID: role.ID,
			AppID:  app.ID,
		}
		if err := database.DB.Create(&userRole).Error; err != nil {
			log.Fatal("Failed to assign role:", err)
		}
		fmt.Println("\n✅ Success! User has been promoted to Admin.")
		fmt.Println("You can now login and access: http://localhost:8080/admin")
	} else {
		fmt.Println("\n⚠️  User is already an Admin.")
	}
}

func createPermissionMasks(roleID uint64, hexMask string) {
	maskBigInt := utils.ParseMask(hexMask)
	bucketIndex := int16(0)
	// If mask is 0, loop won't run, which is fine (sparse storage)
	// But we need to handle the case where maskBigInt > 0
	for maskBigInt.Sign() > 0 {
		lower64 := new(big.Int).And(maskBigInt, new(big.Int).SetUint64(^uint64(0)))
		maskVal := lower64.Int64()

		if maskVal != 0 {
			permMask := model.SysRolePermissionMask{
				RoleID:      roleID,
				BucketIndex: bucketIndex,
				Mask:        maskVal,
			}
			database.DB.Create(&permMask)
		}
		maskBigInt.Rsh(maskBigInt, 64)
		bucketIndex++
	}
}
