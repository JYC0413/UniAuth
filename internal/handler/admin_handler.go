package handler

import (
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"UniAuth/internal/database"
	"UniAuth/internal/model"
	"UniAuth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// --- App Management ---

func ListApps(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userID := userIDStr.(uuid.UUID)

	scope := getMaxDataScope(userID)

	var apps []model.SysApp
	query := database.DB.Model(&model.SysApp{})

	if scope == 3 {
		// All data
	} else if scope == 2 {
		// Dept: Self + Subordinates
		subIDs, err := getAllSubordinateIDs(userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch subordinates"})
			return
		}
		allIDs := append(subIDs, userID)
		query = query.Where("id IN (SELECT app_id FROM sys_app_members WHERE user_id IN ?)", allIDs)
	} else {
		// Self (Default)
		query = query.Where("id IN (SELECT app_id FROM sys_app_members WHERE user_id = ?)", userID)
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	var total int64
	query.Count(&total)
	query = query.Offset(offset).Limit(limit)

	if err := query.Find(&apps).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch apps"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":  apps,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

type CreateAppRequest struct {
	Code string `json:"code" binding:"required"`
	Name string `json:"name" binding:"required"`
}

func CreateApp(c *gin.Context) {
	var req CreateAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	app := model.SysApp{
		Code: req.Code,
		Name: req.Name,
	}
	if err := database.DB.Create(&app).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create app"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": app})
}

// --- Permission Management ---

func ListAppPermissions(c *gin.Context) {
	appID := c.Param("app_id")
	var permissions []model.SysPermission
	if err := database.DB.Where("app_id = ?", appID).Order("bit_index asc").Find(&permissions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch permissions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": permissions})
}

type CreatePermissionRequest struct {
	PermissionCode string `json:"permission_code" binding:"required"`
	Description    string `json:"description"`
}

func CreateAppPermission(c *gin.Context) {
	appIDStr := c.Param("app_id")
	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid app ID"})
		return
	}

	var req CreatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find next available bit index
	var maxIndex *int
	database.DB.Model(&model.SysPermission{}).Where("app_id = ?", appID).Select("MAX(bit_index)").Scan(&maxIndex)

	nextIndex := 0
	if maxIndex != nil {
		nextIndex = *maxIndex + 1
	}

	if nextIndex > 32767 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "permission limit reached (max 32767 per app)"})
		return
	}

	perm := model.SysPermission{
		AppID:          uint64(appID),
		PermissionCode: req.PermissionCode,
		BitIndex:       int16(nextIndex),
		Description:    req.Description,
	}

	if err := database.DB.Create(&perm).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create permission"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": perm})
}

type UpdatePermissionRequest struct {
	PermissionCode string `json:"permission_code"`
	Description    string `json:"description"`
}

func UpdateAppPermission(c *gin.Context) {
	permID := c.Param("perm_id")
	var req UpdatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := make(map[string]interface{})
	if req.PermissionCode != "" {
		updates["permission_code"] = req.PermissionCode
	}
	updates["description"] = req.Description

	if err := database.DB.Model(&model.SysPermission{}).Where("id = ?", permID).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update permission"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Permission updated"})
}

func DeleteAppPermission(c *gin.Context) {
	permID := c.Param("perm_id")
	if err := database.DB.Delete(&model.SysPermission{}, permID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete permission"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Permission deleted"})
}

type BatchPermissionRequest struct {
	PermissionCode string `json:"permission_code"`
	BitIndex       *int16 `json:"bit_index"`
	Description    string `json:"description"`
}

func BatchCreateAppPermissions(c *gin.Context) {
	appIDStr := c.Param("app_id")
	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid app ID"})
		return
	}

	var reqs []BatchPermissionRequest
	if err := c.ShouldBindJSON(&reqs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = database.DB.Transaction(func(tx *gorm.DB) error {
		for _, req := range reqs {
			if req.PermissionCode == "" {
				continue
			}

			var existing model.SysPermission
			result := tx.Where("app_id = ? AND permission_code = ?", appID, req.PermissionCode).First(&existing)

			if result.Error == nil {
				// Update existing
				existing.Description = req.Description
				if err := tx.Save(&existing).Error; err != nil {
					return err
				}
			} else if result.Error == gorm.ErrRecordNotFound {
				// Create new
				perm := model.SysPermission{
					AppID:          uint64(appID),
					PermissionCode: req.PermissionCode,
					Description:    req.Description,
				}

				if req.BitIndex != nil {
					// Check if index is taken
					var count int64
					tx.Model(&model.SysPermission{}).
						Where("app_id = ? AND bit_index = ?", appID, *req.BitIndex).
						Count(&count)

					if count > 0 {
						return gorm.ErrInvalidData
					}
					perm.BitIndex = *req.BitIndex
				} else {
					// Auto assign
					var maxIndex *int
					tx.Model(&model.SysPermission{}).Where("app_id = ?", appID).Select("MAX(bit_index)").Scan(&maxIndex)
					nextIndex := 0
					if maxIndex != nil {
						nextIndex = *maxIndex + 1
					}
					if nextIndex > 32767 {
						return fmt.Errorf("permission limit reached (max 32767 per app)")
					}
					perm.BitIndex = int16(nextIndex)
				}

				if err := tx.Create(&perm).Error; err != nil {
					return err
				}
			} else {
				return result.Error
			}
		}
		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to batch import: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Batch import successful"})
}

// --- Role Management ---

func ListAppRoles(c *gin.Context) {
	appID := c.Param("app_id")
	var roles []model.SysRole
	// Preload DataScope and PermissionMasks
	if err := database.DB.Preload("DataScope").Preload("PermissionMasks").Where("app_id = ?", appID).Find(&roles).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch roles"})
		return
	}

	// Populate PermissionMask field for API compatibility
	for i := range roles {
		finalMask := new(big.Int)
		for _, pm := range roles[i].PermissionMasks {
			uVal := uint64(pm.Mask)
			bucketBig := new(big.Int).SetUint64(uVal)
			shift := uint(pm.BucketIndex) * 64
			bucketBig.Lsh(bucketBig, shift)
			finalMask.Or(finalMask, bucketBig)
		}
		roles[i].PermissionMask = utils.MaskToHex(finalMask)
	}

	c.JSON(http.StatusOK, gin.H{"data": roles})
}

func GetRole(c *gin.Context) {
	roleID := c.Param("role_id")
	var role model.SysRole
	if err := database.DB.Preload("DataScope").Preload("PermissionMasks").First(&role, roleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}

	// Populate PermissionMask field for API compatibility
	finalMask := new(big.Int)
	for _, pm := range role.PermissionMasks {
		uVal := uint64(pm.Mask)
		bucketBig := new(big.Int).SetUint64(uVal)
		shift := uint(pm.BucketIndex) * 64
		bucketBig.Lsh(bucketBig, shift)
		finalMask.Or(finalMask, bucketBig)
	}
	role.PermissionMask = utils.MaskToHex(finalMask)

	c.JSON(http.StatusOK, gin.H{"data": role})
}

type CreateRoleRequest struct {
	Name           string `json:"name" binding:"required"`
	PermissionMask string `json:"permission_mask"` // Optional initial mask (Hex string)
}

func CreateAppRole(c *gin.Context) {
	appIDStr := c.Param("app_id")
	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid app ID"})
		return
	}

	var req CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	role := model.SysRole{
		AppID: uint64(appID),
		Name:  req.Name,
	}

	// Transaction to create role, default data scope, and permission masks
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&role).Error; err != nil {
			return err
		}
		// Default Data Scope: Self (1)
		dataScope := model.SysRoleDataScope{
			RoleID:    role.ID,
			ScopeType: 1,
		}
		if err := tx.Create(&dataScope).Error; err != nil {
			return err
		}

		// Handle Permission Mask if provided
		if req.PermissionMask != "" {
			maskBigInt := utils.ParseMask(req.PermissionMask)
			// Split into buckets
			// Assuming 64-bit buckets.
			// We need to iterate through bits of the BigInt and set appropriate buckets.
			// Or simpler: iterate 0 to max bit length of BigInt.
			// Since ParseMask returns a BigInt, we can check bits.
			// However, BigInt doesn't easily give "max set bit" without calculation.
			// Let's assume we support up to some reasonable number or just iterate until 0.
			// Actually, we can just iterate through buckets until the mask is consumed.

			// But wait, the input is a Hex string representing the FULL mask.
			// We need to slice this BigInt into 64-bit chunks.

			bucketIndex := int16(0)
			for maskBigInt.Sign() > 0 {
				// Get lower 64 bits
				lower64 := new(big.Int).And(maskBigInt, new(big.Int).SetUint64(^uint64(0)))
				maskVal := lower64.Int64()

				if maskVal != 0 {
					permMask := model.SysRolePermissionMask{
						RoleID:      role.ID,
						BucketIndex: bucketIndex,
						Mask:        maskVal,
					}
					if err := tx.Create(&permMask).Error; err != nil {
						return err
					}
				}

				// Shift right by 64
				maskBigInt.Rsh(maskBigInt, 64)
				bucketIndex++
			}
		}

		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create role"})
		return
	}
	// Reload role to include relations
	database.DB.Preload("PermissionMasks").First(&role, role.ID)

	// Populate PermissionMask field for API compatibility
	finalMask := new(big.Int)
	for _, pm := range role.PermissionMasks {
		uVal := uint64(pm.Mask)
		bucketBig := new(big.Int).SetUint64(uVal)
		shift := uint(pm.BucketIndex) * 64
		bucketBig.Lsh(bucketBig, shift)
		finalMask.Or(finalMask, bucketBig)
	}
	role.PermissionMask = utils.MaskToHex(finalMask)

	c.JSON(http.StatusCreated, gin.H{"data": role})
}

type UpdateRoleRequest struct {
	PermissionMask string `json:"permission_mask"`
	ScopeType      int    `json:"scope_type"`
	CustomConfig   string `json:"custom_config"`
}

func UpdateRole(c *gin.Context) {
	roleIDStr := c.Param("role_id")
	roleID, err := parseUint(roleIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ID"})
		return
	}

	var req UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = database.DB.Transaction(func(tx *gorm.DB) error {
		// Update Mask if provided
		if req.PermissionMask != "" {
			// First, delete existing masks for this role
			if err := tx.Delete(&model.SysRolePermissionMask{}, "role_id = ?", roleID).Error; err != nil {
				return err
			}

			maskBigInt := utils.ParseMask(req.PermissionMask)
			bucketIndex := int16(0)
			for maskBigInt.Sign() > 0 {
				lower64 := new(big.Int).And(maskBigInt, new(big.Int).SetUint64(^uint64(0)))
				maskVal := lower64.Int64()

				if maskVal != 0 {
					permMask := model.SysRolePermissionMask{
						RoleID:      roleID,
						BucketIndex: bucketIndex,
						Mask:        maskVal,
					}
					if err := tx.Create(&permMask).Error; err != nil {
						return err
					}
				}
				maskBigInt.Rsh(maskBigInt, 64)
				bucketIndex++
			}
		}

		// Update Data Scope if provided
		if req.ScopeType > 0 {
			var scope model.SysRoleDataScope
			result := tx.Where("role_id = ?", roleID).First(&scope)
			if result.Error != nil {
				if result.Error == gorm.ErrRecordNotFound {
					// Create if not exists
					scope = model.SysRoleDataScope{
						RoleID:       roleID,
						ScopeType:    req.ScopeType,
						CustomConfig: req.CustomConfig,
					}
					if err := tx.Create(&scope).Error; err != nil {
						return err
					}
				} else {
					return result.Error
				}
			} else {
				// Update
				scope.ScopeType = req.ScopeType
				scope.CustomConfig = req.CustomConfig
				if err := tx.Save(&scope).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Role updated"})
}

func parseUint(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

// --- User Management ---

func ListUsers(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userID := userIDStr.(uuid.UUID)

	scope := getMaxDataScope(userID)

	var users []model.SysUser
	query := database.DB.
		Model(&model.SysUser{}).
		Preload("UserRoles.Role").
		Preload("UserRoles.App")

	if scope == 3 {
		// All
	} else if scope == 2 {
		// Dept
		subIDs, err := getAllSubordinateIDs(userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch subordinates"})
			return
		}
		allIDs := append(subIDs, userID)
		query = query.Where("id IN ?", allIDs)
	} else {
		// Self
		query = query.Where("id = ?", userID)
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	var total int64
	query.Count(&total)
	query = query.Offset(offset).Limit(limit)

	if err := query.Find(&users).Error; err != nil {
		log.Printf("ListUsers DB error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":  users,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

type CreateUserRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func CreateUser(c *gin.Context) {
	var req CreateUserRequest
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
		Email:     req.Email,
		Password:  string(hashedPassword),
		Status:    1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := database.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": user})
}

type SetRoleRequest struct {
	RoleID uint64 `json:"role_id" binding:"required"`
	AppID  uint64 `json:"app_id" binding:"required"`
}

func SetUserRole(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req SetRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Upsert Logic: Check if user already has a role for this app
	var userRole model.SysUserRole
	result := database.DB.Where("user_id = ? AND app_id = ?", userID, req.AppID).First(&userRole)

	if result.Error == nil {
		// Update existing role
		userRole.RoleID = req.RoleID
		if err := database.DB.Save(&userRole).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Role updated"})
	} else if result.Error == gorm.ErrRecordNotFound {
		// Create new assignment
		userRole = model.SysUserRole{
			UserID: userID,
			RoleID: req.RoleID,
			AppID:  req.AppID,
		}
		if err := database.DB.Create(&userRole).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign role"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"message": "Role assigned"})
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
	}
}

func GetUserAppRole(c *gin.Context) {
	userIDStr := c.Param("user_id")
	appIDStr := c.Param("app_id")

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	appID, err := strconv.ParseUint(appIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid app ID"})
		return
	}

	var userRole model.SysUserRole
	if err := database.DB.Preload("Role").Where("user_id = ? AND app_id = ?", userID, appID).First(&userRole).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusOK, gin.H{"data": nil}) // No role assigned
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": userRole.Role})
}

// --- Helper for Admin Check ---

func CheckAdminPermission(c *gin.Context) {
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userID := userIDStr.(uuid.UUID)

	// 1. Find 'uniauth-admin' app
	var adminApp model.SysApp
	if err := database.DB.Where("code = ?", "uniauth-admin").First(&adminApp).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Admin system not initialized"})
		return
	}

	// 2. Get User's Mask for 'uniauth-admin'
	var userRoles []model.SysUserRole
	if err := database.DB.Preload("Role.PermissionMasks").Where("user_id = ? AND app_id = ?", userID, adminApp.ID).Find(&userRoles).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permissions"})
		return
	}

	finalMask := new(big.Int)
	for _, ur := range userRoles {
		for _, pm := range ur.Role.PermissionMasks {
			// Reconstruct BigInt from buckets
			// Handle negative int64 (two's complement) if necessary, but big.NewInt handles int64 correctly.
			// However, we treated it as unsigned bits.
			// If the top bit of int64 is set, it's negative.
			// We want the unsigned 64-bit value.
			// Go's big.NewInt takes int64.
			// If we want to treat it as uint64, we should use SetUint64.
			// Since we stored it as int64 in DB (Postgres bigint), we need to be careful.
			// Let's cast to uint64 before setting to BigInt to be safe.
			uVal := uint64(pm.Mask)
			bucketBig := new(big.Int).SetUint64(uVal)

			shift := uint(pm.BucketIndex) * 64
			bucketBig.Lsh(bucketBig, shift)
			finalMask.Or(finalMask, bucketBig)
		}
	}

	// 3. Check that bit 0 (admin.access) is set in the uniauth-admin mask.
	// Bit 0 is reserved for "admin.access" — the first permission created by setup_admin.go.
	adminBit := new(big.Int).SetBit(new(big.Int), 0, 1)
	if new(big.Int).And(finalMask, adminBit).Cmp(adminBit) != 0 {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	c.Next()
}

// --- Helpers ---

func getMaxDataScope(userID uuid.UUID) int {
	var adminApp model.SysApp
	if err := database.DB.Where("code = ?", "uniauth-admin").First(&adminApp).Error; err != nil {
		return 1 // Default to Self
	}

	var userRoles []model.SysUserRole
	if err := database.DB.Preload("Role.DataScope").Where("user_id = ? AND app_id = ?", userID, adminApp.ID).Find(&userRoles).Error; err != nil {
		return 1
	}

	maxScope := 0
	for _, ur := range userRoles {
		if ur.Role.DataScope != nil {
			if ur.Role.DataScope.ScopeType > maxScope {
				maxScope = ur.Role.DataScope.ScopeType
			}
		}
	}
	if maxScope == 0 {
		return 1
	}
	return maxScope
}

func getAllSubordinateIDs(managerID uuid.UUID) ([]uuid.UUID, error) {
	type Result struct {
		SubordinateID uuid.UUID
	}
	var results []Result
	query := `
	WITH RECURSIVE subordinates AS (
		SELECT subordinate_id FROM sys_user_relations WHERE manager_id = ?
		UNION
		SELECT r.subordinate_id FROM sys_user_relations r
		INNER JOIN subordinates s ON r.manager_id = s.subordinate_id
	)
	SELECT subordinate_id FROM subordinates;
	`
	if err := database.DB.Raw(query, managerID).Scan(&results).Error; err != nil {
		return nil, err
	}

	ids := make([]uuid.UUID, len(results))
	for i, r := range results {
		ids[i] = r.SubordinateID
	}
	return ids, nil
}
