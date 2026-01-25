package model

import (
	"time"

	"github.com/google/uuid"
)

// SysApp 应用表
type SysApp struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Code      string    `gorm:"type:varchar(50);uniqueIndex;not null" json:"code"`
	Name      string    `gorm:"type:varchar(100)" json:"name"`
	SecretKey string    `gorm:"type:varchar(64)" json:"secret_key"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SysPermission 权限字典表
type SysPermission struct {
	ID             uint64 `gorm:"primaryKey;autoIncrement" json:"id"`
	AppID          uint64 `gorm:"index;uniqueIndex:idx_app_bit_index;not null" json:"app_id"`
	PermissionCode string `gorm:"type:varchar(100);not null" json:"permission_code"`
	BitIndex       int16  `gorm:"type:smallint;uniqueIndex:idx_app_bit_index;not null" json:"bit_index"` // 0-127
	Description    string `gorm:"type:text" json:"description"`

	App SysApp `gorm:"foreignKey:AppID" json:"-"`
}

// SysRole 角色表
type SysRole struct {
	ID             uint64 `gorm:"primaryKey;autoIncrement" json:"id"`
	AppID          uint64 `gorm:"index;not null" json:"app_id"`
	Name           string `gorm:"type:varchar(50);not null" json:"name"`
	PermissionMask string `gorm:"type:char(32);not null;default:'00000000000000000000000000000000'" json:"permission_mask"` // 128位 Hex 字符串

	App       SysApp            `gorm:"foreignKey:AppID" json:"-"`
	DataScope *SysRoleDataScope `gorm:"foreignKey:RoleID;constraint:OnDelete:CASCADE" json:"data_scope,omitempty"`
}

// SysRoleDataScope 角色数据范围表
type SysRoleDataScope struct {
	ID           uint64 `gorm:"primaryKey;autoIncrement" json:"id"`
	RoleID       uint64 `gorm:"uniqueIndex;not null" json:"role_id"`
	ScopeType    int    `gorm:"type:smallint;not null;default:1" json:"scope_type"` // 1:Self, 2:Dept, 3:All, 4:Custom
	CustomConfig string `gorm:"type:text" json:"custom_config"`                     // Custom Dept IDs etc.

	Role SysRole `gorm:"foreignKey:RoleID" json:"-"`
}

// SysUserRole 用户-角色关联表
type SysUserRole struct {
	ID     uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID uuid.UUID `gorm:"type:uuid;index;not null" json:"user_id"`
	RoleID uint64    `gorm:"index;not null" json:"role_id"`
	AppID  uint64    `gorm:"index;not null" json:"app_id"`

	User SysUser `gorm:"foreignKey:UserID" json:"-"`
	Role SysRole `gorm:"foreignKey:RoleID" json:"role"`
	App  SysApp  `gorm:"foreignKey:AppID" json:"app"`
}

// SysUser 用户表
type SysUser struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Username string    `gorm:"type:varchar(50);uniqueIndex;not null" json:"username"`
	Email    string    `gorm:"type:varchar(100);uniqueIndex" json:"email"`
	Password string    `gorm:"type:varchar(255);not null" json:"-"`   // Store hashed password
	Status   int16     `gorm:"type:smallint;default:1" json:"status"` // 1:正常 0:禁用

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	UserRoles []SysUserRole `gorm:"foreignKey:UserID" json:"user_roles,omitempty"`
}

func (SysPermission) TableName() string {
	return "sys_permissions"
}

func (SysRole) TableName() string {
	return "sys_roles"
}

func (SysRoleDataScope) TableName() string {
	return "sys_role_data_scopes"
}

func (SysUser) TableName() string {
	return "sys_users"
}

func (SysUserRole) TableName() string {
	return "sys_user_roles"
}

func (SysApp) TableName() string {
	return "sys_apps"
}
