package model

import (
	"time"

	"github.com/google/uuid"
)

// SysApp 应用表
type SysApp struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Code        string    `gorm:"type:varchar(50);uniqueIndex;not null" json:"code"`
	Name        string    `gorm:"type:varchar(100)" json:"name"`
	SecretKey   string    `gorm:"type:varchar(64)" json:"secret_key"`
	RedirectURL string    `gorm:"type:varchar(255)" json:"redirect_url"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
	ID    uint64 `gorm:"primaryKey;autoIncrement" json:"id"`
	AppID uint64 `gorm:"index;not null" json:"app_id"`
	Name  string `gorm:"type:varchar(50);not null" json:"name"`

	// PermissionMask is not stored in DB anymore, but populated for API compatibility
	PermissionMask string `gorm:"-" json:"permission_mask"`

	App             SysApp                  `gorm:"foreignKey:AppID" json:"-"`
	DataScope       *SysRoleDataScope       `gorm:"foreignKey:RoleID;constraint:OnDelete:CASCADE" json:"data_scope,omitempty"`
	PermissionMasks []SysRolePermissionMask `gorm:"foreignKey:RoleID;constraint:OnDelete:CASCADE" json:"permission_masks,omitempty"`
}

// SysRolePermissionMask 角色权限位分段表
type SysRolePermissionMask struct {
	RoleID      uint64 `gorm:"primaryKey;autoIncrement:false" json:"role_id"`
	BucketIndex int16  `gorm:"primaryKey;autoIncrement:false;type:smallint" json:"bucket_index"` // 0: 0-63, 1: 64-127...
	Mask        int64  `gorm:"type:bigint;not null;default:0" json:"mask"`                       // 64位掩码

	Role SysRole `gorm:"foreignKey:RoleID" json:"-"`
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

// SysAppMember 应用成员表 (记录谁维护哪个App)
type SysAppMember struct {
	AppID    uint64    `gorm:"primaryKey;autoIncrement:false" json:"app_id"`
	UserID   uuid.UUID `gorm:"type:uuid;primaryKey" json:"user_id"`
	RoleType int16     `gorm:"type:smallint;default:1" json:"role_type"` // 1: Owner, 2: Member

	App  SysApp  `gorm:"foreignKey:AppID" json:"app"`
	User SysUser `gorm:"foreignKey:UserID" json:"user"`
}

// SysUserRelation 用户上下级关系表
type SysUserRelation struct {
	ManagerID     uuid.UUID `gorm:"type:uuid;primaryKey" json:"manager_id"`
	SubordinateID uuid.UUID `gorm:"type:uuid;primaryKey" json:"subordinate_id"`

	Manager     SysUser `gorm:"foreignKey:ManagerID" json:"manager"`
	Subordinate SysUser `gorm:"foreignKey:SubordinateID" json:"subordinate"`
}

// SysTokenBlacklist Token黑名单表
type SysTokenBlacklist struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Token     string    `gorm:"type:varchar(512);uniqueIndex;not null" json:"token"`
	ExpiresAt time.Time `gorm:"index;not null" json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (SysPermission) TableName() string {
	return "sys_permissions"
}

func (SysRole) TableName() string {
	return "sys_roles"
}

func (SysRolePermissionMask) TableName() string {
	return "sys_role_permission_masks"
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

func (SysAppMember) TableName() string {
	return "sys_app_members"
}

func (SysUserRelation) TableName() string {
	return "sys_user_relations"
}

func (SysTokenBlacklist) TableName() string {
	return "sys_token_blacklist"
}
