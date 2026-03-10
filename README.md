# UniAuth - 统一认证与授权系统

UniAuth 是一个基于 Go (Gin) 和 PostgreSQL 构建的轻量级、高性能的统一认证与授权系统。它旨在为多个下游应用提供集中的用户管理、认证（Authentication）和授权（Authorization）服务。

## 📖 项目简介

本项目设计初衷是为了解决微服务或多应用架构下的权限管理难题。它采用了 **RBAC (Role-Based Access Control)** 模型，并结合 **位掩码 (Bitmask)** 技术来实现高效的权限校验。同时，系统支持灵活的 **数据范围 (Data Scope)** 控制，满足复杂的业务需求。

### 核心特性

*   **多应用支持**: 单个 UniAuth 实例可同时管理多个业务系统的权限。
*   **高效权限校验**: 使用位掩码 (Bitmask) 表示权限，支持无限扩展（通过分段 Bucket 机制），校验速度极快。
*   **灵活的数据范围**: 支持 `仅本人`、`本部门`、`全部数据`、`自定义` 等多种数据权限粒度。
*   **JWT 认证**: 使用 JWT 进行无状态认证，支持 Token 黑名单机制（用于注销）。
*   **简单易用的管理界面**: 提供基础的 HTML/JS 前端用于管理应用、角色、权限和用户。

---

## 📂 项目结构

```text
UniAuth/
├── internal/               # 核心后端代码
│   ├── config/             # 配置加载 (环境变量/.env)
│   ├── database/           # 数据库连接与初始化
│   ├── handler/            # HTTP 请求处理器 (API Controller)
│   │   ├── auth_handler.go   # 登录、注册、注销
│   │   ├── user_handler.go   # 用户权限查询
│   │   ├── meta_handler.go   # 元数据查询 (如权限列表)
│   │   └── admin_handler.go  # 管理后台接口 (应用、角色、用户管理)
│   ├── middleware/         # Gin 中间件 (如 AuthMiddleware)
│   ├── model/              # GORM 数据库模型定义
│   └── utils/              # 工具函数 (JWT, Bitmask, Crypto)
├── web/                    # 前端静态资源
│   ├── index.html          # 登录页
│   ├── dashboard.html      # 用户个人中心 (演示权限获取)
│   └── admin.html          # 系统管理后台
├── .env                    # 环境变量配置文件 (需自行创建)
├── go.mod                  # Go 依赖管理
└── main.go                 # 程序入口
```

---

## 🚀 快速开始

### 1. 环境准备

*   **Go**: 1.18+
*   **PostgreSQL**: 12+

### 2. 配置数据库

创建一个 PostgreSQL 数据库（例如 `uniauth`）。

### 3. 配置文件

在项目根目录下创建 `.env` 文件，配置如下：

```env
SERVER_PORT=8080

# 数据库配置
DB_HOST=localhost
DB_USER=postgres
DB_PASSWORD=your_password
DB_NAME=uniauth
DB_PORT=5432
# 或者使用完整连接字符串 (优先级更高)
# DATABASE_URL=postgres://user:pass@localhost:5432/uniauth?sslmode=disable

# JWT 密钥
JWT_SECRET=your-super-secret-key-change-me
```

### 4. 运行项目

```bash
# 下载依赖
go mod tidy

# 运行
go run main.go
```

系统启动后，会自动根据 `model` 定义迁移数据库表结构。

访问地址:
*   登录页: `http://localhost:8080/web/index.html`
*   管理后台: `http://localhost:8080/web/admin.html` (需先登录并拥有管理员权限)

---

## 🛠 系统设计详解

### 1. 权限模型 (Bitmask)

UniAuth 使用位掩码来存储和校验权限，这比传统的“用户-权限”关联表更高效。

*   **SysPermission**: 定义了具体的权限点。每个权限都有一个 `BitIndex` (位索引)。
*   **SysRolePermissionMask**: 存储角色的权限。由于 64 位整数无法覆盖无限的权限，我们使用了 **分段 (Bucket)** 机制。
    *   `BucketIndex = 0`: 存储第 0-63 号权限
    *   `BucketIndex = 1`: 存储第 64-127 号权限
    *   以此类推...
*   **前端校验**: 后端返回合并后的 Hex 字符串掩码，前端将其转换为 BigInt 进行位运算校验。

### 2. 数据范围 (Data Scope)

除了功能权限，系统还控制用户能看到“哪些数据”。

*   **ScopeType**:
    *   `1 (SELF)`: 仅查看自己的数据。
    *   `2 (DEPT)`: 查看本部门及下级部门的数据 (基于 `sys_user_relations` 表)。
    *   `3 (ALL)`: 查看所有数据。
    *   `4 (CUSTOM)`: 自定义规则 (配合 `CustomConfig` 字段使用)。
*   **合并逻辑**: 如果用户拥有多个角色，系统会取所有角色中 **最大** 的权限范围 (Max Scope)。

### 3. 数据库核心表

*   `sys_apps`: 注册接入的子系统。
*   `sys_users`: 用户表。
*   `sys_roles`: 角色表 (归属于特定 App)。
*   `sys_user_roles`: 用户与角色的关联 (User <-> Role <-> App)。
*   `sys_permissions`: 权限定义 (BitIndex 的源头)。

---

## 🔌 API 概览

### 认证模块 (Auth)
*   `POST /api/auth/login`: 用户登录，返回 JWT 和 HttpOnly Cookie。
*   `POST /api/auth/logout`: 注销登录 (加入黑名单)。
*   `POST /api/auth/register`: 用户注册。

### 用户模块 (User)
*   `GET /api/user/mask?app_code={code}`: 获取当前用户在指定应用下的 **权限掩码** 和 **数据范围**。这是下游应用集成的核心接口。

### 元数据模块 (Meta)
*   `GET /api/meta/permissions?app_code={code}`: 获取指定应用的权限字典 (Code -> BitIndex 映射)。

### 管理模块 (Admin)
*需携带 Admin 权限 Token*

*   **应用管理**:
    *   `GET /api/admin/apps`: 列表
    *   `POST /api/admin/apps`: 创建
*   **权限管理**:
    *   `GET /api/admin/apps/:app_id/permissions`: 列表
    *   `POST /api/admin/apps/:app_id/permissions`: 创建
    *   `POST /api/admin/apps/:app_id/permissions/batch`: 批量导入
*   **角色管理**:
    *   `GET /api/admin/apps/:app_id/roles`: 列表
    *   `POST /api/admin/apps/:app_id/roles`: 创建
    *   `PUT /api/admin/roles/:role_id`: 更新 (权限掩码、数据范围)
*   **用户管理**:
    *   `GET /api/admin/users`: 列表
    *   `POST /api/admin/users`: 创建
    *   `POST /api/admin/users/:user_id/roles`: 分配角色

---

## 💻 前端说明

`web/` 目录下提供了简单的参考实现：

*   **admin.html**: 这是一个单页应用 (SPA) 风格的管理后台。它演示了如何调用 Admin API 来管理整个系统的元数据。
*   **dashboard.html**: 演示了普通用户登录后，如何调用 `/api/user/mask` 获取自己的权限，并根据权限展示不同的内容。

---

## 🤝 交接注意事项

1.  **初始化管理员**: 系统首次启动后，建议手动在数据库或通过注册接口创建一个用户，并赋予其 `uniauth-admin` 应用的超级管理员权限，以便进入后台管理。
2.  **位掩码扩展**: 目前前端 JS 处理 BigInt 兼容性较好，但需注意老旧浏览器可能不支持。
3.  **安全性**: 生产环境请务必开启 HTTPS，并设置 `Secure` Cookie 属性 (在 `auth_handler.go` 中修改)。
