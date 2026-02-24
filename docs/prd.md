# 统一身份认证与权限管理平台 (UniAuth) PRD

| 项目名称 | UniAuth 统一鉴权中心 |
| --- | --- |
| **文档版本** | V1.4.0 |
| **文档状态** | 正式发布 |
| **技术栈** | Backend: **Go (Gin)**<br>Database: **Supabase (PostgreSQL)**<br>Protocol: **OAuth2 / OIDC + Bitmask** |

---

## 1. 项目背景与目标

### 1.1 项目背景

随着业务线的扩张，存在多个独立的业务平台（CRM、ERP、WMS等）。当前各系统独立维护用户体系，导致用户体验割裂、权限管理混乱、维护成本高昂。需构建一套统一的身份认证中心，实现“一次登录，全网通行”。

### 1.2 核心目标

1. **统一身份源 (Centralized Identity)**：所有用户信息托管在 Supabase 统一数据库中。
2. **单点登录 (SSO)**：基于 Cookie/Token 机制，实现多子系统间的无感登录。
3. **高性能鉴权 (High Performance)**：摒弃传统的字符串匹配，采用 **无限位掩码 (Infinite Bitmask)** 算法，实现微秒级权限判定，极低内存占用。
4. **安全隔离**：业务系统不直接接触用户密码，通过标准协议与鉴权中心交互。
5. **可视化管理 (Admin Dashboard)**：提供完整的 Web 管理界面，用于应用管理、权限配置、角色分配及用户授权。

---

## 2. 系统架构设计

### 2.1 逻辑架构图

系统划分为 **鉴权中心 (Auth Service)** 与 **业务子系统 (Business Apps)** 两大域。

* **鉴权中心 (Provider)**：负责颁发 Token、管理权限字典、计算位掩码。包含 **Admin Portal (管理后台)**。
* **业务系统 (Consumer)**：负责定义所需权限（注册字典）、同步位掩码、执行本地位运算鉴权。

### 2.2 核心机制：无限位掩码 (Infinite Bitmask Permission)

每个应用（App）拥有独立的权限空间，支持无限数量的原子权限点（Index 0-N）。

* **权限字典 (Dictionary)**：
    * `Permission A` -> `Index 0` -> `Bucket 0, Bit 0`
    * `Permission B` -> `Index 65` -> `Bucket 1, Bit 1`

* **分桶存储 (Bucket Storage)**：
    * 权限位被切分为多个 **64位桶 (Bucket)**。
    * `Bucket Index = Bit Index / 64`
    * `Bit Offset = Bit Index % 64`
    * 数据库仅存储非空的桶，实现稀疏存储。

* **角色/用户掩码 (Mask Calculation)**：
    * 用户持有权限 A (Index 0) 和 B (Index 65)。
    * `UserMask` = `Bucket 0: 0x1` + `Bucket 1: 0x2`。
    * API 返回时合并为一个完整的 Hex String。

* **存储格式**：
    * 数据库中不再存储定长字符串，而是存储在 `sys_role_permission_masks` 表中，每行记录一个桶的 64 位掩码 (BigInt)。
    * Go 后端使用 `math/big` 包进行高精度运算和合并。

---

## 3. 功能需求详细说明

### 3.1 模块一：认证服务 (Authentication)

此模块运行在鉴权中心，面向所有用户和业务系统。

#### F1. 用户登录 (SSO Login)
* **输入**：用户名、密码。
* **处理逻辑**：
    1. 校验 Supabase `sys_users` 表中的密码哈希（使用 Argon2）。
    2. 验证通过后，生成 **Global Session (JWT)**。
    3. **关键动作**：在根域名（如 `.company.com`）下种入 `HttpOnly` Cookie。
    4. **Token 传递**：登录成功后，返回 JWT Token。前端在跳转回业务系统（Redirect URL）时，会将 Token 作为 Query Parameter 传递（例如 `?token=...`），以便业务系统（或 Admin Portal）在无 Cookie 环境下也能进行 API 调用。
* **输出**：SSO Cookie, JWT Token 及 重定向指令。

#### F2. 令牌签发 (Token Issue)
* **内容**：JWT Payload 中包含 `uid` 和 `data_scope`。
* **Payload 规范**：
```json
{
  "uid": "uuid-xxx",
  "data_scope": "SELF", // 数据权限范围
  "iss": "auth.company.com",
  "exp": 1735660800
}
```

#### F3. 用户注销 (Global Logout)
* **逻辑**：
    1. 清除根域名 Cookie。
    2. **Token 黑名单 (Blacklist)**：将当前 JWT Token 加入数据库黑名单表 (`sys_token_blacklist`)，并记录过期时间。
    3. 中间件层拦截所有在黑名单中的 Token 请求。

### 3.2 模块二：权限管理 (Authorization Logic)

此模块为后台管理功能，用于配置“谁有什么权限”。

#### F4. 应用与权限字典管理
* **应用注册**：创建新的 `AppID` (如 `crm`, `wms`)。
* **权限位分配 (核心)**：
    * 管理员为 `crm` 应用新增权限点 `user:edit`。
    * 系统自动分配一个未使用的 **位索引 (Bit Index)**，例如 `Index: 130`。
    * 系统计算该权限的桶位置：`Bucket: 2`, `Offset: 2`。
    * **约束**：无数量限制。

#### F5. 角色管理与掩码预计算
* **逻辑**：
    * 创建角色“CRM管理员”。
    * 勾选权限 `user:view (Index 0)`, `user:edit (Index 130)`。
    * **后端实时计算**：
        * Bucket 0: `1<<0` = `1`
        * Bucket 2: `1<<2` = `4`
    * 将计算结果（Bucket Index + Mask）存入 `sys_role_permission_masks` 表。**这是高性能的关键，查询时无需再次聚合。**
* **数据权限 (Data Scope)**：
    * 支持配置角色的数据范围：`SELF` (仅本人), `DEPT` (本部门), `ALL` (全部), `CUSTOM` (自定义)。
    * **自定义配置 (Custom Config)**：当 Scope Type 为 `CUSTOM` 时，支持存储 JSON 格式的配置（如部门 ID 列表）。

#### F6. 用户授权
* **逻辑**：将用户与角色关联。
* **最终权限计算**：用户在某 App 下的最终权限 = `用户关联的所有Role的Mask` 进行 **按位或 (OR)** 运算（按桶合并）。

### 3.3 模块三：管理后台 (Admin Portal)

UniAuth 自身作为一个特殊的 App (`uniauth-admin`) 存在，拥有自己的权限字典和角色。

#### F9. 管理后台权限控制 (RBAC for Admin)
* **自我管理**：UniAuth 系统本身也是一个 App，Code 为 `uniauth-admin`。
* **超级管理员**：拥有 `uniauth-admin` 下的所有权限。
* **普通管理员**：可能只拥有 `user:view` 或 `app:view` 权限。
* **权限点示例**：
    * `app:create` (创建新应用)
    * `app:edit` (修改应用信息)
    * `perm:manage` (管理权限字典)
    * `role:manage` (管理角色)
    * `user:manage` (管理用户)
    * `user:assign-role` (给用户分配角色)

#### F10. 可视化管理界面
* **应用列表页**：展示所有接入的 App，支持新增/编辑。
* **权限字典页**：选择 App 后，展示该 App 下的所有权限点及其 BitIndex，支持新增权限（自动分配 Index）。
* **角色管理页**：
    * 选择 App。
    * 展示角色列表。
    * **角色编辑**：提供 Checkbox 列表展示该 App 的所有权限，勾选后自动计算 Mask 并保存。
    * **数据范围配置**：支持选择数据范围类型，若为 Custom 类型，提供文本域输入自定义配置 (JSON)。
* **用户管理页**：
    * 用户列表（分页、搜索）。
    * **授权弹窗**：选择 App -> 选择角色 -> 赋予用户。

### 3.4 模块四：业务系统中间件 (Client SDK / Middleware)

此部分逻辑运行在业务系统（如 CRM）的 Go 后端中。

#### F7. 权限字典同步
* **时机**：业务系统启动时 / 定时任务 / 接收到变更通知时。
* **动作**：调用鉴权中心 API `/api/meta/permissions?app_id=crm`。
* **缓存**：在本地内存构建 Map：`"user:edit" -> big.Int(Index)`。

#### F8. 请求鉴权拦截 (Middleware)
* **步骤**：
    1. 解析请求 Cookie 或 Header (`Authorization: Bearer ...`) 中的 JWT，提取 UserID。
    2. **黑名单校验**：检查 Token 是否在黑名单中。
    3. 查询该用户的 Mask（优先查本地 Redis 缓存，无缓存查鉴权中心 `/api/user/mask`）。
    4. 确定当前 API 需要的权限（如 `user:edit`，Index=130）。
    5. **位运算判定**：
    ```go
    // Go 伪代码
    bucketIdx := 130 / 64
    bitOffset := 130 % 64
    // 从 UserMask 中提取对应 Bucket 的值
    userBucketMask := GetBucket(UserMask, bucketIdx)
    requiredBit := 1 << bitOffset
    
    if (userBucketMask & requiredBit) != 0 {
        Next() // 放行
    } else {
        Abort(403) // 拒绝
    }
    ```

---

## 4. 数据架构设计 (Supabase Schema)

基于 Supabase (PostgreSQL) 的表结构设计。

### 4.1 实体关系图 (ER Diagram)

### 4.2 表结构定义

#### 1. `sys_apps` (应用表)
| 字段名 | 类型 | 约束 | 说明 |
| --- | --- | --- | --- |
| id | bigint | PK |  |
| code | varchar(50) | Unique | 应用标识 (crm, erp, uniauth-admin) |
| name | varchar(100) |  | 应用名称 |
| secret_key | varchar(64) |  | 用于后端服务间通讯签名 |

#### 2. `sys_permissions` (权限字典表)
*定义每一位代表的含义。*
| 字段名 | 类型 | 约束 | 说明 |
| --- | --- | --- | --- |
| id | bigint | PK |  |
| app_id | bigint | FK | 归属应用 |
| permission_code | varchar(100) |  | 权限标识 (user:add) |
| bit_index | int2 | **无限制** | **核心字段：位索引** |
| description | text |  | 描述 |
| **Unique Index** | (app_id, bit_index) |  | 确保同一应用下位索引不冲突 |

#### 3. `sys_roles` (角色表)
| 字段名 | 类型 | 约束 | 说明 |
| --- | --- | --- | --- |
| id | bigint | PK |  |
| app_id | bigint | FK | 归属应用 |
| name | varchar(50) |  | 角色名 |

#### 4. `sys_role_permission_masks` (角色权限位分段表)
*核心表：存储每个角色的权限位分段（桶）。*
| 字段名 | 类型 | 约束 | 说明 |
| --- | --- | --- | --- |
| role_id | bigint | PK, FK | 关联角色 |
| bucket_index | smallint | PK | 第几个“桶”，0 代表 0-63位，1 代表 64-127位... |
| mask | bigint | NotNull | **核心字段：64位掩码** |

#### 5. `sys_role_data_scopes` (角色数据范围表)
| 字段名 | 类型 | 约束 | 说明 |
| --- | --- | --- | --- |
| id | bigint | PK |  |
| role_id | bigint | FK | 关联角色 |
| scope_type | smallint | Default 1 | 1:Self, 2:Dept, 3:All, 4:Custom |
| custom_config | text | Nullable | 自定义配置 (JSON) |

#### 6. `sys_users` (用户表)
| 字段名 | 类型 | 约束 | 说明 |
| --- | --- | --- | --- |
| id | uuid | PK | Supabase Auth UUID 或 自建 |
| username | varchar(50) | Unique |  |
| email | varchar(100) | Unique |  |
| password | varchar(255) | | Hash后的密码 |
| status | int2 |  | 1:正常 0:禁用 |

#### 7. `sys_user_roles` (用户-角色关联)
| 字段名 | 类型 | 约束 | 说明 |
| --- | --- | --- | --- |
| id | bigint | PK |  |
| user_id | uuid | FK |  |
| role_id | bigint | FK |  |
| app_id | bigint | FK | **冗余字段**，用于快速过滤应用维度的角色 |

#### 8. `sys_token_blacklist` (Token 黑名单表)
| 字段名 | 类型 | 约束 | 说明 |
| --- | --- | --- | --- |
| id | bigint | PK |  |
| token | varchar(512) | Unique | JWT Token 字符串 |
| expires_at | timestamp | Index | Token 原定过期时间 |
| created_at | timestamp |  | 加入黑名单时间 |

---

## 5. 接口协议设计

所有接口采用 RESTful JSON 格式。

### 5.1 获取权限元数据 (Meta API)
*用于业务系统同步字典。*
* **GET** `/api/v1/meta/permissions`
* **Query**: `app_code=crm`
* **Response**:
```json
{
    "code": 200,
    "data": [
        { "key": "user:view", "idx": 0 },
        { "key": "user:edit", "idx": 1 },
        { "key": "admin:super", "idx": 1000 }
    ]
}
```

### 5.2 获取用户权限掩码 (Runtime API)
*用于业务系统查询当前登录用户的总权限。*
* **GET** `/api/v1/auth/my-mask`
* **Query**: `app_code=crm`
* **Header**: `Authorization: Bearer <token>` (可选，优先 Cookie)
* **Response**:
```json
{
    "code": 200,
    "data": {
        "uid": "uuid...",
        // 计算后的最终掩码 (Hex String)，长度不定
        // 业务系统收到后需 parse 为 BigInt
        "mask": "0000...0003", 
        "data_scopes": [
            {
                "scope_type": 4,
                "custom_config": "{\"dept_ids\": [1, 2]}"
            }
        ],
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", // 返回当前有效 Token
        "redirect_url": "http://crm.company.com/callback"
    }
}
```

### 5.3 管理后台 API (Admin API)
*需要 `uniauth-admin` 应用下的相应权限。*

* **App Management**:
    * `GET /api/v1/admin/apps` (List Apps)
    * `POST /api/v1/admin/apps` (Create App)
    * `PUT /api/v1/admin/apps/:id` (Update App)

* **Permission Management**:
    * `GET /api/v1/admin/apps/:app_id/permissions` (List Permissions)
    * `POST /api/v1/admin/apps/:app_id/permissions` (Add Permission - Auto assign index)

* **Role Management**:
    * `GET /api/v1/admin/apps/:app_id/roles` (List Roles)
    * `POST /api/v1/admin/apps/:app_id/roles` (Create Role with Mask)
    * `PUT /api/v1/admin/roles/:role_id` (Update Role Mask & Data Scope)

* **User Management**:
    * `GET /api/v1/admin/users` (List Users)
    * `POST /api/v1/admin/users/:user_id/roles` (Assign Role)

---

## 6. 技术实现规范 (Go)

### 6.1 位运算处理 (big.Int)
由于 Go 语言原生 `uint64` 只有 64 位，不足以支撑无限位权限，**必须**使用标准库 `math/big`。

**Go 代码规范示例：**
```go
import (
    "math/big"
)

// 1. 将数据库中的 Hex String 转为 BigInt
func ParseMask(hexStr string) *big.Int {
    i := new(big.Int)
    i.SetString(hexStr, 16) // 16进制解析
    return i
}

// 2. 鉴权判定
// userMask: 用户拥有的掩码
// requiredIndex: 接口需要的权限位索引 (如 130)
func HasPermission(userMask *big.Int, requiredIndex int) bool {
    // 构造所需的原子掩码 (1 << index)
    requiredBit := new(big.Int).Lsh(big.NewInt(1), uint(requiredIndex))
    
    // 逻辑： (User & Required) == Required
    result := new(big.Int).And(userMask, requiredBit)
    return result.Cmp(requiredBit) == 0
}
```

### 6.2 异常处理
* **掩码合并**：当用户拥有多个角色时，Go 后端必须遍历所有角色，使用 `new(big.Int).Or(mask1, mask2)` 进行合并计算。

---

## 7. 安全与运维要求

1. **数据库安全**：Supabase 开启 Row Level Security (RLS)，虽然主要逻辑在 Go 后端，但 RLS 作为兜底防止数据裸奔。
2. **通讯安全**：鉴权中心与业务系统之间的通讯（如获取 Mask），必须走内网或使用 `API Secret` 签名验证，防止伪造请求。
3. **缓存策略**：
    * 业务系统应在本地 (Memory/Redis) 缓存 `Permission Dictionary` (TTL: 1小时)。
    * 用户 Mask 建议缓存 TTL 设置为 5-10 分钟，以平衡权限变更的实时性与性能。
