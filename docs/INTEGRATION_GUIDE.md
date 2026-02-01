# UniAuth 统一权限系统接入指南

本文档旨在指导子系统如何接入 UniAuth 统一权限系统，包括前端认证流程、UI 交互规范、后端权限校验及数据范围（Data Scope）的实现方案。

## 1. 接入前准备

所有接入 UniAuth 的子系统，必须在环境变量或配置文件中配置以下参数，以便在环境切换时（开发/测试/生产）能够灵活调整：

```bash
# 统一认证中心的基础 URL
AUTH_BASE_URL=http://auth.jyccloud.cn

# 当前子系统的唯一标识码 (需在 UniAuth 管理后台注册)
APP_CODE=your-subsystem-code
```

---

## 2. 前端集成指南

### 2.1 认证与授权流程

前端页面加载时，应遵循以下标准流程：

1.  **请求权限掩码**：调用 UniAuth 接口获取当前用户的权限状态。
2.  **处理未登录 (401)**：如果接口返回 401，说明用户未登录或 Token 过期，需跳转至统一登录页。
3.  **获取权限与数据范围**：登录成功后，解析返回的权限掩码（Mask）和数据范围配置。

**代码逻辑示例 (伪代码):**

```javascript
// 这里最好的动态加载的
const AUTH_BASE_URL = xxx; // e.g., http://auth.jyccloud.cn
const APP_CODE = xxx;           // e.g., crm-system

async function initAuth() {
    try {
        // 1. 请求当前用户在当前 App 下的权限掩码
        const response = await fetch(`${AUTH_BASE_URL}/api/v1/auth/my-mask?app_code=${APP_CODE}`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}` // 假设 Token 存储在本地
            }
        });

        // 2. 处理未登录情况
        if (response.status === 401) {
            // 构造回调地址，登录成功后跳回当前页面
            const redirectUrl = encodeURIComponent(window.location.href);
            window.location.href = `${AUTH_BASE_URL}/?redirect=${redirectUrl}`;
            return;
        }

        const data = await response.json();
        
        // 3. 保存权限掩码和用户信息
        // mask: BigInt 格式的权限位掩码
        // user: 包含 id, username 等
        store.commit('SET_USER_MASK', BigInt('0x' + data.mask)); 
        store.commit('SET_USER_INFO', data.user);

    } catch (error) {
        console.error("Auth initialization failed", error);
    }
}
```

### 2.2 UI 交互规范：置灰而非隐藏

为了提升用户体验和功能的可见性，UniAuth 遵循以下 UI 规范：

*   **原则**：除非有特殊安全要求，**没有权限的按钮/菜单应当“置灰（Disabled）”而不是“隐藏（Hidden）”**。
*   **目的**：
    *   让用户知道系统具备该功能。
    *   让用户知道自己缺乏该权限，方便向管理员申请。

**实现示例 (Vue):**

```html
<!-- ❌ 不推荐：直接隐藏 -->
<button v-if="hasPermission('product:delete')">删除商品</button>

<!-- ✅ 推荐：置灰并提示 -->
<button :disabled="!hasPermission('product:delete')" title="您没有删除商品的权限">
  删除商品
</button>
```

**权限判断辅助函数:**

```javascript
// 需预先加载权限字典 (Permission Code -> Bit Index)
// 项目里应该有permissions.json，通过后端请求这个权限字典而不是配置在每个前端页面，或者通过web server动态加载是更优解
const permissionDict = {
    'product:view': 1,
    'product:edit': 2,
    'product:delete': 3
    // ...
};

function hasPermission(permCode) {
    const userMask = store.state.userMask; // 当前用户的 BigInt 掩码
    const bitIndex = permissionDict[permCode];
    
    if (bitIndex === undefined) return false; // 未知权限，默认拒绝
    
    const requiredBit = 1n << BigInt(bitIndex);
    return (userMask & requiredBit) === requiredBit;
}
```

---

## 3. 后端集成指南

后端服务在接收请求时，必须进行两层校验：**功能权限校验** 和 **数据范围校验**。

### 3.1 功能权限校验 (Middleware)

在执行任何 Controller 逻辑前，中间件应拦截请求并校验 Token 和权限掩码。

```go
func CheckPermission(permCode string) gin.HandlerFunc {
    return func(c *gin.Context) {
        // 1. 验证 Token (JWT)
        // 2. 获取当前用户对当前 App 的 Permission Mask (可缓存)
        userMask := GetUserMask(userID, appCode)
        
        // 3. 计算所需权限位
        requiredBit := GetBitIndex(permCode)
        
        // 4. 位运算校验
        if !userMask.HasBit(requiredBit) {
            c.AbortWithStatusJSON(403, gin.H{"error": "Access Denied"})
            return
        }
        c.Next()
    }
}
```

### 3.2 数据操作校验

在进行增删改（CUD）操作时，**不能仅依赖前端传来的 ID**，必须校验该数据是否属于当前用户可操作的范围。

*   **修改/删除**：查询数据时，必须带上数据范围过滤条件。如果查询不到数据，说明无权操作或数据不存在。

---

## 4. 数据范围 (Data Scope) 实现指南

UniAuth 定义了策略（Scope Type），子系统负责实现数据的归属结构。

### 4.1 数据库设计要求

为了支持数据范围控制，子系统的业务表（如订单、商品、客户）**必须**包含数据归属字段。

**推荐表结构设计：**

```sql
CREATE TABLE sub_products (
    id BIGINT PRIMARY KEY,
    name VARCHAR(100),
    -- 核心：记录数据归属人
    owner_id UUID NOT NULL, 
    -- 可选：记录归属部门（如果业务强依赖部门查询）
    dept_id BIGINT, 
    created_at TIMESTAMP
);

CREATE INDEX idx_product_owner ON sub_products(owner_id);
```

### 4.2 数据范围过滤逻辑

UniAuth 提供 4 种标准数据范围，子系统需在查询 SQL 中动态拼接 `WHERE` 条件：

| Scope Type | 含义 | SQL 过滤逻辑示例 |
| :--- | :--- | :--- |
| **1: Self** | 仅本人数据 | `WHERE owner_id = :current_user_id` |
| **2: Team** | 本人及下属 | `WHERE owner_id IN (:current_user_id, :subordinate_ids...)` |
| **3: All** | 全部数据 | 无需过滤条件 (或 `WHERE 1=1`) |
| **4: Custom**| 自定义部门/人 | `WHERE owner_id IN (:custom_config_ids...)` |

### 4.3 获取下属关系 (Team Scope)

当 Scope 为 **Team (2)** 时，子系统需要知道“谁是当前用户的下属”。

*   **方案 A (推荐)**：子系统自行维护一份 `sys_user_relations` 副本或类似的层级表，保持业务独立性。
*   **方案 B**：实时调用 UniAuth 的 API 获取下属 ID 列表（注意缓存，避免性能瓶颈）。
*   **方案 C**：直接连接 UniAuth 数据库的 `public.sys_user_relations` 表（仅限同一内网/数据库实例）。

**Go 代码逻辑示例 (List 接口):**

```go
func ListProducts(c *gin.Context) {
    userID := c.Get("userID")
    // 1. 获取用户在当前 App 的角色及对应的数据范围 (DataScope)
    scopeType := GetUserDataScope(userID, appCode)
    
    query := db.Model(&Product{})
    
    switch scopeType {
    case 1: // Self
        query = query.Where("owner_id = ?", userID)
    case 2: // Team
        subIDs := GetSubordinateIDs(userID) // 获取下属 ID 列表
        allIDs := append(subIDs, userID)
        query = query.Where("owner_id IN ?", allIDs)
    case 3: // All
        // 不加限制
    }
    
    var products []Product
    query.Find(&products)
    c.JSON(200, products)
}
```
