# AI 辅助权限生成指南

本指南旨在帮助开发者利用 AI 工具（如 ChatGPT, Claude, DeepSeek 等）快速扫描现有子系统代码，并生成可直接导入 UniAuth Admin 的权限 JSON 文件。

## 1. 目标

将分散在代码（后端路由、前端按钮）中的权限点提取出来，整理成 UniAuth 支持的批量导入格式。

## 2. JSON 格式规范

UniAuth 批量导入接口接受一个 JSON 数组，每个对象包含以下字段：

```json
[
  {
    "permission_code": "resource:action",
    // 必填，权限唯一标识符，建议使用冒号分隔层级
    "description": "描述信息",
    // 选填，用于在界面上显示
    "usage": "使用说明",
    // 选填，用来解释权限对应的功能
    "bit_index": 10
    // 选填，指定位索引。如果不填，系统将自动分配。
  }
]
```

> **注意**: `bit_index` 只有在你需要强制指定某个权限对应特定位时才填写（例如为了兼容旧系统）。通常情况下，建议让 UniAuth 自动分配。

## 3. AI Prompt 模板

你可以复制以下 Prompt 发送给 AI，并附上你的代码片段（后端路由文件或前端页面文件）。

### 场景 A: 扫描后端路由 (Go/Gin 示例)

**Prompt:**

> 我正在使用一个权限管理系统。请分析我提供的后端代码，提取所有受权限控制的 API 路由，并生成一个 JSON 数组。
>
> **要求：**
> 1. 识别代码中类似 `RequirePermission("user:edit")` 或注释中的权限标记。
> 2. 生成的 JSON 格式如下：`[{"permission_code": "code", "description": "根据路由或函数名推测的中文描述"}]`。
> 3. `permission_code` 应该是代码中实际使用的字符串。
> 4. `description` 请用简洁的中文描述该权限的作用。
>
> **代码内容：**
> (在此处粘贴你的后端路由代码)

### 场景 B: 扫描前端页面 (HTML/JS 示例)

**Prompt:**

> 请分析我提供的前端代码，提取所有带有权限控制标记的元素，并生成权限列表 JSON。
>
> **要求：**
> 1. 查找所有包含 `data-permission="..."` 属性的 HTML 元素。
> 2. 提取属性值作为 `permission_code`。
> 3. 根据按钮文字或上下文推测 `description`。
> 4. 输出格式：`[{"permission_code": "code", "description": "描述"}]`。
> 5. 去除重复项。
>
> **代码内容：**
> (在此处粘贴你的前端 HTML/JS 代码)

## 4. 示例

### 输入 (前端代码片段)

```html
<button data-permission="products:create">新建商品</button>
<a href="#" data-permission="products:view">查看列表</a>
<button onclick="deleteItem()" data-permission="products:delete">删除</button>
```

### AI 输出 (JSON)

```json
[
  {
    "permission_code": "products:create",
    "description": "新建商品"
  },
  {
    "permission_code": "products:view",
    "description": "查看商品列表"
  },
  {
    "permission_code": "products:delete",
    "description": "删除商品"
  }
]
```

## 5. 如何使用

1. 使用上述 Prompt 和你的代码生成 JSON。
2. 登录 UniAuth Admin Portal。
3. 进入 **Applications** -> 选择应用 -> **Permissions** Tab。
4. 点击 **Import JSON** 按钮。
5. 粘贴 JSON 并点击 Import。
