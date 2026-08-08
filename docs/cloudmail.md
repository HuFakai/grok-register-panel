# CloudMail 临时邮箱模块说明

本文档整理项目中 CloudMail（[maillab/cloud-mail](https://github.com/maillab/cloud-mail) 开源自部署临时邮箱系统）的接入接口、功能逻辑与调用链，涵盖**创建账号、获取验证码、删除账号**等完整流程。

## 一、概述

CloudMail 是一个自部署的临时邮箱服务，本项目通过其 HTTP API 实现：

- **创建临时邮箱**：用管理员账号登录后调用 `/api/account/add` 添加邮箱账号
- **获取验证码**：用公开只读 token 轮询 `/api/public/emailList` 查询邮件，从中提取 xAI 注册验证码（`XXX-YYY` 格式）
- **删除账号**：注册流程结束（成功或失败）后调用 `/api/account/delete` 清理邮箱，避免邮箱被占用

核心实现位于 `email_providers/cloudmail.py`，通过 `grok_register_ttk.py` 的 `get_email_and_token()` / `get_oai_code()` 分发逻辑接入注册主流程。

## 二、涉及文件

| 文件 | 作用 |
| --- | --- |
| `email_providers/cloudmail.py` | CloudMail 提供商核心实现（所有 API 调用） |
| `email_providers/common.py` | 公共工具：验证码提取 `extract_verification_code`、用户名生成 `generate_username` |
| `grok_register_ttk.py` | 注册面板主程序：cloudmail 的配置读取、入口封装与分发 |
| `connectivity.py` | 连通性检查：CloudMail 站点可达性检测 |
| `webui/email_domain_store.py` | 邮箱域名池：cloudmail 是受支持的服务商之一 |
| `webui/monitor.py` | Web 面板：CloudMail 域名池 UI 入口 |
| `config.example.json` | 配置示例（`cloudmail_*` 相关配置项） |
| `tests/test_cloudmail.py` | 单元测试：管理员鉴权过期重试逻辑 |

## 三、HTTP 接口一览

CloudMail 共使用 **5 个 HTTP 接口**，其中 2 个管理接口（需管理员 JWT）、2 个公开接口（需公开 token）、1 个登录接口：

| 接口 | 方法 | 路径 | 鉴权 | 用途 |
| --- | --- | --- | --- | --- |
| 管理员登录 | `POST` | `/api/login` | 无 | 管理员邮箱+密码换取管理 JWT |
| 创建邮箱账号 | `POST` | `/api/account/add` | 管理 JWT | **创建账号** |
| 删除邮箱账号 | `DELETE` | `/api/account/delete` | 管理 JWT | **删除账号** |
| 生成公开 token | `POST` | `/api/public/genToken` | 无 | 管理员换取只读公开 token |
| 查询邮件列表 | `POST` | `/api/public/emailList` | 公开 token | **获取验证码** |

> 所有接口响应统一格式为 `{"code": 200, "data": ..., "message": ...}`，`code != 200` 时视为失败（见 `_response_data`）。

## 四、接口详细说明

### 1. 管理员登录 `/api/login`

用于管理操作前的登录鉴权，返回 JWT token。

```python
resp = http_post(
    f"{url}/api/login",
    json={"email": email, "password": password},
    headers={"Content-Type": "application/json"},
)
# 响应: {"code": 200, "data": {"token": "<JWT>"}}
```

### 2. 创建邮箱账号 `/api/account/add`

管理员登录后添加一个临时邮箱地址。

```python
resp = http_post(
    f"{url}/api/account/add",
    json={"email": address, "token": ""},   # token 字段固定传空串
    headers={"Content-Type": "application/json", "Authorization": jwt},
)
# 响应: {"code": 200, "data": {"accountId": 42}}
# 返回的 accountId（或 id）会被缓存，供后续删除使用
```

### 3. 删除邮箱账号 `/api/account/delete`

管理员登录后按 `accountId` 删除邮箱（注册流程结束后清理）。

```python
resp = http_delete(
    f"{url}/api/account/delete",
    params={"accountId": account_id},
    headers={"Content-Type": "application/json", "Authorization": jwt},
)
```

### 4. 生成公开 token `/api/public/genToken`

用管理员邮箱+密码换取**只读公开 token**，用于查询邮件。这样邮件轮询不需要携带管理 JWT，降低管理权限泄露风险。

```python
resp = http_post(
    f"{url}/api/public/genToken",
    json={"email": admin_email, "password": admin_password},
    headers={"Content-Type": "application/json"},
)
# 响应: {"code": 200, "data": {"token": "<public token>"}}
```

公开 token 有全局缓存（见下文「功能逻辑 · 4」），失效时自动强制刷新。

### 5. 查询邮件列表 `/api/public/emailList`

携带公开 token 查询收件箱邮件，可指定收件人地址精确过滤。

```python
payload = {"size": 20}
if to_email:
    payload["toEmail"] = to_email
resp = http_post(
    f"{url}/api/public/emailList",
    json=payload,
    headers={"Content-Type": "application/json", "Authorization": public_token},
)
# 响应 data 兼容 list / rows / emails / records 多种字段结构
```

## 五、核心功能逻辑

### 1. 创建邮箱（`create_mailbox`）

`grok_register_ttk.py::cloudmail_get_email_and_token()` → `create_mailbox()`，流程如下：

1. **配置校验**：`url` / `admin_email` / `admin_password` / `domains` 任一为空即抛异常
2. **域名轮询**：按 `_domain_index % len(domains)` 在域名列表中轮询（round-robin），`_domain_index` 每次自增
3. **生成用户名**：优先使用传入的 `username`，否则用 `common.generate_username(10)` 生成真人风格随机名（如 `james.smith42`，无 `tmp` 前缀）
4. **拼接地址**：`address = 本地部分@域名`
5. **调用 `add_address`** 创建邮箱账号
6. **缓存 accountId**：将 `address -> accountId` 存入全局 `_account_ids` 字典（供流程结束清理）
7. **返回** `(address, "cloudmail_catch_all")`——第二项是占位 token，CloudMail 采用 catch-all 收信，不依赖 token

### 2. 添加/删除账号的重试机制（`add_address` / `delete_address`）

CloudMail 的部署会存在「并发登录使上一个管理 JWT 失效」的问题，因此这两个管理操作：

- 使用全局 `_admin_operation_lock` 互斥锁，保证**登录 + 变更操作原子执行**，避免并发登录互相顶掉 JWT
- 最多重试 **2 次**：首次若因鉴权失败（错误信息含 `身份认证` / `重新登录` / `unauthorized` / `401` / `token`）则重新登录重试一次，其余错误直接抛出

### 3. 获取公开 token（`gen_public_token` / `get_shared_token`）

- `gen_public_token`：直接调用 `/api/public/genToken`
- `get_shared_token`：带缓存的封装，按 `(url, admin_email, admin_password)` 作为缓存 key，全局单例缓存 `_public_token`；`force_refresh=True` 时强制重新生成
- 邮件轮询期间若发现 token 失效（错误含 `token` / `401` / `unauthorized` / `鉴权`），自动 `force_refresh=True` 刷新后续轮

### 4. 等待验证码（`wait_for_code`）

`grok_register_ttk.py::cloudmail_get_oai_code()` → `wait_for_code()`，这是获取验证码的核心轮询逻辑：

- **默认参数**：`timeout=180` 秒，`poll_interval=3` 秒
- **流程**：
  1. 先获取公开 token（失败则记录日志继续）
  2. 循环直到超时：
     - 检查取消状态（`raise_if_cancelled`，用户点停止时抛 `RegistrationCancelled`）
     - **每 35 秒触发一次 `resend_callback`** 重新发送验证码（若提供了），模拟手动点「重发」
     - 调用 `public_email_list` 查询邮件（`size=20`，按 `toEmail` 精确匹配当前邮箱）
     - 邮件按 `emailId` / `id` / `messageId` 去重，**同一封邮件最多解析 5 次**（防止重复处理同一封）
     - 解析正文：从 `content` / `text` / `textContent` / `text_content` / `body` / `snippet` / `intro` 字段收集文本，HTML 字段（`html` / `htmlContent` / `html_content`）先剥掉标签再拼接
     - 用 `extract_verification_code` 提取验证码，**命中立即返回**
     - 每轮结束 `sleep_with_cancel(poll_interval)` 再查下一轮
  3. **超时抛异常**：`CloudMail 在 180s 内未收到验证码邮件`
  4. **`finally` 中调用 `cleanup_address` 删除临时邮箱**（无论成功/失败/取消都会清理）

### 5. 清理邮箱（`cleanup_address`）

- 从 `_account_ids` 中按邮箱地址弹出已缓存的 `accountId`
- 调用 `delete_address` 删除，成功打印 `[CloudMail] 已删除临时邮箱: xxx (accountId=yyy)`
- 删除失败只打印错误日志、**不抛出**，避免影响注册主流程

### 6. 验证码提取（`extract_verification_code`，位于 `common.py`）

- 主正则：`\b([A-Za-z0-9]{3}-[A-Za-z0-9]{3})\b`，匹配 xAI 验证码格式（如 `QO7-TUD` / `CXX-PC2` / `XSB-802`）
- **伪码过滤**：CloudMail 会把管理后台 HTML（含 `per-100`、`max-100` 等 CSS class）拼进邮件正文，旧逻辑会误把 `per-100` 当验证码。现逻辑：
  - 黑名单 token 直接排除（`per-100`、`max-100` 等）
  - 左右都是纯数字的排除，左侧是 `per/max/top/all/col/row/box/pad/gap` 等模板词且右侧纯数字的排除
- **上下文打分**：靠近 `xAI`(+8)、`verification`(+6)、`security code`(+6)、`验证码`(+6) 等关键词优先；含 `class=`、`stylesheet`、`width:` 等 HTML 特征的减分
- **匹配优先级**：主题行 `XXX-YYY xAI` → 正文中邻近 `xAI` 的模式 → 关键词模式 → 全文打分选最高 → 兜底纯数字 4-8 位验证码（`verification code: xxx` / `验证码：xxx`）

### 7. 运行时状态与重置（`reset_runtime_state`）

清理全局状态：域名轮询游标 `_domain_index`、公开 token 缓存 `_public_token`、账号 id 缓存 `_account_ids`，用于程序重启/重置时避免脏状态。

## 六、与注册主流程的集成

`grok_register_ttk.py` 中 `get_email_and_token()` / `get_oai_code()` 按 `email_provider` 配置分发，`cloudmail` 分支如下：

```python
# 创建邮箱阶段
if provider == "cloudmail":
    return cloudmail_get_email_and_token(domain=managed_domain)

# 等待验证码阶段
if provider == "cloudmail":
    return cloudmail_get_oai_code(
        dev_token, email,
        timeout=timeout, poll_interval=poll_interval,
        log_callback=log_callback, cancel_callback=cancel_callback,
        resend_callback=resend_callback,
    )
```

调用链：

```
注册主流程 get_email_and_token()
  └─ cloudmail_get_email_and_token(domain)
       ├─ get_cloudmail_url() / get_cloudmail_admin_email() / get_cloudmail_password()  # 读取配置
       └─ cloudmail_provider.create_mailbox(http_post, url, admin, pwd, domains, username)
            ├─ 域名轮询 + 生成地址
            ├─ add_address() → POST /api/login + POST /api/account/add
            └─ 返回 (email, "cloudmail_catch_all")

注册主流程 get_oai_code()
  └─ cloudmail_get_oai_code(dev_token, email, ...)
       └─ cloudmail_provider.wait_for_code(http_post, http_delete, url, admin, pwd, email, ...)
            ├─ get_shared_token() → POST /api/public/genToken
            ├─ 循环轮询 public_email_list() → POST /api/public/emailList
            ├─ extract_verification_code() 提取验证码
            └─ finally: cleanup_address() → DELETE /api/account/delete
```

## 七、域名池集成（`webui/email_domain_store.py`）

CloudMail 是域名池支持的 4 个服务商之一（`cloudflare` / `cloudmail` / `moemail` / `yyds`）：

- **域名选择**：`select_domain("cloudmail")` 从面板池选一个「健康 + 启用 + 未达拒绝阈值」的域名（优先 `use_count` 最少的），返回给 `create_mailbox` 作为 `domains`；面板池未配置时返回 `configured=False`，回退到 `config.json` 的 `defaultDomains`
- **结果记录**：注册成功提交邮箱后 `record_domain_result(provider, email, "accepted")` 清零连续失败；xAI 明确拒绝域名时累计 `rejected`，达到阈值（默认 3 次）自动拉黑该域名
- **容错**：邮箱 API 错误、验证码超时、普通网络异常**不会**处罚域名，避免基础设施故障误判为域名质量问题

## 八、配置项

配置来源优先级：**环境变量 > `config.json`**。

| 配置项 | 环境变量 | 说明 |
| --- | --- | --- |
| `cloudmail_url` | `CLOUDMAIL_URL` | CloudMail 站点地址（如 `https://mail.example.com`） |
| `cloudmail_admin_email` | `CLOUDMAIL_ADMIN_EMAIL` | 管理员邮箱 |
| `cloudmail_password` | `CLOUDMAIL_PASSWORD` | 管理员密码 |
| `defaultDomains` | — | 旧逻辑域名列表（逗号/空白分隔，如 `mail-a.example.com,mail-b.example.com`）；面板域名池配置后优先使用面板池 |

> `get_cloudmail_url()` 会做 `rstrip("/")` 规范化，避免拼接 API 路径时出现双斜杠。

## 九、连通性检查（`connectivity.py`）

`email_provider == "cloudmail"` 时，连通性检测逻辑：

```python
if provider == "cloudmail":
    url = str(config.get("cloudmail_url", "") or "").rstrip("/")
    if not url:
        return "邮箱API", False, "未配置 cloudmail_url"
    resp = http_get(url, timeout=10)
    return "邮箱API", resp.status_code < 400, f"CloudMail HTTP {resp.status_code}"
```

即对站点根路径发一次 `GET` 请求，状态码 < 400 视为连通。

## 十、测试覆盖

| 测试文件 | 覆盖内容 |
| --- | --- |
| `tests/test_cloudmail.py` | `add_address` 鉴权过期自动重试逻辑（模拟第一次登录返回 401 后重试成功） |
| `tests/test_email_domain_worker_integration.py` | 集成测试中 mock `cloudmail_provider.create_mailbox`，验证域名池与注册 worker 的联动 |
| `tests/test_email_domain_store.py` | 域名池对 cloudmail 服务的配置/选择/拉黑逻辑 |
| `tests/test_extract_code.py` | 验证码提取（含 CloudMail 拼接 HTML 导致伪码的过滤场景） |

运行入口：`scripts/run_tests.sh` 包含 `tests/test_cloudmail.py`。

## 十一、关键容错与设计要点

1. **管理 JWT 互斥**：`_admin_operation_lock` 保证登录+变更原子，规避并发登录互相顶掉 JWT 的已知问题
2. **公开 token 分离**：邮件查询用只读公开 token，避免管理 JWT 高频暴露；token 失效自动刷新
3. **自动重发验证码**：轮询中每 35 秒主动触发一次「重新发送」回调，提高验证码邮件到达率
4. **流程结束必清理**：`wait_for_code` 的 `finally` 保证邮箱账号在成功、失败、取消三种情况下都被删除
5. **验证码防误判**：针对 CloudMail 拼接管理后台 HTML 的特点做了伪码过滤与上下文打分
6. **删除失败不阻断**：清理失败仅记录日志，不影响注册结果落盘
