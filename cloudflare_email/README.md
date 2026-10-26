# Cloudflare 邮箱核心（精简版）

主项目 [grok-register-panel](../README.md) 的 **Cloudflare Worker 临时邮箱**（[cloudflare_temp_email](https://github.com/dreamhunter2333/cloudflare_temp_email) 兼容）核心功能提取，一条完整链路：

**建号（catch-all 免建号 / admin 建号）→ 轮询收信 → 提取 xAI 验证码 → 删信**

> 本目录是主工程代码的**精简重写**（快照式复制，主工程不受影响）。相比完整版裁掉了：旧版 address/password 建号 fallback、配置胶水函数、以及 `integration/` 摘录与 `legacy/` 死代码存档；验证码提取与用户名生成做了等价压缩。完整行为以主工程 `email_providers/cloudflare.py` + `email_providers/common.py` + `grok_register_ttk.py` 为准。

## 文件与来源

| 文件 | 说明 | 来源 |
|---|---|---|
| `cloudflare_email.py` | 核心单文件模块（仅标准库，HTTP 回调注入） | `email_providers/cloudflare.py`（建号/收信/删信）、`email_providers/common.py`（验证码提取/用户名/随机子域）、`grok_register_ttk.py` L1361-1399（catch-all 自签 JWT） |
| `test_cloudflare_email.py` | 5 个核心用例 | `tests/test_cloudflare_provider.py`、`tests/test_cloudflare_catchall.py` |

```bash
python3 test_cloudflare_email.py   # OK cloudflare_email
```

## 快速用法

```python
import requests, time
import cloudflare_email as cf

base = "https://temp-mail.example.com"

# 建号方式一：catch-all 免建号（需服务端 JWT_SECRET + *.根域泛域收信，零 API 调用）
address, jwt = cf.cloudflare_catchall_email_and_token("your-jwt-secret", domain="example.com")

# 建号方式二：admin 建号（撞名自动重试）
address, jwt = cf.create_temp_address(
    requests.post, base,
    accounts_path="/admin/new_address", domain="example.com",
    api_key="your-admin-password", auth_mode="x-admin-auth",
    randomize_subdomain=False,
)

# 轮询收信，提取 xAI 验证码（XXX-YYY）；拿到后自动删信
code = cf.wait_for_code(
    requests.get, base, jwt, address,
    messages_path="/api/mails", timeout=180, poll_interval=3,
    log_callback=print,
    on_code_mail=lambda mid: cf.delete_mail(
        requests.delete, base, mid, admin_auth="your-admin-password",
    ),
)
```

## API 契约（路径均可在服务端配置中改）

| 用途 | 默认路径 | 方法 | 鉴权 |
|---|---|---|---|
| 建号（直建） | `/api/new_address` | POST `{domain?}` | 按 auth_mode |
| 建号（管理员） | `/admin/new_address` | POST `{name, enablePrefix:false, domain?}`，**不能**用旧版 address/password payload | 按 auth_mode |
| 收件列表 | `/api/mails` | GET `limit/offset`，兼容 `results/messages/data` 包裹 | `Authorization: Bearer <jwt>` |
| 邮件详情 | `/api/mail/{id}`，失败再试 `{收信接口}/{id}` | GET | 同上 |
| 删信 | `/admin/mails/{id}` | DELETE | `x-admin-auth`（管理员密码） |

鉴权模式 `auth_mode`：`none` / `query-key`（URL `?key=`）/ `bearer` / `x-api-key` / `x-admin-auth`；另有全局访问密码 `custom_auth` 独立叠加 `x-custom-auth` 头（服务端 PASSWORDS）。

## 配置键（主工程 config.json，核心模块对应参数）

| 键 | 默认 | 说明 |
|---|---|---|
| `cloudflare_api_base` | `""` | Worker 站点根地址，唯一必填 |
| `cloudflare_api_key` | `""` 🔒 | API Key / 管理员密码（按 auth_mode；删信复用） |
| `cloudflare_auth_mode` | `none` | 见上表五种 |
| `cloudflare_custom_auth` | `""` 🔒 | 全局访问密码 |
| `cloudflare_jwt_secret` | `""` 🔒 | 非空即启用 catch-all 免建号（只能写 config.json，不在 WebUI 表单） |
| `cloudflare_randomize_subdomain` | `false` | 建号挂随机子域，需服务端泛域 catch-all |
| `defaultDomains` | `""` | 收信域名（逗号分隔，主工程轮转选择） |
| `cloudflare_path_accounts/messages/...` | 见上表 | 接口路径 |

## 核心行为要点

1. **撞名重试**：并发建号撞 `Address already exists`（400/409）时换随机名重试最多 4 次；其余错误立即抛出且不回显响应体（防泄露服务端密钥）。用户名为拟真姓名池 + 随机后缀（`generate_username`）。
2. **收件人过滤**：轮询时 `to[].address`/`address` 必须匹配目标邮箱，防止多 worker 串信；每封邮件最多解析 5 次。
3. **验证码提取是启发式的**：先主题/句式锚定，再全文候选打分（字母数字混合加分、靠近 verification/xai 加分、靠近 HTML 样式特征扣分），拦截 `per-100` 等模板伪码；SpaceXAI 新模板全数字码 `427-599` 仅在确认上下文放行。
4. **删信失败不阻塞**：拿到验证码后触发 `on_code_mail` 清理收件箱，异常只记日志。
5. **主工程配套**（不在本目录）：邮箱 API 强制直连不走代理、域名池连续被拒自动拉黑、多配置档轮换且取码切回建号档——完整逻辑见主工程 `grok_register_ttk.py`。

## 主工程集成点

`email_providers/cloudflare.py`（核心客户端）、`email_providers/common.py`（共享工具）、`grok_register_ttk.py` L1271-2714（胶水层）、`connectivity.py` L125-198（建号端点探测）、`webui/email_provider_store.py`（配置存储）、`webui/email_domain_store.py`（域名池）。

注意：主工程里 `register_flow.py` 的 Turnstile（`challenges.cloudflare.com`）是人机验证、`docs/cloudmail.md` 是另一个邮箱提供商 CloudMail，均与本项目 "Cloudflare 邮箱" 无关。
