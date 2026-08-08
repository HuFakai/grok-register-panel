# macOS 本地启动、参数与 grok2api 接入指南

本文针对以下组合：

- macOS 本地运行 `grok-register-panel`
- CloudMail 或其它受支持邮箱服务
- CPA 可选远程部署
- Resin 运行在远程服务器，本机优先直连已认证的公网代理端口
- 新版 Go 后端 [chenyme/grok2api](https://github.com/chenyme/grok2api)

兼容性核对基线：2026-08-07 的 grok2api `main`，版本 `v3.1.1`，提交
`9c03e4aedd7ba64bdfb7383c34fbc851b8d36dd6`。后续若 grok2api 再次修改导入
协议，应优先以其管理页导出的样例文件和当前源码为准。

## 1. 运行关系

```text
macOS grok-register-panel
  ├─ 邮箱 API：CloudMail / Cloudflare / MoeMail / YYDS / DuckMail / MailNest
  ├─ 注册浏览器：Camoufox
  ├─ 出口代理：140.245.36.206:2261 → 远端 Resin（强制认证）
  ├─ 可选：SSO → OAuth → 远程 CPA
  └─ 账号产物 → TXT/JSONL → grok2api Grok Web → 转换为 Grok Build
```

本项目不要直接导入 VLESS、Trojan 或 Hysteria2 订阅。订阅由 Resin 解析和维护，
本项目使用 Resin 提供的 HTTP 正向代理入口。Camoufox/Firefox 不支持带用户名密码
认证的 SOCKS5 代理，因此 Resin 开启强制认证时不要给注册任务填写 `socks5h://`。

## 2. 首次安装

建议 Python 3.13。不要在已有虚拟环境上再次执行 `uv venv ... --replace`，否则已安装
依赖会被清空。

```bash
cd "/Users/fakaihu/Documents/project/注册机/grok-register-panel"

uv venv --python 3.13 .venv
source .venv/bin/activate

python -m pip install -U pip
python -m pip install -r requirements.txt
python -m camoufox fetch
```

验证：

```bash
.venv/bin/python -c "import playwright, camoufox, psutil; print('依赖正常')"
.venv/bin/python -m camoufox version
```

如果 `.venv` 已经存在，只需：

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m camoufox fetch
```

## 3. 创建配置

```bash
cp config.example.json config.json
chmod 600 config.json
```

推荐先通过 Web 面板配置邮箱服务和域名池。下面是与当前场景相关的最小示例；
不要直接复制示例中的占位值：

```json
{
  "email_provider": "cloudmail",
  "cloudmail_url": "https://mail.example.com",
  "cloudmail_admin_email": "admin@mail.example.com",
  "cloudmail_password": "替换为真实密码",
  "defaultDomains": "mail-a.example.com,mail-b.example.com",

  "proxy": "",
  "register_count": 10,
  "register_workers": 2,
  "account_interval": "60-120",
  "accounts_per_ip": 2,
  "ip_failure_rotate_threshold": 3,
  "sso_wait_timeout": 50,
  "sso_poll_interval": 0.5,
  "sso_retry_count": 3,
  "sso_retry_interval": 6,
  "enable_nsfw": false,

  "cpa_auto_add": true,
  "cpa_token_mode": "device_protocol",
  "cpa_auth_dir": "",
  "cpa_remote_url": "https://你的CPA管理地址",
  "cpa_management_key": "替换为CPA管理密钥",
  "grok2api_auth_dir": "grok2api_auth"
}
```

`defaultDomains` 可以用英文逗号或空白分隔多个域名。也可以在 Web 面板的
“邮箱服务 → 域名轮换 → 高级设置”中逐行导入；面板域名池配置后优先于旧字段。

## 4. 连接远程 Resin

当前 Resin 服务器地址为 `140.245.36.206`，公网代理接入点为 `2261`。根据 Resin
接入点配置，该端口已开启 HTTP 正向代理、SOCKS5 和强制客户端认证，并关闭了管理
页面与 HTTP 反向代理。这个分工适合作为公网代理端口，本机不再需要持续保持 SSH
连接。

### 4.1 公网与防火墙设置

先在 Oracle Cloud 安全列表或 NSG 中放行 TCP `2261`。来源应设置为当前 Mac 的公网
IPv4 加 `/32`，例如 `203.0.113.10/32`；不要长期使用 `0.0.0.0/0`。如果服务器还
启用了 UFW、firewalld 或其它主机防火墙，也要添加相同的来源限制。

公网只需开放 `2261`。Resin 管理端口 `2260` 应继续保持仅服务器本机可访问，不要
对公网放行。强制客户端认证不能代替防火墙白名单，两者应同时启用。

先测试 TCP 是否可达：

```bash
nc -vz -G 3 140.245.36.206 2261
```

再测试 HTTP 代理认证和实际出口 IP。下面的写法不会把 Token 直接写进命令历史：

```bash
read -s "RESIN_PROXY_TOKEN?Resin Token: "; echo
curl --fail --show-error \
  --proxy "http://Default.mac-test:${RESIN_PROXY_TOKEN}@140.245.36.206:2261" \
  https://api.ipify.org
echo
unset RESIN_PROXY_TOKEN
```

如果 Token 含有 `@`、`:`、`/` 等 URL 保留字符，需要先做 URL 编码，或直接在 Resin
中生成只含字母和数字的新 Token。

### 4.2 导入 Web 代理池

启动 Web 面板后，在“代理池”导入以下模板；把 `RESIN_PROXY_TOKEN` 替换成真实
Token，不要保留占位文字：

```text
http://Default.{session}:RESIN_PROXY_TOKEN@140.245.36.206:2261
```

这里必须使用 `http://`。虽然代理池检测器支持带认证的 `socks5h://`，但注册浏览器
基于 Firefox，Playwright 会在启动时报 `Browser does not support socks5 proxy
authentication`。HTTPS 注册页面会通过 HTTP 代理的 CONNECT 隧道访问，并不代表
注册流量是明文传输。

`{account}` 与 `{session}` 等价。程序会按 worker 和轮次展开为不同 Resin 身份：

```text
Default.grokreg-w1-r0
Default.grokreg-w2-r0
Default.grokreg-w1-r1
```

点击“检测”，确认状态为健康。固定用户名如 `Default.macbook` 可以连接，但所有
worker 会共享粘性身份；多并发应使用模板。

### 4.3 SSH 隧道备用方案

如果公网 `2261` 暂时不可达，可临时回退到原来的 SSH 隧道。这个终端必须保持
运行：

```bash
ssh -i "/你的私钥路径/服务器.key" \
  -N \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -L 2260:127.0.0.1:2260 \
  ubuntu@140.245.36.206
```

备用代理模板为：

```text
http://Default.{session}:RESIN_PROXY_TOKEN@127.0.0.1:2260
```

可用 `lsof -nP -iTCP:2260 -sTCP:LISTEN` 确认本机隧道是否仍在监听。不要同时把
公网和隧道模板作为两个代理导入，否则它们可能仍然落到同一组 Resin 出口节点。

## 5. 启动 Web 面板

生成面板 Token：

```bash
export MONITOR_TOKEN="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))')"
echo "$MONITOR_TOKEN"
```

同一个终端继续运行：

```bash
export MONITOR_HOST=127.0.0.1
export MONITOR_PORT=8787
export CPA_AUTH_DIR="$PWD/cpa_auth"
export PANEL_INCLUDE_TAIL=1

.venv/bin/python webui/monitor.py
```

浏览器打开：

```text
http://127.0.0.1:8787/
```

把终端中生成的 `MONITOR_TOKEN` 填入页面 Token 输入框。建议操作顺序：

1. “邮箱服务”选择实际服务商，保存后执行连接测试。
2. 如需多域名，展开高级设置逐行导入域名。
3. “代理池”导入 Resin 会话模板并检测到健康。
4. 运行模式先选“单批”。
5. 并发先设 `1` 或 `2`，稳定后再提高。
6. 开启“IP 注册数量控制”，每 IP 账号数设 `2`，Sticky 时长设 `300`。
7. 设置单批数量后点击启动。

停止任务请优先点击页面“停止”。在运行面板的终端按 `Ctrl+C` 也会停止属于当前
项目目录的编排器和批处理进程。

## 6. 不启动 Web 的命令行方式

macOS 不需要 `xvfb-run`：

```bash
.venv/bin/python -u run_batch_headless.py 10 2
```

最后两个参数分别是：

- `10`：本轮账号槽位数量。
- `2`：并发 worker 数。

监督进程会在浏览器驱动崩溃或长时间无输出时继续未完成槽位，并在整轮结束后刷新
账号汇总文件。

GUI 方式：

```bash
.venv/bin/python grok_register_ttk.py
```

## 7. 账号文件

每个注册任务单独一个文件夹 `accounts/tasks/<任务ID>/`（任务ID 形如
`20260807-143000-n40`），存放该任务产生的所有账号文件，避免账号过多时
根目录堆满文件：

| 文件 | 格式 | 用途 |
|---|---|---|
| `accounts/tasks/<任务ID>/accounts_all.txt` | `账号----密码----sso` | 本任务完整总表 |
| `accounts/tasks/<任务ID>/grok2api_web_sso.txt` | 每行一个 SSO | grok2api 的 Grok Web 快速 TXT 导入 |
| `accounts/tasks/<任务ID>/grok2api_web_accounts.jsonl` | 每行一个 JSON | grok2api Web 导入并保留邮箱、名称 |
| `accounts/tasks/<任务ID>/<邮箱>.txt` | `账号----密码----sso` | 单账号恢复和故障保护 |
| `accounts/tasks/<任务ID>/sso_pending.txt` | `邮箱----sso` | 本任务待重转 SSO 队列（补录会汇总所有任务） |
| `grok2api_auth/g2a-*.json` | `grok_build` OAuth JSON | 开启 SSO→OAuth 后生成的新版单账号 Build 导入文件 |
| `grok2api_auth/grok2api_build_accounts.jsonl` | 每行一个 Build JSON | 自动汇总的最新版 Build 批量导入文件 |

> 兼容：历史遗留的根目录账号文件仍会被聚合扫描（不迁移、不删除）；根目录不再
> 生成新的聚合文件。清理旧任务直接删除对应 `accounts/tasks/<任务ID>/` 文件夹。

所有凭据文件都会尽量保持 `0600`，目录保持 `0700`。不要上传到 GitHub、网盘公开
分享或粘贴到 Issue。

## 8. 导入最新版 grok2api

最新版 grok2api 将账号分为 Grok Web、Grok Build、Grok Console 三个独立池。

推荐流程：

1. 登录 grok2api 管理页面。
2. 打开“账号”，选择 **Grok Web**。
3. 点击导入，上传 `accounts/grok2api_web_accounts.jsonl`；也可上传
   `accounts/grok2api_web_sso.txt`。
4. 等待 Web 账号身份、额度同步完成。
5. 在 Web 账号页选择“转换为 Grok Build”。
6. 首次建议选择 `missing` /“仅缺失账号”，避免重建已经关联的 Build 账号。
7. 转换完成后切到 **Grok Build**，同步额度和模型。
8. 到“模型路由”确认实际可用模型，再创建客户端密钥。

如果本项目已经成功执行 SSO→OAuth，还可以在 Grok Build 页面直接导入
`grok2api_auth/grok2api_build_accounts.jsonl`，也可多选 `g2a-*.json`。
`grok2api_auth_dir` 只是本地输出目录，不会自动把文件
上传到远程 grok2api。

旧版 `issuer::client_id` 嵌套 `auth.json` 不再是新版 grok2api 的 Build 导入格式。
本项目已将 `g2a-*.json` 调整为最新版字段：`provider`、`client_id`、
`access_token`、`refresh_token`、`expires_at`、`email`、`user_id` 等。

## 9. config.json 参数

### 注册与浏览器

| 参数 | 默认/建议 | 说明 |
|---|---|---|
| `register_count` | `1` | GUI/CLI 默认单轮账号槽位数；Web 单批数量会覆盖它 |
| `register_workers` | `1`，建议 `1-3` | 并发浏览器数，不会超过本轮数量 |
| `account_interval` | `60-120` | 账号间隔秒数；`0` 不等待，`90` 固定等待，`60-120` 随机等待 |
| `accounts_per_ip` | `2` | 每个真实公网 IP 可完成的账号槽位；`0`=不限（只按连续失败换 IP）；成功与最终失败都计数 |
| `ip_failure_rotate_threshold` | `3` | 同一出口连续最终失败达到该次数即换 IP（始终生效）；成功会清零 |
| `sso_wait_timeout` | `50` | 提交注册资料后等待 SSO 的总窗口，允许 `15-180` 秒 |
| `sso_poll_interval` | `0.5` | Cookie 轮询间隔，允许 `0.2-2.0` 秒；过低只会增加浏览器调用 |
| `sso_retry_count` | `3` | 自然跳转未写入 SSO 时，最多轻量推进 grok.com 的次数，允许 `0-5` |
| `sso_retry_interval` | `6` | 两次推进之间的最短间隔，允许 `3-30` 秒 |
| `enable_nsfw` | `false` | 注册后尝试开启 Web NSFW；失败不应影响 SSO 保存 |
| `debug_mode` | `false` | 强制单账号、单并发并保留更多调试行为 |
| `close_browser_on_stop` | `false` | 手动停止时是否关闭浏览器；批处理正常结束仍会清理 |
| `log_level` | `info` | 日志等级预留项；敏感字段仍会脱敏 |
| `user_agent` | 示例 UA | 兼容配置；主要浏览器指纹由 Camoufox 管理 |
| `proxy` | 空或旧代理 | 旧版单代理回退；面板代理池一旦配置就优先使用面板池 |

### CPA 与 grok2api

| 参数 | 说明 |
|---|---|
| `cpa_auto_add` | 注册拿到 SSO 后是否继续换 OAuth；关闭时仍保存全部 SSO 导入文件 |
| `cpa_token_mode` | `device_protocol`、`device_browser` 或 `auth_code`；优先使用 `device_protocol` |
| `cpa_auth_dir` | 本地 CPA `xai-*.json` 输出目录；只用远程 CPA 时可留空 |
| `cpa_remote_url` | 远程 CPA Management API 根地址 |
| `cpa_management_key` | 远程 CPA 管理密钥，必须与 `cpa_remote_url` 成对配置 |
| `grok2api_auth_dir` | 新版 grok2api Build OAuth JSON 输出目录；不会自动上传 |

主要使用 grok2api 时，即使 `cpa_auto_add=false` 也不影响 Web SSO 导入和 Web→Build
转换；这通常比注册时同时进行 OAuth 转换更容易排查。需要远程 CPA 同步时再打开。

### 邮箱服务

| 参数 | 说明 |
|---|---|
| `email_provider` | `cloudflare`、`cloudmail`、`moemail`、`yyds`、`duckmail`、`mailnest` |
| `defaultDomains` | Cloudflare/CloudMail 可用域名，逗号或空白分隔 |
| `cloudmail_url` | CloudMail 站点 URL |
| `cloudmail_admin_email` | CloudMail 管理员邮箱 |
| `cloudmail_password` | CloudMail 管理员密码 |
| `cloudflare_api_base` | Cloudflare 临时邮箱 Worker/API 根地址 |
| `cloudflare_api_key` | Cloudflare 邮箱 API Key |
| `cloudflare_auth_mode` | `none`、`query-key`、`bearer`、`x-api-key`、`x-admin-auth` |
| `cloudflare_custom_auth` | Cloudflare 邮箱服务的全局管理密码 |
| `cloudflare_path_*` | 域名、建号、Token、邮件接口路径；一般保持默认 |
| `duckmail_api_base` | DuckMail/Mail.tm API 根地址 |
| `duckmail_api_key` | DuckMail API Key，公共域可能允许留空 |
| `yyds_api_key` / `yyds_jwt` | YYDS 两种鉴权方式，按服务要求选择 |
| `yyds_default_domain` | YYDS 固定域名；留空自动选择 |
| `mailnest_api_key` | MailNest API Key |
| `mailnest_project_code` | MailNest 项目代码，默认 `x-ai001` |
| `moemail_api_base` | MoeMail 站点 URL |
| `moemail_api_key` | MoeMail `X-API-Key` |
| `moemail_domain` | MoeMail 固定域名；留空自动读取可用域名 |
| `moemail_expiry_ms` | `3600000`、`86400000`、`604800000`、`0`，对应 1 小时、1 天、7 天、永久 |

## 10. Web/运行环境变量

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `MONITOR_TOKEN` | 空 | 面板写接口必需的 Bearer Token |
| `MONITOR_HOST` | `127.0.0.1` | Web 绑定地址；本机使用不要改为公网地址 |
| `MONITOR_PORT` | `8787` | Web 端口 |
| `MONITOR_STOP_TASKS_ON_EXIT` | `1` | 关闭面板时停止当前项目任务；设 `0` 才允许任务继续 |
| `PANEL_INCLUDE_TAIL` | 本机默认开 | 是否向页面返回脱敏日志尾部 |
| `MONITOR_CORS_ORIGIN` | 空 | 可选的单一允许跨域来源 |
| `CPA_AUTH_DIR` | `./cpa_auth` | 面板统计 CPA 文件的位置，不等同于远程 CPA URL |
| `BATCH_LOG` | 自动发现 | 强制指定面板读取的批处理日志 |
| `GROK_BATCH_IDLE_TIMEOUT` | `360` | 子进程无输出多少秒后判定卡住，最小 60 |
| `GROK_BATCH_MAX_RESTARTS` | `8` | 浏览器驱动崩溃/卡住时最多恢复次数 |
| `GROK_PYTHON_BIN` | 项目 `.venv` | 显式指定运行任务的 Python |
| `GROK_USE_XVFB` | `auto` | macOS 不使用；Linux 可设 `auto`、`1`、`0` |
| `PROXY_POOL_STATE_FILE` | `log/proxy_pool.json` | 面板代理池状态与凭据文件 |
| `PROXY_POOL_LEGACY_FILE` | `proxies.txt` | 旧代理文件位置 |
| `PROXY_NETWORK_COOLDOWN_SECONDS` | `90` | 网络故障代理冷却秒数 |
| `PROXY_RISK_COOLDOWN_SECONDS` | `1800` | 注册风控代理冷却秒数 |
| `EMAIL_PROVIDER_CONFIG_FILE` | `config.json` | 邮箱服务配置文件 |
| `EMAIL_DOMAIN_POOL_STATE_FILE` | `log/email_domain_pool.json` | 邮箱域名池状态文件 |
| `BLACKLIST_STATE_FILE` | `log/blacklist_state.json` | ASN 黑名单状态文件 |
| `CLOUDMAIL_URL` | 空 | 可覆盖 `config.json.cloudmail_url` |
| `CLOUDMAIL_ADMIN_EMAIL` | 空 | 可覆盖 CloudMail 管理员邮箱 |
| `CLOUDMAIL_PASSWORD` | 空 | 可覆盖 CloudMail 管理员密码 |
| `MOEMAIL_API_BASE` / `MOEMAIL_API_URL` | 空 | 可覆盖 MoeMail URL |
| `MOEMAIL_API_KEY` | 空 | 可覆盖 MoeMail API Key |

## 11. 常见问题

### `ModuleNotFoundError: playwright`

通常是重建 `.venv` 后没有重新安装依赖：

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m camoufox fetch
```

### 代理检测失败

公网模式依次确认 `nc -vz -G 3 140.245.36.206 2261` 可达、云安全列表/NSG 与服务器
防火墙允许当前公网 IP、Resin Token 正确、2261 接入点处于启用状态。家用宽带公网
IP 变化后，需要同步更新 `/32` 白名单。

备用隧道模式则确认 SSH 进程仍在、`127.0.0.1:2260` 正在监听。不要把 Resin
Docker 内部地址 `resin:2260` 直接填到 Mac。

### 新会话还是同一个 IP

Resin 新身份不保证一定映射到不同节点。本项目会核验真实 IP；若没有变化，会等待
Sticky 时长并继续检测。订阅中只有少量健康出口时尤其常见。

开启“IP 注册数量控制”时，只有账号槽位数或 Sticky 时长达到页面设置才主动换
会话。例如设置仍为 `10` 个和 `1500` 秒时，完成 3 个账号不会触发轮换。关闭开关
后不再按数量或时间轮换，只有连续最终失败达到“连续失败换 IP”阈值才更换；任一
账号成功都会把该 worker 的连续失败数清零。

### 清理过期日志

控制台“日志尾部”上方可设置保留天数并点击“清理过期日志”。清理范围仅限
`log/*.log`，最新批处理/编排日志会保留；代理池、邮箱域名池、账号结果 JSONL、
PID 和锁文件不会被删除。保留天数允许 `1-365`。

### grok2api 导入账号后没有 Grok Build

SSO TXT/JSONL 导入的是 Grok Web。进入 Web 账号操作执行“转换为 Grok Build”，
等待转换和模型同步完成。注册成功本身不等于已经获得 Build OAuth 凭据。

### 安全提醒

- `accounts/`、`grok2api_auth/`、`cpa_auth/`、`config.json` 都包含敏感材料。
- Resin Token、订阅链接、CPA Management Key 泄露后应立即轮换。
- Resin 公网端口 `2261` 应同时启用强制认证和来源 IP 白名单；不要公开管理端口 `2260`。
- Web 面板只绑定 `127.0.0.1`；需要远程访问时优先使用 SSH/Tailscale。
- 不要在截图或故障日志中展示完整 SSO、密码、代理 URL 或管理密钥。
