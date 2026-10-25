# 上游仓库合并记录（Upstream Merge Log）

记录从上游仓库合并/评估的提交边界，方便下次合并时**从上次检查点之后的新提交开始**，
不必重新核对全部历史。

## 上游仓库信息

- URL: `https://github.com/lij768423-svg/grok-register-panel`
- 本地 remote ref: `refs/remotes/upstream-lij/main`（`git fetch <url> main:refs/remotes/upstream-lij/main`）

## 合并边界（检查点）

| 项 | Commit |
|---|---|
| 本地 fork 点（本地已包含其全部内容） | `280c98e` |
| 上次合并到的上游 HEAD | `bc17ebd`（本次已评估，2026-10-26 第四轮） |
| 下次合并起始点 | `bc17ebd` 之后的上游新提交 |

> 本地仓库与上游**无共同祖先**（独立重写历史），不能用 `git merge`，
> 需按文件逐个人工移植（`git show <commit> -- <file>` 取补丁）。

## 本次合并内容（2026-10-26 第四轮：ae281f9 → bc17ebd）

### 已收编（P0+P1）

| Commit | 标题 | 说明 |
|---|---|---|
| `90fd1a5` | fix: keep signup scripts out of the static asset cache | 静态缓存不再回放 JS（JS/Castle 脚本与 400 email-signup-unavailable 相关），`context.route("**/*")` 改按扩展名精确 glob；verify-email 页按已发码处理。新文件 `signup_decisions.py` + `tests/test_signup_page_decision.py`；`static_asset_cache.py` 直接取上游版；register_flow 接入（与本地限流识别/域名拒绝融合）。**注**：`/Users/macm2/code/grok-register-panel/log/static-asset-cache` 已中毒，同步前已清空重建 |
| `35edb43` | feat: Outlook 卡池 provider、住宅出口等待放宽、CPA chat 版本头升至 1.0.13 (#45) | `email_providers/outlook.py` + 测试直接取上游；ttk 取号/收码分发、CLI worker 三处回收钩子（域名拒绝/卡住跳过/通用失败）、GUI 配置页、config 三键；**本地扩展**：GUI worker（run_registration）同步补了 4 处回收钩子（mail 换邮箱重试、域名拒绝、卡住跳过、通用失败），上游只覆盖 CLI；`camoufox_adapter` domcontentloaded + register_flow 等待放宽 8s→20s/10s→25s（补丁干净应用）；`sso_to_auth_json` GROK_CLIENT_VERSION=1.0.13（env 可覆盖，CPA 头专用，token 交换保持 0.2.93） |

### 忽略

| Commit/范围 | 原因 |
|---|---|
| `8e268bc`/`e4987eb` release prep、star history ×15、docs（README/IPWO/landing）、WINDOWS.md、Windows runtime（5ee2366） | 文档/版本/平台不适用 |
| `quality_probe.py` 降智测试、`webui/quality_ops.py`、botFlagSource 风控门降级（88ca73c/2776166/bdcf598） | P2 范围，用户暂缓，后续评估 |
| `97d7dcf` SpaceXAI 数字验证码、`dbcd902` EPIPE+overlay wait、`a4f2d7f`/`d5ea007` inbucket、`bf359a0`/`40f2104`/`11ff721`/`94fc9b8` outlook_rt/SSO 状态、`710ec39` SSO 隔离 | 之前轮次本地已收编等价实现（common.py 字节级一致、inbucket/outlook_rt/epipe-guard 一致、SSO 面板本地超集），无需重复 |

## 本次合并内容（2026-08-12 第三轮：0371716 → ae281f9）

### 已收编

| Commit | 标题 | 说明 |
|---|---|---|
| `9b91ab6` | feat: reduce registration traffic and harden Windows runtime | 流量削减 + Windows 加固。新文件 `retry_policy.py`（重试收敛：启动 2/代理轮换 3/槽位重试 1/supervisor 重启 2，env 可覆盖）、`batch_traffic.py`（本地代理流量计量层，env 门控）；batch_supervisor 管道重写（queue 读线程 + EOF 宽限，保留 a03b789 增量解码语义）+ 78 码不重启；browser_session 探测源 6→3 + 2-20s 预算 + 启动收敛 + meter 接线；run_batch_headless 预检失败返回 78 整批中止 + batch_id 注入；run_until_100 编排失败上限 + rc==78 整批终止；grok_register_ttk 重试收敛 + 预检中止（移除 proxy_fallback_to_local 逃生口，用户确认）+ `_sleep_cancelable`（修复本地潜在 NameError） |
| `ae281f9` | feat: add rolling batch traffic averages | 批次流量滚动平均：history 归档 + 每批/每成功号平均流量 KPI + mark_successful_account |
| `9c5f14d` | fix: validate proxy pool against xAI precheck | 代理池探测追加 xAI 注册页可达性校验；network 冷却到期置 unknown 需重新探测（与本地可用 IP 池互补） |
| `cbd6059` | feat: improve registration recovery and panel telemetry | register_flow SSO 恢复：sign-in 自动登录（以本地 20s hold + 最终页重试块为基准融合）；cloudflare 撞名重试 + randomize_subdomain（默认 false 按本地）；generate_username 随机后缀；邮件直连按配置 base 匹配；monitor 北京时间统一 + 30s 全量刷新 + traffic KPI；blacklist mtime 北京时间 |
| `e73f3cb` | feat: track in-flight jobs across release roots | GROK_COMPAT_PROCESS_ROOTS 跨 release 根进程发现/终止（保留本地 kill_all grace 语义） |
| `4c919a3` | fix(windows): guard fchmod/msvcrt locks and optional headless | `best_effort_fchmod` 助手 + 4 处内联替换（收编通用部分）；GROK_HEADLESS/GROK_HEADED 开关 + 软件渲染 prefs。**跳过** msvcrt 锁/tzdata（纯 Windows） |
| `52909bf` | fix: preserve virtualenv interpreter overrides | GROK_PYTHON_BIN resolve→abspath 保留 venv 符号链接（通用正确性） |
| `b2eb6a2` | fix: reuse Windows-safe file permissions in panel jobs | run_until_100/monitor/recovery_ops 裸 os.fchmod → best_effort_fchmod |

### 忽略

| Commit | 标题 | 原因 |
|---|---|---|
| `ac366e0`+`c1c4d71` / `c77960f`+`7624423` | docs: README/agent guide/remove private links | 文档 |
| `47c7f8e` / `f4b6699` | chore: update star history | 仅 SVG |
| `536b8dc`+`af0de55` / `4f88645` / `0d32188` | docs/release v0.4.0/v0.4.1 | 文档/版本 |
| 4c919a3 的 msvcrt 锁 / tzdata / firefox Windows prefs 分支 | 纯 Windows | macOS 走 fcntl/POSIX，无需 |

## 本次合并内容（2026-08-09）

### 已收编：BFS JWT 风控检测（上游唯一实质新功能）

| Commit | 标题 | 说明 |
|---|---|---|
| `55e4249` | feat: add JWT bfs claim detection for register + panel | BFS 检测全套（注册侧 + 面板 + CLI + 测试） |
| `eb2ca9f` | fix: harden BFS token detection and auth scanning | BFS 加固（JWT 解码、目录扫描） |
| `98da9f6` | Merge PR #15 | 上述两提交的合入（上游 HEAD） |

收编文件：`webui/bfs_ops.py`、`scripts/check_bfs.py`、`tests/test_bfs_detect.py`、
`sso_to_auth_json.py`（BFS 函数群）、`grok_register_ttk.py`（注册侧检测）、
`webui/monitor.py`（BFS 面板）、`config.example.json`（bfs_* 三项）、
`webui/recovery_ops.py`（豁免名单）。

### 忽略：star 图自动更新（CI 提交，仅 docs/star-history-*.svg）

`b3a128d`、`4c1fa66`、`9559e3c`、`91b025b`、`55ebe16`、`ee6a6d7`、`f913952`、`0371716`

## 本次合并内容（2026-08-09 第二轮）

自检查点 `98da9f6` 之后新增 4 个实质提交，除 connectivity 修复外全部收编。

### 已收编

| Commit | 标题 | 说明 |
|---|---|---|
| `a03b789` | fix: drain supervisor output before crash detection | supervisor 管道缓冲崩溃检测：`text=True, bufsize=1` readline 会遮蔽崩溃标记 → 改二进制分块 + 增量 utf-8 解码，崩溃即时重启。保留本地优雅停止改动 |
| `e2c6301` | fix: preserve refreshed success statistics | 面板 2s 快照轮询冲掉「统计已刷新」完整数据 → `fullStats` 缓存 + `statsForSnapshot()` 合并（jsonl/day 统计保留，快照只更新实时计数器） |
| `03a8f7e` | feat: integrate optional static asset cache | opt-in 静态资源磁盘缓存（`GROK_STATIC_ASSET_CACHE=1` 门控）：JS/CSS/字体/图片共享缓存，不缓存文档/XHR/Turnstile，不共享 cookie。新文件 `static_asset_cache.py` + 兼容入口 `run_batch_headless_static_cache.py`/`run_until_100_static_cache.py` + `browser_session.py` 挂载（try/except） |
| `f65f00f` | fix: handle configured BFS auth paths | BFS `Path.is_abs()`→`is_absolute()`（Python 3.11+ 兼容，本地 webui/bfs_ops.py 此前已覆盖该修复）；补 `tests/test_bfs_ops.py` |

### 忽略

| Commit | 标题 | 原因 |
|---|---|---|
| `8b7354c` | fix: avoid false admin email preflight failures | connectivity 预检改 TCP-only；本地真实探测建号端点更优，不合并（对应上游测试 `test_cloudflare_direct_create_does_not_probe_admin_domains` 一并跳过） |
| `9e23229` + `7768eb4` | release: prepare v0.3.0 | 版本发布（版本号/CHANGELOG） |
| `0371716` | chore: update star history | 仅 SVG |

## 上游提交全清单（评估状态）

### fork 点之前（本地已包含，无需合并）

`1ad750d` → `280c98e` 之间的全部提交（Initial snapshot → 跨平台面板）：
1ad750d、4c8ee7f、2c551b4、41793ba、484030f、4723a84、b6b7389、acbfc89、
8e25f48、a1a8dbd、a1c3099、d7e6b09、d5451c3、bb36dd1、302faef、674fdf6、
1261c08、d7403ee、bbca29f、f3fab91、caba51c、addd8f3、51482f7、dd83414、
5a240d3、5db6a6a、280c98e

> 这些功能（外部代理池、邮箱域名池、邮箱服务商配置面板、MoeMail、batch 崩溃恢复、
> 跨平台面板等）本地 fork 时已包含，逐字节一致。

### fork 点之后（本次已评估）

| Commit | 标题 | 状态 |
|---|---|---|
| `f913952` ~ `b3a128d`（7 个） | chore: update star history | 忽略（仅 SVG） |
| `55e4249` | feat: add JWT bfs claim detection | ✅ 已收编 |
| `eb2ca9f` | fix: harden BFS token detection | ✅ 已收编 |
| `98da9f6` | Merge PR #15 | ✅ 已评估（= 收编上述两项） |
| `03a8f7e` | feat: integrate optional static asset cache | ✅ 已收编 |
| `a03b789` | fix: drain supervisor output before crash detection | ✅ 已收编 |
| `8b7354c` | fix: avoid false admin email preflight failures | ⏭ 跳过（本地真实探测更优） |
| `f65f00f` | fix: handle configured BFS auth paths | ✅ 已收编（is_absolute 本地已覆盖，补测试） |
| `e2c6301` | fix: preserve refreshed success statistics | ✅ 已收编 |
| `9e23229` + `7768eb4` | release: prepare v0.3.0 | ⏭ 跳过（版本发布） |
| `0371716` | chore: update star history | ⏭ 跳过（仅 SVG） |
| `47c7f8e` / `f4b6699` | chore: update star history | ⏭ 跳过（仅 SVG） |
| `ac366e0`+`c1c4d71` / `c77960f`+`7624423` | docs: README/agent guide | ⏭ 跳过（文档） |
| `536b8dc`+`af0de55` | docs: runtime optimization notes | ⏭ 跳过（文档） |
| `4f88645` / `0d32188` | release v0.4.0 / v0.4.1 | ⏭ 跳过（版本发布） |
| `cbd6059` | feat: recovery + panel telemetry | ✅ 已收编（SSO 恢复融合 + 撞名重试 + 北京时间等） |
| `e73f3cb` | feat: track in-flight jobs across release roots | ✅ 已收编 |
| `9b91ab6` | feat: reduce registration traffic + Windows 加固 | ✅ 已收编（重试收敛/流量计量/78 码中止） |
| `4c919a3` | fix(windows): fchmod/headless | ✅ 部分收编（best_effort_fchmod + GROK_HEADLESS；跳过 msvcrt/tzdata） |
| `52909bf` | fix: preserve virtualenv interpreter overrides | ✅ 已收编 |
| `b2eb6a2` | fix: reuse Windows-safe file permissions | ✅ 已收编 |
| `9c5f14d` | fix: validate proxy pool against xAI precheck | ✅ 已收编 |
| `ae281f9` | feat: add rolling batch traffic averages | ✅ 已收编 |

## 下次合并指引

1. `git fetch https://github.com/lij768423-svg/grok-register-panel main:refs/remotes/upstream-lij/main`
2. `git log --oneline bc17ebd..refs/remotes/upstream-lij/main`（只看到检查点之后的新提交）
3. 逐个人工移植新功能（无共同祖先，勿用 git merge）
4. 移植后更新本文档的「上次合并到的上游 HEAD」为新 HEAD

## 本地保留的增强（合并时不得被上游覆盖）

cloudflare 启动检查真实探测建号端点、register_flow 20s SSO hold + 最终页重试块、
catch-all 免建号 + 随机子域 + 验证码后删邮件、可用 IP 池（ip_ready_pool）、
空页临时冷却软拉黑（soft_blacklist）、IP 使用统计/启动前预检/分页（5 列）、
配置一键导出导入、邮箱多配置档（profiles）、results_store/ip_usage_store/config_backup、
notify_push、proxy_templates、account_exports 任务目录等。
