# Changelog

## Unreleased

- 「IP 使用」页重构为四个功能标签（数据统计 / 可用 IP 池 / 出口健康 / 策略设置），每个列表独立分页；策略设置页可在线调整池目标、低水位、可信优先阈值与成功/失败/限流冷静期，保存即时生效。
- 成功过的出口不再因单次失败终身拉黑：成功一次冷静 15 分钟，失败按 1h/2h/4h/8h/16h 翻倍（封顶 24h）冷静，限流冷静 24h；冷静期结束自动回到可信池复用。旧版本残留的 `banned` 与永久软拉黑哨兵（≥99999）在读取可信出口时自动纠正，历史成功 IP 直接恢复可用。
- 可信优先阈值（默认 3）落地：可信可用出口达到阈值时优先固定复用成功会话，低于阈值时先消费可用池探测项；池内可用低于低水位（默认 5）时立即补探测（20 秒冷却），不再只等定时周期。
- 「核验会话」改走专用 `/api/ip-health/verify`，只核验到期可信出口，不再误触发补池探测。
- 测试隔离：新增 `tests/conftest.py` 隔离真实 `log/ip_health.json`；补充标签/分页/策略接口/会话核验单测，并修复 grok2api 即时上传日志在路径切换后仍写旧文件的问题。

## 0.2.2 - 2026-10-26（可用 IP 池升级：筛选-消费-回收-复验闭环）

- 新增出口健康档案（`webui/ip_health.py` + `log/ip_health.json`）：注册结果自动回写，成功出口归档会话身份并提升可信度，失败累计黑历史；失败≥2 且从未成功的出口在取口/预检/换口三层全部跳过（失败即弃）。
- 可用 IP 池新增 trusted 区：注册成功过的出口连同 sticky 身份以 7 天（resin 租期）有效期优先复用，`pick_usable` 按 trusted 优先排序；会话核验存活自动续期，连续 2 次失效自动降级。
- 池空兜底链重排：池候选 → leftovers → 可信出口（固定身份直连）→ 随机取模；`scripts/fill_residential_pool.py`（ip-api hosting + 已知机房 ASN 双过滤）灌池结果直接被 worker 消费。
- 面板后台补池线程升级：每轮先核验到期可信出口的 sticky 会话存活（默认 30 分钟一批），存活回灌池、失效降级；「立即探测」按钮同步触发核验。
- 面板新增「住宅出口健康」区块：可信出口的成功/失败计数、ASN 归属、会话存活状态、上次成功时间；池详情表格增加「★ 可信复用」徽标。
- 实测数据：6 个住宅出口 sticky 会话 1 小时后存活率 5/6；复用可信出口跑 3 连注册 3/3 成功（0 新 IP 消耗）。

## 0.2.1 - 2026-10-26（上游同步第四轮）

- 同步上游 v0.6.1 静态缓存修复：缓存只收 CSS/字体/图片，注册页脚本（Castle token）不再从磁盘回放，消除 send-verification-code 400 "Email sign-up isn't available" 的假限流；`context.route` 由 `**/*` 改为按扩展名精确 glob；"Verify your email" 页按已发码处理。
- 新增 signup_decisions 纯函数页面判定（verify-email/CF 等待/壳页分类、submit 黑名单、Turnstile 判定），register_flow 融合接入（保留本地限流识别与域名拒绝）。
- 新增 Outlook/Hotmail 卡池 provider（email----password----client_id----refresh_token，IMAP XOAUTH2 收码，失败未注册邮箱自动回池尾）；CLI worker 与 GUI worker 均接入回收钩子（GUI 侧为本轮本地扩展）；config 新增 outlook_accounts_file / outlook_used_file / outlook_proxy。
- CPA chat 请求头客户端版本升至 1.0.13（env `GROK_CLIENT_VERSION` 可覆盖），token 交换链路保持 0.2.93；10-22 之后注册的账号低版本头会拿 HTTP 426。
- 页面导航默认 `domcontentloaded`，注册页/邮箱表单等待 8s→20s、邮箱按钮 10s→25s（住宅出口友好，数据中心出口同样受益）。

- Supervise headless batches and automatically resume remaining task slots after a Playwright/Camoufox driver crash or stall.
- Persist batch slot progress atomically so completed accounts are not repeated during recovery.
- Make panel process management and batch launch platform-aware: `psutil` discovery, Linux auto-Xvfb, macOS direct launch, Windows virtualenv paths, and actionable missing-procfs errors.

## 0.2.0 - 2026-07-30

- Redesign the live panel with responsive light and dark themes.
- Add a dedicated usage and troubleshooting view.
- Add pending SSO and account-file recovery with success dequeue.
- Move learned ASN rules from Python source into locked JSON state.
- Scope process discovery and termination to one project root.
- Require monitor authentication for operational read and write APIs.
- Add security headers, bounded request bodies, and redacted log output.
- Create runtime credentials, account data, logs, state, and PID files owner-only.
- Add release tests, CI, a systemd service template, and deployment checks.
