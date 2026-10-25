# Changelog

## Unreleased

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
