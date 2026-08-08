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
| 上次合并到的上游 HEAD | `98da9f6`（本次已评估） |
| 下次合并起始点 | `98da9f6` 之后的上游新提交 |

> 本地仓库与上游**无共同祖先**（独立重写历史），不能用 `git merge`，
> 需按文件逐个人工移植（`git show <commit> -- <file>` 取补丁）。

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

`b3a128d`、`4c1fa66`、`9559e3c`、`91b025b`、`55ebe16`、`ee6a6d7`、`f913952`

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

## 下次合并指引

1. `git fetch https://github.com/lij768423-svg/grok-register-panel main:refs/remotes/upstream-lij/main`
2. `git log --oneline 98da9f6..refs/remotes/upstream-lij/main`（只看到检查点之后的新提交）
3. 逐个人工移植新功能（无共同祖先，勿用 git merge）
4. 移植后更新本文档的「上次合并到的上游 HEAD」为新 HEAD

## 本地保留的增强（合并时不得被上游覆盖）

cloudflare 启动检查真实探测建号端点、register_flow 20s SSO hold、catch-all 免建号 +
随机子域 + 验证码后删邮件、IP 使用统计/启动前预检/分页、配置一键导出导入、
邮箱多配置档（profiles）、results_store/ip_usage_store/config_backup、
notify_push、proxy_templates、account_exports 任务目录等。
