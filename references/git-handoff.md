# Git、远端与部署

本流程只在用户选择设备交接且已授权相应动作时执行提交或推送；制作/审核 Skill 本身不替代一次真实项目交接。

## 检查顺序

```text
git --version
git rev-parse --show-toplevel
git branch --show-current
git rev-parse HEAD
git status --short
git remote -v
git diff --check
```

Git 未安装时，先确认系统和可用包管理器，再通过可信的系统渠道安装并复核版本；完整设备交接已授权必要安装时不重复询问，但仍遵守系统权限审批。仅只读检查时给出安装指引。当前目录不是 Git 根目录时先定位实际根目录；确实尚未纳入 Git 且完整交接已授权初始化时，可在确认的项目根初始化，不能在子目录制造嵌套仓库。

## 暂存与提交

交接文件生成后先看 `git status --short`、`git diff --stat`、`git diff --cached --check` 和秘密扫描。只暂存用户授权范围；已有无关修改、删除、未跟踪文件不能静默纳入或丢弃。明确要保存工作进度时，提交信息使用 `handoff(<scene>): prepare <YYYY-MM-DD>`，并注明这是工作快照，不代表业务验收通过。若存在 staged 外部改动，先复核范围，不能覆盖。

提交前检查 worktree、submodule、LFS 和外部资产；未纳入内容写入 `任务交接.md` 或 `环境与验证.md`。

## 远端同步

- 有 remote：核对名称、URL、当前分支、目标分支和权限；秘密扫描远端 URL，不能把 token 写入文件或命令输出。
- 原始 `git remote -v` 输出可能含凭证；只在可保证不回显秘密的方式下检查并展示脱敏结果。先 fetch 核对远端最新状态，失败时把原跟踪引用标为可能过时。
- 无 remote：记录未绑定状态，向用户索要仓库地址和可见性，不能猜测。
- 推送需要用户授权，除非当前请求明确包含提交并推送；不 force push、不自动处理冲突。
- 推送前复核 staged diff；推送后用远端查询核对目标分支实际 commit。若远端较新或分叉，先记录并停止自动合并。
- 网络失败时保留本地交接包并记录错误，不把本地提交称作云端完成。

最终上传范围必须覆盖授权项目成果、整个可携带交接目录及便携 Skill。检查 `.gitignore` 是否遗漏必要文件，不对未知目录盲目 `git add -A`，不绕过 LFS 或远端大小限制。已有 remote 不是 GitHub 时如实说明并核对用户目标，不擅自替换。涉及凭证登录时让用户在安全登录流程操作，不要求把 token 发到对话。

新设备接收时先 `git fetch --prune`、`git status --short`，再在批准分支执行 `git pull --ff-only`；发现本地修改、分叉或远端变化时先报告。
