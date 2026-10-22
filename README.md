# NJMU 校园网自动化连接程序 · 单源仓库

本仓库自 **1.5.9.2** 起是产品源码的**唯一真源（single source of truth）**。
之前 1.5.2–1.5.9.1 的代码只存在于历史构建暂存目录（现归档于 `archive\build_stage\work`）
与各发布 zip 中，历史代码没有版本管理；从 1.5.9.2 起纳入 git，之后任何改动先提交再发版。

## 目录结构

```
repo\
  app\                    产品源码树（构建的根目录）
    src\campus_net_assistant\   Python 包（含 native\bin\NpcapBridge.exe）
    tests\                      隔离回归测试
    tools\                      辅助脚本
    build_local.py              PyInstaller onedir 打包 + 校验 + 出 zip
    version_info.txt            exe 版本资源模板
    使用说明.txt                随包说明（构建时替换 {{VERSION}}）
  releases\<version>.json   发布记录索引（**进版本库**，每次发版一条）
  build_release.ps1       从本仓库出发布包（zip + sha256）
  publish_release.ps1     把已构建的发布包上传到 GitHub Releases
  CHANGELOG.md            版本变更记录（发版说明的正文来源）
  README.md               本文件
```

版本号唯一来源：`app\src\campus_net_assistant\version.py`。

依赖（PySide6 / shiboken6 / PyInstaller）体积约 650 MB，**不进版本库**，放在仓库外：

```
<工作区>\archive\build_stage\work\campus-net-assistant\vendor
```

## 出包与发布包放置规范

```powershell
pwsh .\build_release.ps1                 # 构建，并把 zip + sha256 放到 <工作区>\releases\<主.次>.x\
pwsh .\build_release.ps1 -NoCopy         # 只构建，不复制（试构建用）
pwsh .\build_release.ps1 -Vendor 'D:\other\vendor'
pwsh .\build_release.ps1 -RebuildBridge  # 强制重编 native\bin\NpcapBridge.exe
```

脚本会：读 `version.py` → 调 `build_local.py`（PyInstaller onedir + Rawether 桥编译 +
GUI 冒烟检查 + 桥自检）→ 校验 sha256 → 复制发布包 → 在 `releases\<version>.json` 留记录。

**放置规则（唯一约定）**

| 内容 | 位置 | 是否进 git |
|---|---|---|
| 发布包本体 zip + `.sha256.txt` | `<工作区>\releases\<主.次>.x\`（如 `1.6.x`） | 否 |
| 发布记录索引 | `repo\releases\<version>.json` | **是** |

也就是：**二进制留在工作区、索引进仓库**。`<主.次>.x` 由版本号自动推出（`1.6.3` → `1.6.x`），
不需要手工建目录，也不会再堆到工作区根目录。

## 上传 GitHub Releases

```powershell
pwsh .\publish_release.ps1 -DryRun       # 只打印将要执行的命令，不改变任何东西
pwsh .\publish_release.ps1               # 打标签 v<version>，上传 zip + sha256，正文取 CHANGELOG 对应小节
pwsh .\publish_release.ps1 -Draft       # 传成 draft，先人工看一眼
```

脚本会先核对 zip 的 sha256 与 `releases\<version>.json` 是否一致，不一致直接拒绝发布。
tag 名固定为 `v<version>`（与已有 `v1.5.9.2`…`v1.6.3` 一致）。

资产名用 ASCII：GitHub 会把资产名里的非 ASCII 字符压成点（中文文件名会变成 `NJMU.-…`），
因此脚本把 zip 复制成 `NJMU-CampusNet-Assistant-<version>-Windows-x64.zip` 再上传，
sidecar 内容也按该名生成，下载后可直接 `sha256sum -c`。本地 `releases\` 仍保留中文文件名。

凭据按以下顺序自动解析，任一可用即可（脚本会把实际用的来源打印出来）：

1. `gh auth login`（交互登录，要求令牌带 `repo` + `read:org`）
2. 环境变量 `GH_TOKEN` / `GITHUB_TOKEN`
3. **git 凭据管理器里已存的本仓库推送令牌**（只需 `repo`，不需 `read:org`）——本机当前走的就是这条

所以即使没做 `gh auth login` 也能发版：`gh` 只在登录校验时要求 `read:org`，
用 `GH_TOKEN` 调 Release 接口不受此限（已验证能列出 v1.3.1 / v1.4.3）。

前置条件（本机已完成）：远程 `origin` = `https://github.com/1204799421-bit/njmu-campus-net-assistant.git`，
`gh` 2.102.1 已通过 `winget install --id GitHub.cli` 安装。

```powershell
# 需要交互式 gh（如 gh repo view / gh pr）时才做，需要带 read:org 的令牌
gh auth login
```

没有 gh 时按脚本打印的浏览器方式手工上传即可，命令和资产路径都会列出来。

## 版本规则

- `version.py` 是唯一来源，`build_local.py` 会校验格式并写进 exe 资源。
- 1.5.x：补丁号递增（1.5.9.1、1.5.9.2…），只做点修。
- **1.6**：保活会话身份与互斥体的根治版本（见 `..\docs\analysis\1.6-根治方案-保活进程身份与会话互斥.md`）。
  该版本会重编 `NpcapBridge.exe`，桥哈希变化会导致每台机器需重新做一次原生认证验证。

## 注意

- 不要在 `archive\build_stage\` 或 `archive\product\` 里构建：这些是归档的旧流水线，源码树已过时。
- `NpcapBridge.exe` 自 1.5.8 起字节不变；若重编它，必须同步更新原生验证的版本/哈希判定。
- 构建机需要：Python 3.12、.NET Framework 4.x 的 `csc.exe`（编译 Rawether 桥）、Npcap 驱动（运行期）。
- 工作区总览、历史归档与文档索引见上级目录的 `..\README.md`。