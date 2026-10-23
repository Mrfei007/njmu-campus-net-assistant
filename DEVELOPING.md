# 开发与发布

产品使用说明见 [README.md](README.md)。本文件面向改代码、出包和发版。

## 单源仓库

本仓库自 **1.5.9.2** 起是产品源码的**唯一真源（single source of truth）**。
1.5.2–1.5.9.1 的代码只存在于当时的构建暂存目录与发布 zip 中，没有纳入版本管理；
从 1.5.9.2 起纳入 git，之后任何改动先提交再发版。

版本号唯一来源：`app/src/campus_net_assistant/version.py`。

## 目录结构

```
repo/
  app/                    产品源码树（构建的根目录）
    src/campus_net_assistant/   Python 包（含 native/bin/NpcapBridge.exe、RawetherBridge.exe）
    tests/                      隔离回归测试
    tools/                      辅助脚本（桥接构建、发布校验等）
    build_local.py              PyInstaller onedir 打包 + 校验 + 出 zip
    version_info.txt            exe 版本资源模板
    使用说明.txt                随包说明（构建时替换 {{VERSION}}）
  releases/<version>.json   发布记录索引（**进版本库**，每次发版一条）
  build_release.ps1         从本仓库出发布包（zip + sha256）
  publish_release.ps1       把已构建的发布包上传到 GitHub Releases
  CHANGELOG.md              版本变更记录（发版说明的正文来源）
  DEVELOPING.md             本文件
```

依赖（PySide6 / shiboken6 / PyInstaller）体积约 650 MB，**不进版本库**。构建时通过
`-Vendor` 指向一个包含这些依赖的目录；也可以设置环境变量 `NJMU_DEPENDENCY_VENDOR`，
再直接运行 `app/build_local.py`。公开仓库不预设任何机器上的私有目录。

## 出包

```powershell
pwsh ./build_release.ps1                 # 构建，并把 zip + sha256 放到发布目录
pwsh ./build_release.ps1 -NoCopy         # 只构建，不复制（试构建用）
pwsh ./build_release.ps1 -Vendor '<自定义 vendor 目录>'
pwsh ./build_release.ps1 -RebuildBridge  # 强制重编 native/bin/NpcapBridge.exe
```

`-Vendor` 指向包含 PyInstaller / PySide6 / shiboken6 的目录；未指定时脚本读取
`NJMU_DEPENDENCY_VENDOR`，再退回到仓库同级的 `campus-net-assistant/vendor`。

脚本流程：读 `version.py` → 调 `build_local.py`（PyInstaller onedir + Rawether 桥编译 +
GUI 冒烟检查 + 桥自检）→ 校验 sha256 → 复制发布包 → 在 `releases/<version>.json` 留记录。

## 发布包放置规则（唯一约定）

| 内容 | 位置 | 是否进 git |
|---|---|---|
| 发布包本体 zip + `.sha256.txt` | `<发布目录>/releases/<主.次>.x/`（如 `1.6.x`） | 否 |
| 发布记录索引 | `repo/releases/<version>.json` | **是** |

即：**二进制放在发布目录、索引进仓库**。`<主.次>.x` 由版本号自动推出（`1.6.3` → `1.6.x`），
不需要手工建目录。

## 上传 GitHub Releases

```powershell
pwsh ./publish_release.ps1 -DryRun    # 只打印将要执行的命令，不改变任何东西
pwsh ./publish_release.ps1            # 打标签 v<version>，上传 zip + sha256，正文取 CHANGELOG 对应小节
pwsh ./publish_release.ps1 -Draft     # 传成 draft，先人工看一眼
```

脚本会先核对 zip 的 sha256 与 `releases/<version>.json` 是否一致，不一致直接拒绝发布。
tag 名固定为 `v<version>`（与已有 `v1.5.9.2`…`v1.6.3` 一致）。

**资产名必须是 ASCII**：GitHub 会丢弃资产名里的非 ASCII 字符（中文名会被压成 `NJMU.-…`）。
脚本会把 zip 复制成 `NJMU-CampusNet-Assistant-<version>-Windows-x64.zip` 再上传，
sidecar 内容也按该名生成，下载后可直接校验。本地 `releases/` 文件名仍保留中文。

凭据按以下顺序自动解析，任一可用即可（脚本会打印实际用的来源）：

1. `gh auth login`（交互登录，要求令牌带 `repo` + `read:org`）
2. 环境变量 `GH_TOKEN` / `GITHUB_TOKEN`
3. git 凭据管理器里已存的本仓库推送令牌（只需 `repo`，不需 `read:org`）

`gh` 只在登录校验时要求 `read:org`，用 `GH_TOKEN` 调 Release 接口不受此限。

没有 `gh` 时按脚本打印的浏览器方式手工上传即可，命令和资产路径都会列出来。

## 版本规则

- `version.py` 是唯一来源，`build_local.py` 会校验格式并写进 exe 资源。
- **`CHANGELOG.md` 只列已发布的版本。** 开发中的条目先留在本地，发布时按"最新在最前"的顺序
  并入 `CHANGELOG.md`，不要提交未发布内容。
- 1.5.x：补丁号递增（1.5.9.1、1.5.9.2…），只做点修。
- **1.6**：保活会话身份与互斥体的根治版本。该版本重编 `NpcapBridge.exe`
  （`704b9dc0…` → `d5a55d3f…`），桥哈希变化会导致每台机器需重新做一次原生认证验证。
- 1.6.1 / 1.6.2 / 1.6.3：断网判定与恢复时机优化，1.6.3 修复了 1.6.2 的恢复延迟回归。

## 注意

- 构建依赖、发布 zip 和本机运行状态都不进版本库；提交前用 `git status` / `git diff` 检查是否误带。
- `NpcapBridge.exe` 自 1.5.8 起字节不变；若重编它，必须同步更新原生验证的版本/哈希判定。
- 构建机需要：Python 3.12、.NET Framework 4.x 的 `csc.exe`（编译 Rawether 桥）、Npcap 驱动（运行期）。
- Npcap 安装程序不随仓库或发布包分发；包内只放 `Npcap下载说明.txt`，让用户从官网下载。