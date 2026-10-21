# NJMU 校园网自动化连接程序 · 单源仓库

本仓库自 **1.5.9.2** 起是产品源码的**唯一真源（single source of truth）**。
之前 1.5.2–1.5.9.1 的代码只存在于 `build_stage\work`（构建暂存目录）与各发布 zip 中，
历史代码没有版本管理；从本提交开始纳入 git，之后任何改动先提交再发版。

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
    version.py                  版本号唯一来源
  build_release.ps1       从本仓库出发布包
  CHANGELOG.md            版本变更记录
  README.md               本文件
```

依赖（PySide6 / shiboken6 / PyInstaller）体积约 650 MB，**不进版本库**，放在仓库外：

```
<工作区>\build_stage\work\campus-net-assistant\vendor
```

## 出包

```powershell
pwsh .\build_release.ps1                 # 构建并把 zip + sha256 复制到工作区根目录
pwsh .\build_release.ps1 -NoCopy         # 只构建，不复制（试构建用）
pwsh .\build_release.ps1 -Vendor 'D:\other\vendor'
```

脚本会：读 `app\src\campus_net_assistant\version.py` 的版本号 → 调 `build_local.py`
（PyInstaller onedir + Rawether 桥编译 + GUI 冒烟检查 + 桥自检）→ 校验 sha256 →
复制到工作区根目录 → 在 `release-records\<version>.json` 留一条构建记录。

`build_stage\build_all.ps1` 与 `product\` 下的同名脚本是旧的"基线 + 补丁脚本"流水线，
**已废弃**：它们会从 `旧工作区` 的 1.5 基线重新复制源码并覆盖，等于回退代码。

## 版本规则

- `version.py` 是唯一来源，`build_local.py` 会校验格式并写进 exe 资源。
- 1.5.x：补丁号递增（1.5.9.1、1.5.9.2…），只做点修。
- **1.6**：保活会话身份与互斥体的根治版本（见 `analysis\1.6-根治方案-保活进程身份与会话互斥.md`）。
  该版本会重编 `NpcapBridge.exe`，桥哈希变化会导致每台机器需重新做一次原生认证验证。

## 注意

- 不要在 `build_stage\` 或 `product\` 里构建：这些目录对受限进程不可写，且其源码树已过时。
- `NpcapBridge.exe` 自 1.5.8 起字节不变；若重编它，必须同步更新原生验证的版本/哈希判定。
- 构建机需要：Python 3.12、.NET Framework 4.x 的 `csc.exe`（编译 Rawether 桥）、Npcap 驱动（运行期）。