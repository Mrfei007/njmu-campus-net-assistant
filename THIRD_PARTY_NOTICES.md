# 第三方组件与许可证说明

本项目的自有代码采用 **MIT License**，完整文本见根目录 [`LICENSE`](LICENSE)。
MIT License **不改变**发布包内第三方组件各自的许可证；这些组件仍按下列条款分发。

## 运行时组件

| 组件 | 版本 | 许可证 | 说明 |
|---|---|---|---|
| PySide6 / Qt / shiboken6 | 6.11.1 | LGPL-3.0-only（也提供 GPL-2.0/GPL-3.0/商业许可） | 版权归 The Qt Company 及 Qt/PySide6 贡献者所有。以动态 DLL 形式随发布包分发。源码与许可信息见 [pyside.org](https://pyside.org) 和 [Qt 许可说明](https://www.qt.io/licensing/open-source-lgpl-obligations)。 |
| Python | 3.12.x | PSF-2.0 | 发布包内的 Python 运行时来自官方发行版。 |
| websocket-client | 1.9.0 | BSD-3-Clause | 仅用于与校园网认证服务通信。 |
| PyInstaller | 6.21.0 | GPL-2.0-or-later，含 bootloader 例外 | 仅使用其打包后的 bootloader 和运行时；不是项目自有代码。 |
| Microsoft Visual C++ Runtime | 随 PySide6/Qt 提供 | Microsoft 可再分发组件条款 | 由 Qt/PySide6 官方 Windows 包附带。 |

## 不随项目分发的组件

| 组件 | 说明 |
|---|---|
| Npcap | 项目**不附带** Npcap 安装程序或驱动。用户从 [npcap.com](https://npcap.com/dist/npcap-1.90.exe) 自行下载并安装，须遵守 Nmap Software LLC 的 Npcap 许可证。 |
| 官方锐捷客户端 / W64N55.dll / PCASp50 | 不随项目分发。仅在用户本机已安装官方客户端时，可选地只读使用其驱动组件；相关软件仍受其各自许可证约束。 |

## 许可证文本

本仓库 [`LICENSES/`](LICENSES/) 目录包含主要第三方许可证文本：

- [LGPL-3.0.txt](LICENSES/LGPL-3.0.txt)
- [GPL-3.0.txt](LICENSES/GPL-3.0.txt)
- [BSD-3-Clause.txt](LICENSES/BSD-3-Clause.txt)
- [PSF-2.0.txt](LICENSES/PSF-2.0.txt)
- [PyInstaller-COPYING.txt](LICENSES/PyInstaller-COPYING.txt)
- [websocket-client-LICENSE.txt](LICENSES/websocket-client-LICENSE.txt)
- [pywin32-ctypes-LICENSE.txt](LICENSES/pywin32-ctypes-LICENSE.txt)

如果某个组件的许可证文本与上游发布版本不一致，以该组件官方发行包中的文本为准。

## Qt / PySide6 的 LGPL 说明

发布包中的 Qt/PySide6 库以可替换的动态库形式提供。用户可以用兼容的 LGPL 构建替换这些 DLL；项目不阻止这种替换，也不对这些第三方库的修改施加额外限制。Qt/PySide6 的源码可从其官方仓库获取：

- https://code.qt.io/cgit/pyside/pyside-setup.git/
- https://code.qt.io/cgit/qt/qtbase.git/

如果你再分发本项目的发布包，请同时保留本文件和 `LICENSES/` 目录，并遵守 Qt/PySide6 的 LGPL 条款。