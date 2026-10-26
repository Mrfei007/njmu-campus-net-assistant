# 第三方组件与许可证说明

本项目的自有代码采用 **MIT License**，完整文本见根目录 [`LICENSE`](LICENSE)。
MIT License **不改变**发布包内第三方组件各自的许可证；这些组件仍按下列条款分发。

## 运行时组件

| 组件 | 版本 | 许可证 | 说明 |
|---|---|---|---|
| PySide6 / shiboken6 | 6.11.1 | LGPL-3.0-only（上游另提供 GPL / 商业许可选项） | 版权归 The Qt Company 及贡献者所有；以动态库形式分发，遵循 LGPL 条款。 |
| Qt 运行库及插件（Virtual Keyboard 除外） | 6.11.1 | LGPL-3.0-only 及各内嵌第三方组件的条款 | 包含 Core、Gui、Widgets、Network、OpenGL、Qml / Quick、Svg、Pdf 等及其插件；不得将内嵌第三方组件统一视为 LGPL。见下方归属、许可与对应源码说明。 |
| Qt Virtual Keyboard（DLL 与输入插件） | 6.11.1 | GPL-3.0-only（上游另提供商业许可） | 随 Qt 插件一起分发，不属于 LGPL 组件；保留 GPL 全文及对应源码获取说明。项目自有代码的 MIT 许可不覆盖该组件。 |
| Python | 3.12.9 | PSF-2.0 及官方 Windows 发行版所列历史/第三方条款 | 完整原文见 `LICENSES/CPython-3.12.9-Windows-LICENSE.txt`，而非只有 PSF 条款摘要。 |
| OpenSSL | 3.0.15 | Apache-2.0 | Python Windows 运行时随附的 `libcrypto-3.dll` / `libssl-3.dll`；见对应 LICENSE 和 AUTHORS 原文。 |
| libffi | 3.4.4（DLL ABI 名为 libffi-8） | MIT | 版本依据 CPython 3.12.9 的官方构建依赖；版权与条款见 `LICENSES/libffi-3.4.4-LICENSE.txt`。 |
| websocket-client | 1.9.0 | Apache-2.0 | 用于与本机 Chrome / Edge 的调试接口（CDP）通信；许可证见 `LICENSES/websocket-client-LICENSE.txt`。 |
| PyInstaller | 6.21.0 | GPL-2.0-or-later，含 bootloader 例外；运行时 hooks 为 Apache-2.0 | 用于打包；发布程序包含其 bootloader、加载器及运行时 hooks。完整条款见 `LICENSES/PyInstaller-COPYING.txt`；Apache-2.0 全文另见 `LICENSES/websocket-client-LICENSE.txt`。 |
| Microsoft Visual C++ Runtime | 随 Python / PySide6 / Qt 提供 | Microsoft 可再分发组件条款 | 版权归 Microsoft Corporation 所有；不受本项目 MIT 许可覆盖。Python 官方 Windows 分发的附加条件保留在 `LICENSES/CPython-3.12.9-Windows-LICENSE.txt`，再分发者须另行遵守适用的 Microsoft 条款。 |

## 构建依赖

| 组件 | 版本 | 许可证 | 说明 |
|---|---|---|---|
| pywin32-ctypes | 当前维护环境为 0.2.3 | BSD-3-Clause | PyInstaller 的 Windows 构建依赖；版权归 Enthought, Inc. 所有，原始许可证见 `LICENSES/pywin32-ctypes-LICENSE.txt`。此行不是对旧发布包原始构建环境版本的断言。 |

## 不随项目分发的组件

| 组件 | 说明 |
|---|---|
| Npcap | 项目**不附带** Npcap 安装程序或驱动。用户从 [npcap.com](https://npcap.com/dist/npcap-1.90.exe) 自行下载并安装，须遵守 Nmap Software LLC 的 Npcap 许可证。 |
| 官方锐捷客户端 / W64N55.dll / PCASp50 | 不随项目分发。仅在用户本机已安装官方客户端时，可选地只读使用其驱动组件；相关软件仍受其各自许可证约束。 |

## 许可证文本

本仓库 [`LICENSES/`](LICENSES/) 目录包含主要第三方许可证文本：

- [LGPL-3.0.txt](LICENSES/LGPL-3.0.txt)
- [GPL-3.0.txt](LICENSES/GPL-3.0.txt)
- [PSF-2.0.txt](LICENSES/PSF-2.0.txt)
- [CPython-3.12.9-Windows-LICENSE.txt](LICENSES/CPython-3.12.9-Windows-LICENSE.txt)
- [OpenSSL-3.0.15-LICENSE.txt](LICENSES/OpenSSL-3.0.15-LICENSE.txt)
- [OpenSSL-3.0.15-AUTHORS.md](LICENSES/OpenSSL-3.0.15-AUTHORS.md)
- [libffi-3.4.4-LICENSE.txt](LICENSES/libffi-3.4.4-LICENSE.txt)
- [PyInstaller-COPYING.txt](LICENSES/PyInstaller-COPYING.txt)
- [websocket-client-LICENSE.txt](LICENSES/websocket-client-LICENSE.txt)
- [pywin32-ctypes-LICENSE.txt](LICENSES/pywin32-ctypes-LICENSE.txt)
- [Qt-6.11.1-NOTICES.txt](LICENSES/Qt-6.11.1-NOTICES.txt)：对应版本上游的版权、归属和许可正文集合，保留原始来源；包含跨平台/构建条目的保守超集，不代表每项都装入本程序。
- [Qt-6.11.1-Mesa-NOTICES.txt](LICENSES/Qt-6.11.1-Mesa-NOTICES.txt)：Qt 官方对 Windows 软件 OpenGL 库的版权及条款。
- [Qt-6.11.1-MODULE-COPYRIGHTS.txt](LICENSES/Qt-6.11.1-MODULE-COPYRIGHTS.txt)：Qt 模块自身及 PDFium 字体的原始版权声明。
- [THIRD-PARTY-SOURCES.md](LICENSES/THIRD-PARTY-SOURCES.md)：各组件的适用范围、同版本源码、构建源码入口及再分发说明。

## Qt / PySide6 的动态库与源码

发布包中的 Qt/PySide6 库以可替换的动态库形式提供。用户可以用兼容构建替换这些 DLL；项目不阻止这种替换，也不限制为调试修改后的第三方库而进行的必要逆向工程。Virtual Keyboard 按 GPL 单独说明，不能套用 LGPL 标签。

同版本源码及构建脚本入口见 [THIRD-PARTY-SOURCES.md](LICENSES/THIRD-PARTY-SOURCES.md)，其中明确列出 Qt / PySide6 6.11.1 和各随附组件的来源。Qt 内嵌的 PDFium、字体、图像、压缩库等仍受各自的原始许可证约束。

如果你再分发本项目的发布包，请同时保留本文件、原始版权声明和 `LICENSES/` 目录，并遵守各组件的 LGPL、GPL、Apache、BSD、MIT 及 Microsoft 等适用条款。