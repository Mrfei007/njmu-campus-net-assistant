# 第三方许可与对应源码

适用范围：1.3.1、1.4.3、1.5.9.2、1.6.4 发布包中共用的 Python 3.12.9 与 Qt / PySide6 6.11.1 运行库。项目自有代码采用 MIT；这不重新许可任何第三方库。

## Qt / PySide6 / shiboken6

版权归 The Qt Company Ltd. 及各原始贡献者所有，组件自身及 PDFium 字体的上游版权头另见 `Qt-6.11.1-MODULE-COPYRIGHTS.txt`。本项目没有修改这些随上游发行的 Qt / PySide6 DLL / PYD。发布包中的这些库以动态 DLL / PYD 形式提供；项目不限制用户替换、修改、调试这些第三方库。允许为调试修改后的第三方库而对本程序进行必要的逆向工程。

- Qt（除 Virtual Keyboard 外列出的运行模块）：按 LGPL-3.0-only 使用；内嵌第三方代码仍按自己的条款分发。
- PySide6 / shiboken6：按 LGPL-3.0-only 使用。
- **Qt Virtual Keyboard DLL 和输入插件：GPL-3.0-only，不是 LGPL。** 该组件作为 Qt 的第三方插件单独附带，其源码入口和 GPL 全文一并提供；本项目 MIT 许可不覆盖它。
- 完整 LGPL / GPL 文本：本目录 `LGPL-3.0.txt`、`GPL-3.0.txt`。
- 上游版本为 **v6.11.1**。可从以下官方仓库取得包含构建脚本的源码，在克隆后切换该标签；Qt 总仓库的子模块也应初始化到该标签记录的提交，而非取各仓库最新分支。

| 组件 | 对应版本源码 |
|---|---|
| Qt 总仓库（含子模块版本） | https://code.qt.io/cgit/qt/qt5.git/tree/?h=v6.11.1 |
| Qt Core / Gui / Widgets / Network / OpenGL | https://code.qt.io/cgit/qt/qtbase.git/tree/?h=v6.11.1 |
| Qt Qml / Quick | https://code.qt.io/cgit/qt/qtdeclarative.git/tree/?h=v6.11.1 |
| Qt Svg | https://code.qt.io/cgit/qt/qtsvg.git/tree/?h=v6.11.1 |
| Qt 图像格式插件 | https://code.qt.io/cgit/qt/qtimageformats.git/tree/?h=v6.11.1 |
| Qt PDF（位于 qtwebengine 源码树） | https://code.qt.io/cgit/qt/qtwebengine.git/tree/?h=v6.11.1 |
| Qt Virtual Keyboard | [完整 6.11.1 源码与构建脚本归档](https://download.qt.io/archive/qt/6.11/6.11.1/submodules/qtvirtualkeyboard-everywhere-src-6.11.1.tar.xz)；[同版本 Git 树](https://code.qt.io/cgit/qt/qtvirtualkeyboard.git/tree/?h=v6.11.1) |
| PySide6 / shiboken6 | https://code.qt.io/cgit/pyside/pyside-setup.git/tree/?h=v6.11.1 |

Qt 源码也可从官方归档入口取得：https://download.qt.io/archive/qt/6.11/6.11.1/ 。这些源码与相应库可独立获取，不需要下载本项目的运行 ZIP。

### 内嵌第三方归属

- `Qt-6.11.1-NOTICES.txt` 保留从上述版本源码取得的许可、版权和 `qt_attribution.json` 原文，以及 PDFium / Chromium 子模块中的相关原文；每段均标明来源 URL 与原文件 SHA-256。
- `Qt-6.11.1-Mesa-NOTICES.txt` 为 Qt 6.11.1 官方对 Windows `opengl32sw.dll`（Mesa llvmpipe）的版权和许可说明，保留其 MIT / Boost 条款。
- 归属材料是上游文本的保守超集，含跨平台或只在构建时使用的条目；**列入文本不表示这些组件全部在本 Windows 程序中运行**，也不把不同组件统一改为 LGPL。
- 主要涉及 PDFium、FreeType、HarfBuzz、libjpeg-turbo、libpng、zlib、TIFF、WebP 等。PDFium 对应 Qt 6.11.1 锁定的 `qtwebengine-chromium` 提交 `58c11ad487f8a237cf0ac71cc3e818b52db150df`，其源码入口为 https://github.com/qt/qtwebengine-chromium/tree/58c11ad487f8a237cf0ac71cc3e818b52db150df/chromium/third_party/pdfium 。

### 使用致谢

This software is based in part on the work of the Independent JPEG Group.

本产品使用 FreeType 字体引擎（包括 Qt 中的字体栅格化代码），相关版权归 The FreeType Project 及贡献者所有；也使用 Qt 中基于 Imlib2 的图像平滑缩放代码。它们的原始版权、许可条件和免责声明保留在 `Qt-6.11.1-NOTICES.txt`。PDFium 字体中的原始代码版权包括 Foxit Software Inc.；相应声明保留在 `Qt-6.11.1-MODULE-COPYRIGHTS.txt`。

## Python 和随附库

- CPython 3.12.9： https://www.python.org/ftp/python/3.12.9/Python-3.12.9.tar.xz 。
- `CPython-3.12.9-Windows-LICENSE.txt` 是官方 Windows amd64 嵌入式发行包中的完整原文，保留 PSF、历史授权、Windows 附加条件及发行包列出的随附库条款，不仅是 PSF 简表。
- OpenSSL 3.0.15： https://github.com/openssl/openssl/tree/openssl-3.0.15 ，许可和作者声明见 `OpenSSL-3.0.15-LICENSE.txt` / `OpenSSL-3.0.15-AUTHORS.md`。
- libffi 3.4.4： https://github.com/libffi/libffi/tree/v3.4.4 ，原始版权与条款见 `libffi-3.4.4-LICENSE.txt`。版本依据 CPython 3.12.9 官方构建依赖，而不是 DLL 文件名中的 ABI 数字 8。
- Microsoft C / C++ 运行库仍按 Microsoft 条款分发，不受本项目 MIT 许可覆盖。Python 官方 Windows 许可中的 Microsoft Distributable Code 附加条件同样保留；再次分发前须遵守适用于自己的 Microsoft 授权和分发条件。

## WebSocket 与打包器

- websocket-client 1.9.0： https://github.com/websocket-client/websocket-client/tree/v1.9.0 ，Apache-2.0 全文见 `websocket-client-LICENSE.txt`。
- PyInstaller： https://github.com/pyinstaller/pyinstaller/tree/v6.21.0 ，条款见 `PyInstaller-COPYING.txt`，包括 bootloader 例外及运行时 hooks 的 Apache-2.0 条款。旧包中相关加载器和 hooks 与该版本逐项核对一致；这不是重新构建旧程序。
- pywin32-ctypes：当前维护构建环境使用 0.2.3，BSD-3-Clause 全文见 `pywin32-ctypes-LICENSE.txt`。它是构建依赖，不据此断言旧发布包的原始构建环境版本。

再分发时请保留本说明、原版权声明及适用许可证，并提供适用许可证要求的对应源码获取方式。上游链接指向的独立组件不受本项目 MIT 许可替代。
