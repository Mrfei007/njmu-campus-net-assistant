# 变更记录

本文件从 1.5.9.2 起维护。1.5.2–1.5.9.1 的条目依据发布包与 PYZ 模块差分回溯，
标注了证据来源；更早版本（1.5、1.4.x）没有留存可核对的记录。

## 1.6 — 2026-10-21

**根治：保活进程身份与会话互斥（1.5.9.2 只是补丁）**

1.5.9.2 用"心跳新鲜优先 + 300 秒容差"绕开了误判，但根因仍在：桥接写的
`process_started_at` 不是进程创建时间；会话互斥体以 `bInitialOwner=False` 创建却被当成
"已持有"，导致"进程可能还活着"的保护分支是死代码。1.6 把判定依据换成不可伪造的事实。

改动（主程序与桥接同时升级，状态文件 schema 1 → 2）：

- `npcap_bridge.py`：真实进程创建时间（`GetProcessTimes`）、`keepalive_started_at`、
  单调 `heartbeat_seq`、桥自身 SHA-256 与映像路径写入状态文件；`CreateMutexW(..., True, ...)`
  真正请求会话所有权，`ERROR_ALREADY_EXISTS` 时用 `WaitForSingleObject(0)` 区分
  "另一个会话持有"（退出码 78，不写状态文件）与"前任已死"（接管并记录 `takeover_from`）。
- `native/RawetherBridge.cs`：同一套 schema v2 字段（`BridgeSchemaVersion = 2`、
  `process_created_at`、`keepalive_started_at`、`heartbeat_seq`），互斥体逻辑原本已正确，未改。
- `keepalive_status.py`：三态模型（`running` / `exited` / `unknown`）+ `verdict_basis`
  标明结论来源（`heartbeat`、`process-mutex`、`absent`、`pid-mismatch`、
  `mutex-held-elsewhere`、`legacy-v1` 等）。`unknown` 永不升级为 `exited`；只有
  "进程不在 + 互斥体可获取 + 记录过期" 才判 `absent`。schema v1 记录按 1.5.9.2 原样判定
  （`verdict_basis="legacy-v1"`），未升级桥的机器行为不变。
- `controller.py`：看门狗只在"确定没有会话"时动作，且要求连续 2 次观测（约 4 分钟）；
  重建前再查一次互斥体，仍被持有则跳过；`unknown` 只限频告警（1 条/小时），不再杀进程重连。
  "按请求停止"的会话不再被强行拉起。
- `component_compat.py`（新增）：识别桥比程序旧、程序比桥旧、状态记录来自其它安装目录等
  版本衔接问题，并在状态文案里给出可执行提示。
- 移除 `server_receipt`（"服务端回执"概念没有任何消费方，改为报告最近一次发送时间与连续
  成功次数）。
- `version.py` → 1.6；`使用说明.txt` 说明三态、连续两次确认与"成对升级"。

验证：判定矩阵 23/23（新 `tests/test_keepalive_v2_contract.py`）；跨进程互斥体协议 4/4
（新 `tests/test_keepalive_mutex_ownership.py`：第三方持有→拒绝且不改状态文件、持有者被杀死→
接管、空闲→直接获取、桥退出码 78）；遥测 7/7；`test_workstation_monitor` 56/56（原先 1 例
因 1.5.9.2 语义变化而失效的用例已按新契约改写）；`native_wired` 24/24、
`native_backend_service` 10/10、`ui_15` 11/11、`startup` 16/16；打包内置的
`--gui-smoke-check` 与 Rawether 桥自检均通过；`RawetherBridge.cs` 单独 csc 编译 + 自检通过。
`test_keepalive_contract` 的失败与 `startup_policy` 的 2 个错误在 1.5.9.2 基线上同样存在
（本机 GBK 编码 / 配置迁移），与本次改动无关。

产物：`NJMU校园网自动化连接程序-1.6-Windows-x64.zip`，53,956,039 字节，
SHA-256 `3886142bf63df6e9bb05b3fea6d911d020938f8a34f377f4c1c266df5556615c`，
build id `20261021-173032`。桥 `NpcapBridge.exe` SHA-256
`94490f2a29207e2985df95f86c130ad5838f6c907eb5944c461008b7bbd889e2`（7,522,716 字节，
由 `tools\build_npcap_bridge.py` 重编），`RawetherBridge.exe` SHA-256
`f5d57437b231baf893079c0a61610076f0d927ce8b1ef79631e1a0b04849b6ea`。

## 1.5.9.2 — 2026-10-21

**修复：工位有线"后台保活已退出"误报 + 每约 10 分钟断网重连**

根因：保活状态文件里 `process_started_at` 是桥接"开始保活"的时刻，比进程真实创建时间
晚约 2 秒（PyInstaller onefile 自解包 + Python 初始化 + wpcap 加载 + 网卡枚举）。旧
`_process_state()` 用 1 秒容差比对，必然判 `exited`；会话互斥体从未真正持有，导致
"进程可能还活着"的保护分支是死代码，误判直接升级为 `exited`；1.5.7 新增的看门狗据此
每 10 分钟杀掉健康桥接并重新认证 → 用户看到"已退出"和"断网重连"。

改动（只动读取端判定，桥接未重编）：

- `keepalive_status.py`：心跳新鲜（90 秒内成功发送）优先判 `running/recent-send-success`；
  `_process_state()` 拆分映像名与创建时间校验，创建时间容差 1 s → 300 s（仅用于防 PID 复用）。
- `controller.py`：新增 `_keepalive_heartbeat_is_fresh()`，记录新鲜且发送成功时不重建会话。
- `workstation_monitor.py`："已退出"文案在无退出原因时给出已成功发送次数，区分真退出与误判。
- `version.py` → 1.5.9.2；`使用说明.txt` 补充判定规则。

验证：判定自测 8/8；包内 240 个模块与 1.5.9.1 差分仅 4 个变化；`NpcapBridge.exe`
SHA-256 仍为 `704b9dc0…`（未重编）；GUI 冒烟检查通过。
产物 SHA-256 `8fa68f939c65b436dbcc8d923b340bb9aa40f60d3e15016646ca7f705f265f15`。

## 1.5.9.1 — 2026-10-20

版本号提升（PYZ 差分显示 1.5.9 → 1.5.9.1 仅 `gui`、`version` 两个模块变化）。

## 1.5.9 — 2026-10-20

界面布局调整（PYZ 差分显示 1.5.8 → 1.5.9 仅 `gui`、`ui_layout`、`version` 变化）。
保活与认证逻辑未改动。

## 1.5.8 — 2026-10-20

记录缺失（当时无版本管理）。可确认的事实：`NpcapBridge.exe` 自本版起与后续版本字节一致。

## 1.5.7 — 2026-10-20

新增保活看门狗：检测到保活停止时限频自动重建（默认 10 分钟一次，失败退避至 1 小时）。
注意：它建立在未修复的"假退出"判定之上，因此 1.5.7–1.5.9.1 在工位有线环境下会把
健康会话误杀重建，1.5.9.2 修复了判定并加了护栏。

## 1.5.2 – 1.5.6 — 2026-10-19

无逐条记录。各版发布 zip 与 sha256 归档在工作区根目录；1.5.6 是用户升级前的在用版本
（无看门狗常量）。