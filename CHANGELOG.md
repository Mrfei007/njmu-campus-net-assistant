# 变更记录

本文件从 1.5.9.2 起维护。1.5.2–1.5.9.1 的条目依据发布包与 PYZ 模块差分回溯，
标注了证据来源；更早版本（1.5、1.4.x）没有留存可核对的记录。

## 1.6.3 — 2026-10-21

**修 1.6.2 引入的回归：链路复通后没有立即恢复**

1.6.2 现场实测：21:53:19 拔线，3 秒内判定断网（轮询生效）；21:54:23 插回网线，直到
21:56:38 才开始恢复，21:56:56 成功——**插回后白等 2 分 15 秒**。

根因：`confirmed_failure` 只在"第二次探测也失败且同一块网卡"时才置位
（`_monitor_probe` 末尾那段）。1.6.2 为了省 15 秒跳过了第二次探测，却没补上确认标记，
于是监测每轮都走"原因待确认"分支：不累计失败、不恢复。而 `_bridge_link_down_fresh()`
有 3 分钟窗口，窗口内每轮都短路，直到 21:56:19 窗口过期才做第二次探测——
时间点与日志完全吻合。

- `_monitor_probe()` 新增 `allow_link_down_shortcut` 参数：只有监测循环正处于"断链事件"
  （`link_down_episode`）时才允许短路；短路时把首个观测标记为已确认故障
  （`confirmed_failure=True`、`recovery_allowed=True`，提示改为"链路恢复后联网探测仍
  失败，原生认证会话需要重建"），同一轮即进入恢复判定。
- 短路不再受 3 分钟窗口影响正常监测：恢复成功后链路事件结束，偶发丢包不会被当作断链。
- 预期：插回网线 → 下一轮（≤15 秒等待 + 约 15 秒探测）即恢复，整体约 40 秒。

新增 3 条测试（累计 21 条）：短路补确认标记、非断链事件时仍做第二次探测、
循环级"链路就绪后第一轮即恢复"。

产物：`NJMU校园网自动化连接程序-1.6.3-Windows-x64.zip`，53,960,316 字节，
SHA-256 `da05944d2652041af3a5a6fe29e9e2cf54307df51a913e9efb8be7cca6924754`，
build id `20261021-221242`。桥 `NpcapBridge.exe` 未改动，仍为
`d5a55d3f76ab7f1bca746e343fad142bbf9e47b1d222742a776a5dadb7eedf84`。

## 1.6.2 — 2026-10-21

**把"发现断网"的延迟真正压下来（1.6.1 现场实测后修正）**

1.6.1 现场拔网线：桥在 20:41:59 写入 `link-down`，但判定离线要等到 20:43:18（**79 秒**），
恢复完成 20:43:42。根因是 1.6.1 的快速探测只在"某一轮已经看到 link-down 记录"时才生效，
而桥断链的时刻常落在两轮之间的 120 秒等待里，那一轮根本没机会看到记录。

- **等待期间轮询**：新增 `_wait_for_next_probe()`，把常规等待切成 `LINK_DOWN_POLL_SECONDS`
  （5 秒）一段，每段只读一次状态文件 JSON（不探测进程）；一旦记录里出现新的
  `exit_reason="link-down"`，立即结束等待、马上开始下一轮探测，并记
  `monitor-probe-accelerated`（含 `skipped_seconds`）。
- **省掉第二次确认探测**：`_monitor_probe()` 在第一次探测失败后，若桥在 3 分钟内刚报过
  `link-down`，直接跳过第二次探测（沿用 `probe_attempts=2` 的计数语义，事件里
  `second_probe_source="bridge-link-down"`），去掉约 15 秒。
- 预期：拔网线 → 判定离线从 ~79 秒缩短到 ~5–20 秒，恢复完成相应提前约 60 秒。

新增 6 条测试（累计 18 条）：标记解析、新鲜窗口、等待期提前唤醒、无信号走满时间、
唤醒信号立即返回、桥报 link-down 时跳过确认探测。

产物：`NJMU校园网自动化连接程序-1.6.2-Windows-x64.zip`，53,959,743 字节，
SHA-256 `8cbb155dcc877f3976c7be2e43c44d96d4e9b4125eddbe83ae9b40f298552300`，
build id `20261021-205045`。桥 `NpcapBridge.exe` 未改动，仍为
`d5a55d3f76ab7f1bca746e343fad142bbf9e47b1d222742a776a5dadb7eedf84`；仍属"成对升级"，
主程序版本变化同样需要重新做一次原生认证验证。

## 1.6.1 — 2026-10-21

**断网发现更快、恢复时机更准（1.6 现场拔插网线实测后的两项优化）**

1.6 实测：拔掉网线后桥在 19:08:23 就记录了 `link-down` 并干净退出，但监测按 2 分钟周期
直到 19:09:52 才判定离线（89 秒延迟），随后 18 秒完成恢复。本次把"发现"和"恢复"分开：

- **快速发现**：监测每轮都会读保活记录，一旦看到 `exit_reason="link-down"`（记录 5 分钟内）
  或本机 `ethernet_ready=False`，本轮等待从 `monitor_interval_seconds`（120s）缩短到
  `LINK_DOWN_FAST_PROBE_SECONDS`（15s），并在进入/退出该状态时各记一条事件
  （`monitor-link-down-detected` / `monitor-link-down-cleared`）。
- **分阶段恢复**：物理链路/地址尚未就绪时只探测、不发起认证恢复，状态写
  `link-down-waiting`（"网线或链路尚未就绪，正在快速探测等待网络恢复；断链期间不会反复发起
  认证"），并记 `monitor-recovery-deferred-link-down`。链路一就绪即按原有流程取恢复锁 →
  停止旧会话 → 原生认证 → 真实联网验证，避免网线还没插好就白跑一遍注销/登录。
- **文案**：`unknown` 原因 `no-successful-send` 从通用"后台保活状态未知"改为
  "后台保活近期没有成功发送，链路可能已断（正在确认）"；`exit_reason=link-down` 的退出本就
  映射为"链路断开后退出"。
- 新增 `app/tests/test_link_down_detection.py`（12 条）：信号矩阵（记录新鲜/过期/其它退出
  原因、有无链路、无观测）、"链路未就绪跳过恢复"与"链路就绪仍恢复"的循环级验证，以及两条
  文案断言。

未改动的判定契约：`unknown` 仍不会升级为 `exited`，看门狗仍只在"确定没有会话"时动作。

产物：`NJMU校园网自动化连接程序-1.6.1-Windows-x64.zip`，53,958,708 字节，
SHA-256 `1b1f6574b4dbaa34169e3629d58de0236dcae8255ae326f11ba5130be31eb8b3`，
build id `20261021-193531`。桥 `NpcapBridge.exe` 未改动，仍为
`d5a55d3f76ab7f1bca746e343fad142bbf9e47b1d222742a776a5dadb7eedf84`（因此升级到 1.6.1
不需要重新验证桥，但主程序版本号变化同样会让"原生认证检查并验证"按钮再次出现，仍需验证一次）。
`RawetherBridge.exe` 每次构建重新编译，哈希为
`c2ec591edf7ba41a0220693bfd116c0f58bc3b28c46f664f5f7eb68044fd9ed0`。

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

产物：`NJMU校园网自动化连接程序-1.6-Windows-x64.zip`，53,955,927 字节，
SHA-256 `a2abc9048daf7e38bf04a445fb9ecb3243780f54a3ad730fd950060bb3f68fda`，
build id `20261021-181903`。桥 `NpcapBridge.exe` SHA-256
`d5a55d3f76ab7f1bca746e343fad142bbf9e47b1d222742a776a5dadb7eedf84`（7,522,795 字节，
由 `tools\build_npcap_bridge.py` 重编），`RawetherBridge.exe` SHA-256
`f5d57437b231baf893079c0a61610076f0d927ce8b1ef79631e1a0b04849b6ea`。

**同日补修（都发生在发布之前，已含在上面的产物里）**

- 桥端 `self_sha256()` 曾在整理导入时漏掉模块级 `hashlib`，构造 `Telemetry` 会抛
  `NameError`（构建期的 `selftest` 不覆盖遥测，所以没被拦住；由遥测单测捕获）。已补顶层
  `import hashlib` 并重编桥。`tools/build_npcap_bridge.py` 现在只在"环境确实拦截
  --onefile 自解包"时才跳过自检（旧桥同样失败，已实测对照），其它失败照旧阻断构建。
- C# 契约测试恢复可运行：`Assembly.Load(File.ReadAllBytes(path))` 代替 `LoadFile`
  （该机器把卷当作"非本机位置"，`LoadFile` 抛 `NotSupportedException`）；子进程输出按
  UTF-8 解码（原先按 GBK，中文 stderr 直接 `UnicodeDecodeError`，真实原因被吞）。
  现在 89 条检查全部通过，覆盖重试次数/间隔、非重试错误码、停止时机、回显序列推进。
- 顺带在目标机上验证了混装路径：1.5.x 旧桥实跑时，1.6 读取端给出
  `state=running / verdict_basis=legacy-v1`，看门狗不会动它。

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
产物 SHA-256 `cd61ace6a90a696b0fab85b06359d727d86bda6c5c66c61278180e50198b7ea5`。
2026-10-22 重新打包：包内新增 `tools\npcap-1.89.exe`（Nmap Software LLC 官方签名版 Npcap 1.89），
并同步更新使用说明与版本信息；程序文件本身未改动（原包 SHA-256 `8fa68f93…`）。

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