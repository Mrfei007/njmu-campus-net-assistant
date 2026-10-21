from __future__ import annotations

from .version import VERSION


PRODUCT_NAME = "NJMU校园网自动化连接程序"
PRODUCT_VERSION = VERSION
INTERNAL_NAME = "NJMUCampusNetAssistant"
EVENT_SOURCE = INTERNAL_NAME
TASK_PREFIX = "NJMUCampusNetAssistant-"
MONITOR_TASK_NAME = f"{TASK_PREFIX}Monitor"
WAKE_TASK_NAME = f"{TASK_PREFIX}Wake"
