from __future__ import annotations

import contextlib
import ctypes
import os
from collections.abc import Iterator


MUTEX_NAME = r"Local\NJMUCampusNetAssistant-Recovery"
MONITOR_MUTEX_NAME = r"Local\NJMUCampusNetAssistant-Monitor"
WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080


@contextlib.contextmanager
def _acquire_mutex(name: str, timeout_ms: int = 0) -> Iterator[bool]:
    if os.name != "nt":
        yield True
        return
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateMutexW(None, False, name)
    if not handle:
        yield False
        return
    acquired = False
    try:
        result = kernel32.WaitForSingleObject(handle, max(0, int(timeout_ms)))
        acquired = result in {WAIT_OBJECT_0, WAIT_ABANDONED}
        yield acquired
    finally:
        if acquired:
            kernel32.ReleaseMutex(handle)
        kernel32.CloseHandle(handle)


def acquire_recovery_lock(timeout_ms: int = 0) -> contextlib.AbstractContextManager[bool]:
    """Prevent wake recovery, manual login and Monitor from recovering together."""
    return _acquire_mutex(MUTEX_NAME, timeout_ms)


def acquire_monitor_lock() -> contextlib.AbstractContextManager[bool]:
    """Allow only one long-running monitor process for the current user session."""
    return _acquire_mutex(MONITOR_MUTEX_NAME)
