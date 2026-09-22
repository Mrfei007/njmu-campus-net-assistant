from __future__ import annotations

import ctypes
import getpass
import os
from ctypes import wintypes


from .product import INTERNAL_NAME, PRODUCT_NAME


TARGET = f"{INTERNAL_NAME}/NJMU"
ERROR_NOT_FOUND = 1168
ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True) if os.name == "nt" else None


class CREDENTIAL_ATTRIBUTE(ctypes.Structure):
    _fields_ = [("Keyword", wintypes.LPWSTR), ("Flags", wintypes.DWORD), ("ValueSize", wintypes.DWORD), ("Value", ctypes.POINTER(ctypes.c_ubyte))]


class CREDENTIAL(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR), ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD), ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.POINTER(CREDENTIAL_ATTRIBUTE)), ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]


def save(username: str, password: str) -> None:
    if os.name != "nt":
        raise RuntimeError("Windows Credential Manager is only available on Windows")
    blob = password.encode("utf-16-le")
    buffer = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
    credential = CREDENTIAL(0, 1, TARGET, PRODUCT_NAME, wintypes.FILETIME(), len(blob), buffer, 2, 0, None, None, username)
    if not ADVAPI32.CredWriteW(ctypes.byref(credential), 0):
        raise ctypes.WinError(ctypes.get_last_error())


def load() -> tuple[str, str]:
    if os.name != "nt":
        raise RuntimeError("Windows Credential Manager is only available on Windows")
    pointer = ctypes.POINTER(CREDENTIAL)()
    if not ADVAPI32.CredReadW(TARGET, 1, 0, ctypes.byref(pointer)):
        if ctypes.get_last_error() == ERROR_NOT_FOUND:
            raise RuntimeError("No campus credentials configured")
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        item = pointer.contents
        password = ctypes.string_at(item.CredentialBlob, item.CredentialBlobSize).decode("utf-16-le")
        return item.UserName or getpass.getuser(), password
    finally:
        ADVAPI32.CredFree(pointer)


def load_username() -> str:
    """Read only the account name, without decoding the credential secret."""
    if os.name != "nt":
        raise RuntimeError("Windows Credential Manager is only available on Windows")
    pointer = ctypes.POINTER(CREDENTIAL)()
    if not ADVAPI32.CredReadW(TARGET, 1, 0, ctypes.byref(pointer)):
        if ctypes.get_last_error() == ERROR_NOT_FOUND:
            raise RuntimeError("No campus credentials configured")
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        username = pointer.contents.UserName or getpass.getuser()
        if not username:
            raise RuntimeError("No campus username configured")
        return username
    finally:
        ADVAPI32.CredFree(pointer)
