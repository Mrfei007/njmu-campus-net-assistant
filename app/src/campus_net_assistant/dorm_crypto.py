"""Offline password transform observed in the NJMU dorm SSO page.

This module does not submit credentials or choose an operator.  The caller must
obtain the per-page ``login-croypto`` value from a verified official page.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import os


_BLOCK_PADDING = 0x00000001
_UCHAR = ctypes.c_ubyte
_UCHAR_PTR = ctypes.POINTER(_UCHAR)
_ULONG = ctypes.c_ulong
_HANDLE = ctypes.c_void_p


class DormCryptoError(RuntimeError):
    """The observed password transform cannot be performed safely."""


def _check(status: int, operation: str) -> None:
    if status < 0:
        raise DormCryptoError(f"Windows AES {operation} failed ({status & 0xffffffff:08x})")


def _bcrypt_api():
    if os.name != "nt":
        raise DormCryptoError("宿舍门户 AES 组件仅支持 Windows")
    library = ctypes.WinDLL("bcrypt.dll")
    library.BCryptOpenAlgorithmProvider.argtypes = [
        ctypes.POINTER(_HANDLE), ctypes.c_wchar_p, ctypes.c_wchar_p, _ULONG,
    ]
    library.BCryptOpenAlgorithmProvider.restype = ctypes.c_long
    library.BCryptSetProperty.argtypes = [
        _HANDLE, ctypes.c_wchar_p, _UCHAR_PTR, _ULONG, _ULONG,
    ]
    library.BCryptSetProperty.restype = ctypes.c_long
    library.BCryptGetProperty.argtypes = [
        _HANDLE, ctypes.c_wchar_p, _UCHAR_PTR, _ULONG, ctypes.POINTER(_ULONG), _ULONG,
    ]
    library.BCryptGetProperty.restype = ctypes.c_long
    library.BCryptGenerateSymmetricKey.argtypes = [
        _HANDLE, ctypes.POINTER(_HANDLE), _UCHAR_PTR, _ULONG, _UCHAR_PTR, _ULONG, _ULONG,
    ]
    library.BCryptGenerateSymmetricKey.restype = ctypes.c_long
    library.BCryptEncrypt.argtypes = [
        _HANDLE, _UCHAR_PTR, _ULONG, _HANDLE, _UCHAR_PTR, _ULONG,
        _UCHAR_PTR, _ULONG, ctypes.POINTER(_ULONG), _ULONG,
    ]
    library.BCryptEncrypt.restype = ctypes.c_long
    library.BCryptDestroyKey.argtypes = [_HANDLE]
    library.BCryptDestroyKey.restype = ctypes.c_long
    library.BCryptCloseAlgorithmProvider.argtypes = [_HANDLE, _ULONG]
    library.BCryptCloseAlgorithmProvider.restype = ctypes.c_long
    return library


def _aes_ecb_pkcs7(data: bytes, key: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise DormCryptoError("宿舍门户本次页面提供的 AES 密钥长度不受支持")
    if not data:
        raise DormCryptoError("待加密内容为空")

    api = _bcrypt_api()
    algorithm = _HANDLE()
    cipher_key = _HANDLE()
    key_object = None
    secret = (_UCHAR * len(key)).from_buffer_copy(key)
    plain = (_UCHAR * len(data)).from_buffer_copy(data)
    try:
        _check(api.BCryptOpenAlgorithmProvider(ctypes.byref(algorithm), "AES", None, 0), "open")
        mode = ctypes.create_unicode_buffer("ChainingModeECB")
        _check(
            api.BCryptSetProperty(
                algorithm, "ChainingMode", ctypes.cast(mode, _UCHAR_PTR),
                ctypes.sizeof(mode), 0,
            ),
            "set mode",
        )
        object_length = _ULONG()
        received = _ULONG()
        _check(
            api.BCryptGetProperty(
                algorithm, "ObjectLength", ctypes.cast(ctypes.byref(object_length), _UCHAR_PTR),
                ctypes.sizeof(object_length), ctypes.byref(received), 0,
            ),
            "get key object size",
        )
        if received.value != ctypes.sizeof(object_length) or not 0 < object_length.value <= 65536:
            raise DormCryptoError("Windows AES 返回无效的密钥对象长度")
        key_object = (_UCHAR * object_length.value)()
        _check(
            api.BCryptGenerateSymmetricKey(
                algorithm, ctypes.byref(cipher_key), key_object, object_length.value,
                secret, len(key), 0,
            ),
            "generate key",
        )
        output_length = _ULONG()
        _check(
            api.BCryptEncrypt(
                cipher_key, plain, len(data), None, None, 0,
                None, 0, ctypes.byref(output_length), _BLOCK_PADDING,
            ),
            "measure ciphertext",
        )
        if not 0 < output_length.value <= len(data) + 16:
            raise DormCryptoError("Windows AES 返回无效的密文长度")
        output = (_UCHAR * output_length.value)()
        written = _ULONG()
        _check(
            api.BCryptEncrypt(
                cipher_key, plain, len(data), None, None, 0,
                output, output_length.value, ctypes.byref(written), _BLOCK_PADDING,
            ),
            "encrypt",
        )
        if written.value != output_length.value:
            raise DormCryptoError("Windows AES 密文长度与预期不符")
        return bytes(output)
    finally:
        if cipher_key.value:
            api.BCryptDestroyKey(cipher_key)
        if algorithm.value:
            api.BCryptCloseAlgorithmProvider(algorithm, 0)
        if key_object is not None:
            ctypes.memset(key_object, 0, ctypes.sizeof(key_object))
        ctypes.memset(secret, 0, ctypes.sizeof(secret))
        ctypes.memset(plain, 0, ctypes.sizeof(plain))


def encrypt_dorm_sso_value(value: str, croypto: str) -> str:
    """Mirror the observed Base64-key AES/ECB/PKCS7 -> Base64 page transform.

    No trimming or password-specific preprocessing is done here: the actual
    submitted model value must be established before the login flow is wired.
    """
    try:
        key = base64.b64decode(croypto, validate=True)
    except (binascii.Error, ValueError) as error:
        raise DormCryptoError("宿舍门户页面提供的加密参数不是有效 Base64") from error
    if len(key) not in (16, 24, 32):
        raise DormCryptoError("宿舍门户页面提供的 AES 密钥长度不受支持")
    return base64.b64encode(_aes_ecb_pkcs7(value.encode("utf-8"), key)).decode("ascii")
