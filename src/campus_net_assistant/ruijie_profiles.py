"""Built-in, redacted NJMU Ruijie compatibility profiles.

Profiles are selected only by the SHA-256 of the official ``8021x.exe``.
They contain no account, password-derived value, MAC/IP address, hardware
identifier, server result frame or raw capture, and they are never used with
an unknown client build.
"""
from __future__ import annotations

import base64

from .ruijie_protocol import CompatibilityProfile


NJMU_PROFILE_ID = "njmu-ruijie-v4.99.20131213"
_SUPPORTED = {
    "b84d7d794a94eb3679caf826b8fddfec76cdc028a1c0e95ae7fcf61e37927bfe": (
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABMRODAyMXguZXhlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEYwMAAQAAExEB+hooAAATERciAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaDAAAExEYBgAAAAAaDgAAExEtCAAAAAAAABoYAAATES8SAAAAAAAAAAAAAAAAAAAAABoJAAATETUDARoYAAATETYSAAAAAAAAAAAAAAAAAAAAABoYAAATETgSAAAAAAAAAAAAAAAAAAAAABoYAAATEU4SAAAAAAAAAAAAAAAAAAAAABqIAAATEU2CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaKAAAExE5ImRlZmF1bHQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGkgAABMRVEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGgkAABMRYgMAGgkAABMRawMAGgkAABMRcANAGh0AABMRbxdSRy1TVSBWNC45OS4yMDEzMTIxMwAaCQAAExF5AwIaFgAAExF2EAAAAAAAAAAAAAAAAAAA",
        "//83d3+fAAAAAP//N3d/nwAAAAD//zd3fz//",
    ),
}


def builtin_profile_for_client(client_sha256: str) -> CompatibilityProfile | None:
    """Return an exact-hash profile, or ``None`` for an unsupported client."""
    encoded = _SUPPORTED.get(client_sha256.casefold())
    if encoded is None:
        return None
    extension = base64.b64decode(encoded[0], validate=True)
    echo_body = base64.b64decode(encoded[1], validate=True)
    return CompatibilityProfile(extension, echo_body, (), client_sha256.casefold())


def supported_client_hashes() -> tuple[str, ...]:
    return tuple(sorted(_SUPPORTED))
