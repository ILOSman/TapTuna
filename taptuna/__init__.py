"""Taptuna — Protocol Laboratory."""

__version__ = "0.1.0"

import os

_native = None
if os.environ.get("TAPTUNA_NATIVE", "1") != "0":
    try:
        from taptuna import _native as _native  # type: ignore
    except ImportError:
        _native = None

HAS_NATIVE = _native is not None