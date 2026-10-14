"""Обёртка над нативным ядром `taptuna._native`.

Поведение:
- Если `_native` импортируется и функции доступны — используем его (HAS_NATIVE=True).
- Иначе — прозрачный fallback на чистую Python-реализацию (ТЗ §12.3, §12.4).
- Флаг `TAPTUNA_NATIVE=0` принудительно выключает native.
"""
from __future__ import annotations

import os
from typing import Any, Optional

from . import reassembly as _reassembly

# ---------------------------------------------------------------------------
# Загрузка _native
# ---------------------------------------------------------------------------

_native: Optional[Any] = None
_native_error: Optional[str] = None

if os.environ.get("TAPTUNA_NATIVE", "1") != "0":
    try:
        from taptuna import _native as _native  # type: ignore
    except ImportError as e:
        _native = None
        _native_error = str(e)

HAS_NATIVE: bool = _native is not None

if not HAS_NATIVE and _native_error:
    import warnings
    warnings.warn(
        f"taptuna._native not available ({_native_error}); "
        f"using pure-Python fallback",
        RuntimeWarning,
        stacklevel=2,
    )


# ---------------------------------------------------------------------------
# Публичный API
# ---------------------------------------------------------------------------

def reassemble(
    segments: list[dict],
    syn_seq: Optional[int] = None,
    overlap_policy: str = "first_wins",
    max_stream_bytes: Optional[int] = None,
) -> dict:
    """Пересборка TCP-потока.

    Единый интерфейс независимо от того, есть ли native.

    Args:
        segments: список dict с ключами abs_seq, len, frame_number, data.
        syn_seq: абсолютный seq SYN-пакета, если был.
        overlap_policy: 'first_wins' | 'last_wins' | 'halt_and_mark'.
        max_stream_bytes: верхний предел объёма потока.

    Returns:
        dict с ключами:
            data: bytes
            gaps: list[dict]
            ambiguities: list[dict]
            segments: list[dict]
            byte_map: list[tuple[int, int, int]]
            stream_start_abs_seq: int
            roles_established: bool
    """
    if HAS_NATIVE:
        try:
            return _reassembly.call_native(
                _native,
                segments=segments,
                syn_seq=syn_seq,
                overlap_policy=overlap_policy,
                max_stream_bytes=max_stream_bytes,
            )
        except Exception as e:
            # Native упал — это баг, но не повод ломать pipeline. Fallback.
            import warnings
            warnings.warn(
                f"native reassembly failed ({e!r}); using Python fallback",
                RuntimeWarning,
                stacklevel=2,
            )
    # Python fallback
    from . import fallback
    return fallback.reassemble_py(
        segments=segments,
        syn_seq=syn_seq,
        overlap_policy=overlap_policy,
        max_stream_bytes=max_stream_bytes,
    )


def native_status() -> dict:
    """Диагностика: что загружено, какая версия, какие ошибки."""
    return {
        "has_native": HAS_NATIVE,
        "error": _native_error,
        "version": getattr(_native, "__version__", None) if _native else None,
        "module": getattr(_native, "__name__", None) if _native else None,
    }


__all__ = ["HAS_NATIVE", "reassemble", "native_status"]