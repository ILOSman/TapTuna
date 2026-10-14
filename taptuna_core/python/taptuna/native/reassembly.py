"""Адаптер к `_native.reassembly`.

Отвечает только за вызов нативного reassembly и нормализацию результата
к общему dict-формату. Никакой логики пересборки здесь нет.
"""
from __future__ import annotations

from typing import Any, Optional


def call_native(
    native_module: Any,
    segments: list[dict],
    syn_seq: Optional[int],
    overlap_policy: str,
    max_stream_bytes: Optional[int],
) -> dict:
    """Вызывает нативный reassembly и приводит результат к общему виду."""
    if not hasattr(native_module, "reassembly"):
        raise RuntimeError("_native.reassembly not found")

    r = native_module.reassembly

    # Приводим policy к виду, который принимает native.
    # В PyO3-модуле это enum, обычно доступный как атрибут.
    policy_obj = _resolve_policy(r, overlap_policy)

    # Собираем вход. У PyO3-структуры обычно есть __new__,
    # принимающий именованные аргументы.
    if hasattr(r, "PyReassemblyInput"):
        inp = r.PyReassemblyInput(
            segments,           # list[PySegmentWrapper]-совместимое
            policy_obj,
            syn_seq,
        )
        out = r.reassemble_py(inp)
    else:
        # Альтернативный API: reassemble(segments, syn_seq, policy)
        out = r.reassemble(segments, syn_seq, policy_obj)

    return _normalize_output(out)


def _resolve_policy(r: Any, name: str) -> Any:
    """Преобразует строку политики в объект, ожидаемый native."""
    aliases = {
        "first_wins": "first_wins",
        "last_wins": "last_wins",
        "halt_and_mark": "halt_and_mark",
    }
    if name not in aliases:
        raise ValueError(f"unknown overlap_policy: {name}")
    # PyOverlapPolicy в PyO3 сделан с classmethod-конструкторами
    factory = getattr(r.PyOverlapPolicy, name, None)
    if factory is None:
        raise RuntimeError(f"_native.reassembly.PyOverlapPolicy.{name} not found")
    return factory()


def _normalize_output(out: Any) -> dict:
    """Приводит PyReassembledStream к dict.

    Поля PyO3-объекта доступны через геттеры, поэтому getattr работает.
    """
    # byte_map приходит как list[tuple[int,int,int]] или как list[PyByteMapEntry]
    bm_raw = getattr(out, "byte_map", [])
    byte_map = [_norm_byte_map_entry(x) for x in bm_raw]

    return {
        "data": bytes(getattr(out, "data", b"")),
        "gaps": [_norm_gap(g) for g in getattr(out, "gaps", [])],
        "ambiguities": [_norm_amb(a) for a in getattr(out, "ambiguities", [])],
        "segments": [_norm_seg(s) for s in getattr(out, "segments", [])],
        "byte_map": byte_map,
        "stream_start_abs_seq": int(getattr(out, "stream_start_abs_seq", 0)),
        "roles_established": bool(getattr(out, "roles_established", False)),
    }


def _norm_byte_map_entry(x: Any) -> tuple[int, int, int]:
    if isinstance(x, tuple) and len(x) == 3:
        return (int(x[0]), int(x[1]), int(x[2]))
    # PyByteMapEntry со start/end/frame
    return (
        int(getattr(x, "start")),
        int(getattr(x, "end")),
        int(getattr(x, "frame")),
    )


def _norm_gap(g: Any) -> dict:
    if isinstance(g, dict):
        return g
    return {
        "offset": int(getattr(g, "offset")),
        "length": int(getattr(g, "length")),
        "frames": list(getattr(g, "frames", [])),
    }


def _norm_amb(a: Any) -> dict:
    if isinstance(a, dict):
        return a
    policy = getattr(a, "policy", None)
    policy_name = getattr(policy, "name", None) if policy is not None else None
    return {
        "offset": int(getattr(a, "offset")),
        "length": int(getattr(a, "length")),
        "frames": list(getattr(a, "frames", [])),
        "policy": policy_name,
    }


def _norm_seg(s: Any) -> dict:
    if isinstance(s, dict):
        return s
    status = getattr(s, "status", None)
    status_name = getattr(status, "name", None) if status is not None else None
    return {
        "stream_offset": int(getattr(s, "stream_offset")),
        "length": int(getattr(s, "length")),
        "abs_seq_start": int(getattr(s, "abs_seq_start")),
        "abs_seq_end": int(getattr(s, "abs_seq_end")),
        "status": status_name,
        "first_frame": int(getattr(s, "first_frame")),
        "last_frame": int(getattr(s, "last_frame")),
    }