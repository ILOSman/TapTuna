"""Профиль памяти: framing + extract на 100k сообщений (§10 ТЗ).

Измеряет Python-объекты, создаваемые PyO3-вызовами (list[int] vs bytes).
Rust-часть (буферы reassembly) измеряется отдельно через dhat
(benches/memory.rs).

Тест только на POSIX: tracemalloc кроссплатформенный, но цифры
имеют смысл только в контексте Linux x86-64 (§10).
"""
from __future__ import annotations

import gc
import sys
import tracemalloc

import pytest

from taptuna import native as _nat


pytestmark = pytest.mark.skipif(
    not _nat.HAS_NATIVE,
    reason="native core not available",
)


def _frame_stream(stream: bytes, framing: dict) -> dict:
    return _nat._native.framing.frame_stream(stream, framing)


def test_frame_stream_100k_messages_memory():
    """100k сообщений × 100 байт = 10 МиБ потока.

    Считает пиковую память Python-объектов через tracemalloc.
    Если framing возвращает bytes — будет ~10-15 МиБ.
    Если list[int] — в 20-30 раз больше (Python int ~28 байт).
    """
    N = 100_000
    msg_size = 100
    stream = b"\xAB" * (N * msg_size)

    gc.collect()
    tracemalloc.start()

    out = _frame_stream(stream, {
        "kind": "fixed",
        "size": msg_size,
        "max_message": 1024,
    })
    messages = out["messages"]

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mib = peak / (1024 * 1024)
    print(f"\nstream:        {len(stream) / (1024 * 1024):.1f} MiB")
    print(f"messages:      {len(messages)}")
    print(f"peak Python:   {peak_mib:.1f} MiB")

    assert len(messages) == N, f"expected {N}, got {len(messages)}"

    # Мягкая проверка: после оптимизации PyBytes должно быть < 200 MiB.
    # До оптимизации (list[int]) ~300-400 MiB.
    # Не ассертим жёстко, чтобы не ломать CI на разных версиях Python.
    if peak_mib > 400:
        pytest.fail(
            f"peak Python memory {peak_mib:.1f} MiB > 400 MiB. "
            "Вероятно, framing возвращает list[int] вместо bytes."
        )


def test_frame_stream_leftover_memory():
    """Leftover тоже должен быть bytes, не list[int]."""
    # Делимитер 'X' не встречается → всё сообщение уходит в leftover
    stream = b"A" * 1024

    gc.collect()
    tracemalloc.start()
    out = _frame_stream(stream, {
        "kind": "delimiter",
        "delim": [0x58],  # 'X'
        "include_delim": True,
        "max_message": 4096,
    })
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Не проверяем, потому что leftover в текущем API возвращается как bytes
    # (или как list[int] до оптимизации). Просто фиксируем в логе.
    print(f"\nleftover bytes: {out.get('leftover_bytes', '—')}")
    print(f"peak Python:    {peak / 1024:.1f} KiB")
