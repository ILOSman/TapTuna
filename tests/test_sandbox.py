"""Тесты sandbox для script-интерпретаций (§8.5, §20.2)."""
from __future__ import annotations

import time

import pytest

from taptuna.interpreters.script_sandbox import ScriptInterpreter


# ---------------------------------------------------------------------------
# Whitelist
# ---------------------------------------------------------------------------

def test_whitelist_blocks_socket():
    code = """
import socket
def interpret(payload, index, stream_offset):
    return {"status": "ok"}
"""
    interp = ScriptInterpreter(
        spec={"code": code, "message_size": 4},
        name="block_socket", seed=0,
    )
    results = interp.interpret(b"ABCD", direction_id=1)
    assert len(results) == 1
    assert results[0].status.value == "unknown_frame"
    joined = " ".join(results[0].notes)
    assert "socket" in joined
    assert "not allowed" in joined


def test_whitelist_allows_math():
    code = """
import math, struct
def interpret(payload, index, stream_offset):
    return {
        "status": "ok",
        "fields": {
            "sqrt2": math.sqrt(2),
            "value": struct.unpack('>I', payload)[0],
        },
    }
"""
    interp = ScriptInterpreter(
        spec={"code": code, "message_size": 4},
        name="allow_math", seed=0,
    )
    results = interp.interpret(b"\x00\x00\x00\x2a", direction_id=1)
    assert len(results) == 1
    assert results[0].status.value == "ok"
    assert results[0].fields["value"] == 42
    assert abs(results[0].fields["sqrt2"] - 1.4142135) < 1e-6


def test_whitelist_blocks_os():
    code = """
import os
def interpret(payload, index, stream_offset):
    return {"status": "ok"}
"""
    interp = ScriptInterpreter(
        spec={"code": code, "message_size": 4},
        name="block_os", seed=0,
    )
    results = interp.interpret(b"ABCD", direction_id=1)
    assert results[0].status.value == "unknown_frame"
    assert "os" in " ".join(results[0].notes)


# ---------------------------------------------------------------------------
# Таймауты и лимиты
# ---------------------------------------------------------------------------

def test_cpu_limit_kills_worker():
    code = """
def interpret(payload, index, stream_offset):
    while True:
        pass
"""
    interp = ScriptInterpreter(
        spec={"code": code, "message_size": 4},
        name="cpu_burn",
        cpu_seconds=1,
        timeout_per_message=60.0,   # wall-clock не должен сработать
    )
    start = time.monotonic()
    results = interp.interpret(b"ABCD", direction_id=1)
    elapsed = time.monotonic() - start

    assert elapsed < 10.0, f"worker не убит за разумное время: {elapsed:.2f}с"
    assert len(results) == 1
    assert results[0].status.value == "unknown_frame"
    joined = " ".join(results[0].notes).lower()
    assert "cpu" in joined or "sigxcpu" in joined or "killed" in joined


def test_wall_clock_timeout():
    code = """
import time
def interpret(payload, index, stream_offset):
    time.sleep(30)
    return {"status": "ok"}
"""
    interp = ScriptInterpreter(
        spec={"code": code, "message_size": 4},
        name="sleepy",
        cpu_seconds=60,             # CPU не сработает
        timeout_per_message=1.0,    # сработает wall-clock
    )
    start = time.monotonic()
    results = interp.interpret(b"ABCD", direction_id=1)
    elapsed = time.monotonic() - start

    assert elapsed < 5.0, f"wall-clock timeout не сработал за 5с: {elapsed:.2f}с"
    assert len(results) == 1
    assert results[0].status.value == "unknown_frame"
    joined = " ".join(results[0].notes).lower()
    assert "timeout" in joined


# ---------------------------------------------------------------------------
# Respawn: каждый вызов — новый процесс
# ---------------------------------------------------------------------------

def test_worker_respawns_each_call():
    """Падение worker'а не ломает следующий вызов — процесс создаётся заново."""
    bad_code = """
def interpret(payload, index, stream_offset):
    raise RuntimeError("boom")
"""
    bad = ScriptInterpreter(
        spec={"code": bad_code, "message_size": 4},
        name="boom", seed=0,
    )
    results_bad = bad.interpret(b"ABCD", direction_id=1)
    assert results_bad[0].status.value == "partial"

    good_code = """
def interpret(payload, index, stream_offset):
    return {"status": "ok", "fields": {"n": len(payload)}}
"""
    good = ScriptInterpreter(
        spec={"code": good_code, "message_size": 4},
        name="good", seed=0,
    )
    results_good = good.interpret(b"ABCD", direction_id=1)
    assert results_good[0].status.value == "ok"
    assert results_good[0].fields["n"] == 4


# ---------------------------------------------------------------------------
# Детерминизм seed
# ---------------------------------------------------------------------------

def test_seed_is_deterministic():
    code = """
import random
def interpret(payload, index, stream_offset):
    return {
        "status": "ok",
        "fields": {"r": random.randint(0, 1000000)},
    }
"""
    a = ScriptInterpreter(
        spec={"code": code, "message_size": 4}, name="rnd", seed=42,
    )
    b = ScriptInterpreter(
        spec={"code": code, "message_size": 4}, name="rnd", seed=42,
    )
    ra = a.interpret(b"ABCD", direction_id=1)
    rb = b.interpret(b"ABCD", direction_id=1)
    assert ra[0].fields["r"] == rb[0].fields["r"]