"""Smoke-тест native: вызывается из CI после установки wheel (§12.4).

Проверяет, что:
- пакет `taptuna` импортируется;
- подмодуль `taptuna._native` доступен;
- обёртка `taptuna.native` видит native;
- все шесть модулей native на месте.
"""
from __future__ import annotations

import sys


def main() -> int:
    print("python:", sys.version)

    import taptuna
    print("taptuna:", taptuna.__file__)

    import taptuna._native as n
    print("native:", n.__file__)

    mods = sorted(x for x in dir(n) if not x.startswith("_"))
    print("modules:", mods)
    for m in ("wire", "seq", "reassembly", "framing", "extract", "safe_eval"):
        assert m in mods, f"missing native module: {m}"

    from taptuna.native import HAS_NATIVE, native_status
    print("HAS_NATIVE:", HAS_NATIVE)
    print(native_status())
    assert HAS_NATIVE, "native не подключён"

    # Мини-прогон: reassembly
    from taptuna.native import reassemble
    out = reassemble(
        segments=[
            {"abs_seq": 1000, "len": 5, "frame_number": 1, "data": b"Hello"},
            {"abs_seq": 1005, "len": 5, "frame_number": 2, "data": b"World"},
        ],
        syn_seq=999,
        overlap_policy="first_wins",
    )
    assert out["data"] == b"HelloWorld", out
    print("reassembly OK")

    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())