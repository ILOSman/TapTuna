"""Тесты ingest: fake tshark, один вызов на файл (§20.2)."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from taptuna.manifest import create_manifest
from taptuna.store import init_db

from taptuna.ingest import (
    TSHARK_FIELDS,
    _parse_line,
    compute_sha256,
    group_by_stream,
    ingest_capture,
    run_tshark,
)


# ---------------------------------------------------------------------------
# _parse_line
# ---------------------------------------------------------------------------

def _make_tsv_line(*, stream=0, frame=1, ts=1700000000.0,
                   ip_src="10.0.0.1", ip_dst="10.0.0.2",
                   sport=1234, dport=80, seq=1000, ack=0, tcp_len=5,
                   syn=0, ack_f=0, fin=0, rst=0, payload="48656c6c6f"):
    parts = [
        str(stream), str(frame), str(ts), ip_src, ip_dst,
        str(sport), str(dport), str(seq), str(ack), str(tcp_len),
        str(syn), str(ack_f), str(fin), str(rst), payload,
    ]
    return "\t".join(parts)


def test_parse_line_full():
    line = _make_tsv_line()
    row = _parse_line(line)
    assert row is not None
    assert row.stream == 0
    assert row.frame == 1
    assert row.ip_src == "10.0.0.1"
    assert row.port_src == 1234
    assert row.tcp_len == 5
    assert row.payload == b"Hello"


def test_parse_line_empty_fields():
    line = _make_tsv_line(stream="", payload="")
    # stream пустой -> None
    assert _parse_line(line) is None


def test_parse_line_too_few_fields():
    assert _parse_line("0\t1") is None


def test_parse_line_empty_string():
    assert _parse_line("") is None


# ---------------------------------------------------------------------------
# group_by_stream
# ---------------------------------------------------------------------------

def test_group_by_stream_single():
    rows = [
        _parse_line(_make_tsv_line(frame=1, seq=1000, tcp_len=0, syn=1, payload="")),
        _parse_line(_make_tsv_line(frame=2, seq=1001, tcp_len=5, payload="48656c6c6f")),
    ]
    sessions = group_by_stream([r for r in rows if r is not None])
    assert len(sessions) == 1
    s = sessions[0]
    assert s.stream_index == 0
    assert s.syn_frame == 1
    assert s.roles_established is True


def test_group_by_stream_multiple():
    rows = [
        _parse_line(_make_tsv_line(stream=0, frame=1)),
        _parse_line(_make_tsv_line(stream=1, frame=2)),
        _parse_line(_make_tsv_line(stream=2, frame=3)),
    ]
    sessions = group_by_stream([r for r in rows if r is not None])
    assert len(sessions) == 3


# ---------------------------------------------------------------------------
# Fake tshark
# ---------------------------------------------------------------------------

def _make_fake_tshark(tmp_path: Path, lines: list[str]) -> tuple[Path, Path]:
    """Возвращает (путь_к_скрипту, путь_к_счётчику).

    Счётчик инкрементится ТОЛЬКО при вызове с -r (ingest PCAP),
    а не при 'tshark -v' (который дёргает create_manifest).
    """
    script = tmp_path / "fake_tshark.sh"
    counter = tmp_path / "tshark_calls.txt"
    body = (
        "#!/bin/bash\n"
        f'for arg in "$@"; do\n'
        f'  if [ "$arg" = "-r" ]; then\n'
        f'    echo x >> {counter}\n'
        f'    break\n'
        f'  fi\n'
        f'done\n'
        "cat <<'TSV_EOF'\n"
        + "\n".join(lines) + "\n"
        "TSV_EOF\n"
        "exit 0\n"
    )
    script.write_text(body, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return script, counter


def test_run_tshark_single_call(tmp_path, monkeypatch):
    """run_tshark вызывает fake-tshark ровно один раз на файл."""
    out = [_make_tsv_line(frame=1, tcp_len=5)]
    script, counter = _make_fake_tshark(tmp_path, out)

    monkeypatch.setenv("TAPTUNA_TSHARK", str(script))
    # сбрасываем кеш tshark_check, если он есть
    import importlib
    from taptuna import tshark_check
    importlib.reload(tshark_check)

    pcap = tmp_path / "in.pcap"
    pcap.write_bytes(b"\x00" * 24)

    rows = run_tshark(pcap)
    assert len(rows) == 1
    assert rows[0].frame == 1

    assert counter.read_text().count("x") == 1, "tshark должен вызываться ровно один раз"


def test_ingest_single_tshark_call(tmp_path, monkeypatch):
    """Полный ingest_capture: tshark вызывается один раз на файл."""
    out = [
        _make_tsv_line(frame=1, seq=1000, tcp_len=0, syn=1, payload=""),
        _make_tsv_line(frame=2, seq=1001, tcp_len=5, payload="48656c6c6f"),
    ]
    script, counter = _make_fake_tshark(tmp_path, out)

    monkeypatch.setenv("TAPTUNA_TSHARK", str(script))
    import importlib
    from taptuna import tshark_check
    importlib.reload(tshark_check)

    project = tmp_path / "proj"
    project.mkdir()
    create_manifest(project)
    init_db(project)

    pcap = tmp_path / "in.pcap"
    pcap.write_bytes(b"\x00" * 24)

    result = ingest_capture(project_dir=project, input_path=pcap, no_copy=False)
    assert result["sessions"] == 1
    assert result["packets"] == 2

    calls = counter.read_text().count("x")
    assert calls == 1, f"tshark вызван {calls} раз, ожидался 1"


# ---------------------------------------------------------------------------
# compute_sha256
# ---------------------------------------------------------------------------

def test_compute_sha256(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"abc")
    sha = compute_sha256(p)
    assert sha == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"