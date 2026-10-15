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
                   syn="False", ack_f="False", fin="False", rst="False",
                   payload="48656c6c6f"):
    """Собирает TSV-строку в формате tshark 4.x.

    Флаги передаются строками: "True"/"False" (новые версии tshark)
    или "1"/"0" (старые). По умолчанию — "False".
    """
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


def test_parse_line_flags_true_false():
    """tshark 4.x возвращает флаги как строки 'True'/'False'."""
    line = _make_tsv_line(syn="True", ack_f="True",
                          fin="False", rst="False")
    row = _parse_line(line)
    assert row is not None
    assert row.syn is True
    assert row.ack_flag is True
    assert row.fin is False
    assert row.rst is False


def test_parse_line_flags_one_zero():
    """Старые версии tshark возвращают '1'/'0'."""
    line = _make_tsv_line(syn="1", ack_f="1", fin="0", rst="0")
    row = _parse_line(line)
    assert row is not None
    assert row.syn is True
    assert row.ack_flag is True
    assert row.fin is False
    assert row.rst is False


# ---------------------------------------------------------------------------
# group_by_stream
# ---------------------------------------------------------------------------

def test_group_by_stream_single():
    """SYN без ACK → roles_established, syn_frame=1."""
    rows = [
        _parse_line(_make_tsv_line(frame=1, seq=1000, tcp_len=0,
                                    syn="True", ack_f="False", payload="")),
        _parse_line(_make_tsv_line(frame=2, seq=1001, tcp_len=5,
                                    syn="False", ack_f="True",
                                    payload="48656c6c6f")),
    ]
    sessions = group_by_stream([r for r in rows if r is not None])
    assert len(sessions) == 1
    s = sessions[0]
    assert s.stream_index == 0
    assert s.syn_frame == 1
    assert s.roles_established is True


def test_group_by_stream_syn_ack_not_establishing():
    """SYN+ACK (ответ сервера) не устанавливает роли — роли ставит клиентский SYN."""
    rows = [
        _parse_line(_make_tsv_line(frame=2, seq=5000, tcp_len=0,
                                    syn="True", ack_f="True", payload="")),
    ]
    sessions = group_by_stream([r for r in rows if r is not None])
    assert len(sessions) == 1
    s = sessions[0]
    # syn_frame не выставлен: syn=True, но ack_flag=True
    assert s.syn_frame is None
    assert s.roles_established is False


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
    """Создаёт исполняемый fake-tshark.

    На POSIX — bash-скрипт. На Windows — .bat (CreateProcess не умеет
    запускать .sh напрямую). В обоих случаях счётчик инкрементится
    только при вызове с -r, чтобы не считать 'tshark -v'.
    """
    counter = tmp_path / "tshark_calls.txt"

    if os.name == "nt":
        # Windows: .bat
        script = tmp_path / "fake_tshark.bat"
        body = "@echo off\r\n"
        body += "set count_call=0\r\n"
        body += ":loop\r\n"
        body += "if \"%~1\"==\"\" goto done\r\n"
        body += "if \"%~1\"==\"-r\" (echo x >> \"" + str(counter) + "\")\r\n"
        body += "shift\r\n"
        body += "goto loop\r\n"
        body += ":done\r\n"
        for line in lines:
            # Экранируем ^ и & для .bat
            safe = line.replace("^", "^^").replace("&", "^&")
            body += "echo " + safe + "\r\n"
        body += "exit /b 0\r\n"
        script.write_text(body, encoding="ascii")
    else:
        # POSIX: bash
        script = tmp_path / "fake_tshark.sh"
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
        _make_tsv_line(frame=1, seq=1000, tcp_len=0,
                       syn="True", ack_f="False", payload=""),
        _make_tsv_line(frame=2, seq=1001, tcp_len=5,
                       syn="False", ack_f="True",
                       payload="48656c6c6f"),
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