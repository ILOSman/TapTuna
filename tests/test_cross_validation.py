"""Cross-validation: Native vs Python, детерминизм verify (§20.3)."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from taptuna.native import HAS_NATIVE, reassemble as native_reassemble
from taptuna.native.fallback import reassemble_py


# ---------------------------------------------------------------------------
# Идентичность native и fallback
# ---------------------------------------------------------------------------

def _canonical(result: dict) -> dict:
    """Нормализует результат для сравнения (убирает типовые различия)."""
    return {
        "data": bytes(result["data"]),
        "gaps": sorted(
            [(g["offset"], g["length"], tuple(sorted(g["frames"]))) for g in result["gaps"]]
        ),
        "ambiguities": sorted(
            [(a["offset"], a["length"], tuple(sorted(a["frames"])),
              a.get("policy")) for a in result["ambiguities"]]
        ),
        "stream_start_abs_seq": result["stream_start_abs_seq"],
        "roles_established": result["roles_established"],
    }


@pytest.mark.skipif(not HAS_NATIVE, reason="native not available")
def test_native_vs_python_simple():
    segs = [
        {"abs_seq": 1000, "len": 5, "frame_number": 1, "data": b"Hello"},
        {"abs_seq": 1005, "len": 5, "frame_number": 2, "data": b"World"},
    ]
    a = native_reassemble(segments=segs, syn_seq=999, overlap_policy="first_wins")
    b = reassemble_py(segments=segs, syn_seq=999, overlap_policy="first_wins",
                      max_stream_bytes=None)
    assert _canonical(a) == _canonical(b)


@pytest.mark.skipif(not HAS_NATIVE, reason="native not available")
def test_native_vs_python_with_gap():
    segs = [
        {"abs_seq": 1000, "len": 5, "frame_number": 1, "data": b"Hello"},
        {"abs_seq": 1015, "len": 5, "frame_number": 2, "data": b"World"},
    ]
    a = native_reassemble(segments=segs, syn_seq=999, overlap_policy="first_wins")
    b = reassemble_py(segments=segs, syn_seq=999, overlap_policy="first_wins",
                      max_stream_bytes=None)
    ca, cb = _canonical(a), _canonical(b)
    assert ca["data"] == cb["data"]
    assert ca["gaps"] == cb["gaps"]


@pytest.mark.skipif(not HAS_NATIVE, reason="native not available")
def test_native_vs_python_overlap():
    segs = [
        {"abs_seq": 1000, "len": 10, "frame_number": 1, "data": b"HelloWorld"},
        {"abs_seq": 1005, "len": 10, "frame_number": 2, "data": b"XXXXXDiffe"},
    ]
    for policy in ("first_wins", "last_wins", "halt_and_mark"):
        a = native_reassemble(segments=segs, syn_seq=999, overlap_policy=policy)
        b = reassemble_py(segments=segs, syn_seq=999, overlap_policy=policy,
                          max_stream_bytes=None)
        assert _canonical(a)["data"] == _canonical(b)["data"], f"policy={policy}"
        assert len(a["ambiguities"]) == len(b["ambiguities"]), f"policy={policy}"


# ---------------------------------------------------------------------------
# Детерминизм verify: два прогона → одинаковый run_hash
# ---------------------------------------------------------------------------

def _run_verify_twice(project_dir: Path, corpus_id: int, interp_id: int) -> tuple[str, str]:
    from taptuna.verification import verify_corpus
    a = verify_corpus(project_dir, corpus_id=corpus_id,
                      interpretation_id=interp_id, seed=42)
    b = verify_corpus(project_dir, corpus_id=corpus_id,
                      interpretation_id=interp_id, seed=42)
    return a["run_hash"], b["run_hash"]


@pytest.fixture
def ready_project(tmp_path: Path) -> tuple[Path, int, int]:
    """Проект с одним capture, одной сессией, одной интерпретацией, одним корпусом."""
    import json

    from taptuna.manifest import create_manifest
    from taptuna.store import init_db, open_db

    project = tmp_path / "proj"
    project.mkdir()
    create_manifest(project)
    init_db(project)

    # Наполняем БД напрямую, минуя ingest
    conn = open_db(project)
    cur = conn.cursor()

    cur.execute(
        """INSERT INTO captures (sha256, filename, file_size, packet_count, tshark_version)
           VALUES (?,?,?,?,?)""",
        ("a" * 64, "x.pcap", 1024, 2, "TShark 4.7.4"),
    )
    capture_id = cur.lastrowid

    cur.execute(
        """INSERT INTO sessions
           (capture_id, stream_index, ip_src, ip_dst, port_src, port_dst,
            roles_established, syn_frame, first_frame, last_frame,
            start_time, end_time, packets_a2b, packets_b2a, bytes_a2b, bytes_b2a)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (capture_id, 0, "10.0.0.1", "10.0.0.2", 12345, 8080,
         1, 1, 1, 2, 1.0, 2.0, 2, 0, 13, 0),
    )
    session_id = cur.lastrowid

    cur.execute(
        """INSERT INTO directions
           (session_id, direction, stream_start_abs_seq, reassembled_bytes,
            gaps_json, ambiguities_json, overlap_policy)
           VALUES (?,?,?,?,?,?,?)""",
        (session_id, "a_to_b", 1001, 13, "[]", "[]", "first_wins"),
    )
    direction_id = cur.lastrowid

    cur.execute(
        """INSERT INTO packets
           (direction_id, frame_number, abs_seq, tcp_len,
            flags_syn, flags_ack, flags_fin, flags_rst,
            payload_sha256, payload_inline, stream_offset)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (direction_id, 2, 1001, 13, 0, 1, 0, 0,
         None, b"Hello, World!", 0),
    )
    conn.commit()

    # Интерпретация
    framing = json.dumps({"kind": "fixed", "size": 13, "max_message": 1024})
    fields = json.dumps({"name": "message", "fields": [
        {"name": "raw", "type": "bytes", "offset": 0, "size": 13},
    ]})
    cur.execute(
        """INSERT INTO interpretations
           (name, version, kind, source_yaml, source_hash,
            framing_json, fields_json, constraints_json, semantics_json)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        ("fixed13", 1, "declarative", "{}", "h", framing, fields, "[]", "{}"),
    )
    interp_id = cur.lastrowid

    # Корпус
    cur.execute(
        "INSERT INTO corpora (name, criteria_json) VALUES (?,?)",
        ("c1", json.dumps({"any_ports": [8080]})),
    )
    corpus_id = cur.lastrowid
    conn.commit()
    conn.close()

    return project, corpus_id, interp_id


def test_verify_deterministic_hash(ready_project):
    project, corpus_id, interp_id = ready_project
    h1, h2 = _run_verify_twice(project, corpus_id, interp_id)
    assert h1 == h2, f"run_hash не совпадает: {h1} != {h2}"
    assert len(h1) == 64  # sha256 hex