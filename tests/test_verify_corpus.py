"""Тесты verify_corpus: cancel → cancelled, gaps → unknown_ranges
(ТЗ §7.1 R4, §10)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from taptuna.manifest import create_manifest
from taptuna.store import init_db, open_db
from taptuna.errors import ValidationError


def _seed_project(
    project: Path,
    *,
    with_gap: bool = False,
    with_second_session: bool = False,
) -> tuple[int, int, int]:
    """capture + session + direction (+ gap) + interpretation + corpus.
    Возвращает (corpus_id, interpretation_id, session_id)."""
    conn = open_db(project)
    cur = conn.cursor()

    cur.execute(
        """INSERT INTO captures
           (sha256, filename, file_size, packet_count, tshark_version)
           VALUES (?,?,?,?,?)""",
        ("a" * 64, "x.pcap", 100, 3, "TShark"),
    )
    cap = cur.lastrowid

    cur.execute(
        """INSERT INTO sessions
           (capture_id, stream_index, ip_src, ip_dst, port_src, port_dst,
            roles_established, syn_frame, first_frame, last_frame,
            start_time, end_time, packets_a2b, packets_b2a, bytes_a2b, bytes_b2a)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cap, 0, "1.1.1.1", "2.2.2.2", 1000, 2000,
         1, 1, 1, 3, 0.0, 3.0, 3, 0, 15, 0),
    )
    sid = cur.lastrowid

    # Вторая сессия — чтобы тест отмены мог сработать после первой итерации.
    # Вторая сессия — только для cancel-теста. Для gap-теста её нет.
    sid2: int | None = None
    if with_second_session:
        cur.execute(
            """INSERT INTO sessions
               (capture_id, stream_index, ip_src, ip_dst, port_src, port_dst,
                roles_established, syn_frame, first_frame, last_frame,
                start_time, end_time, packets_a2b, packets_b2a, bytes_a2b, bytes_b2a)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (cap, 1, "1.1.1.1", "2.2.2.2", 1001, 2001,
             1, 1, 4, 6, 3.0, 6.0, 3, 0, 15, 0),
        )
        sid2 = cur.lastrowid

    # with_gap=True → 15 байт потока, байты [5,10) — gap.
    gaps_json = json.dumps(
        [{"offset": 5, "length": 5, "frames": [99]}]
        if with_gap else []
    )

    cur.execute(
        """INSERT INTO directions
           (session_id, direction, stream_start_abs_seq, reassembled_bytes,
            gaps_json, ambiguities_json, overlap_policy)
           VALUES (?,?,?,?,?,?,?)""",
        (sid, "a_to_b", 1, 15, gaps_json, "[]", "first_wins"),
    )
    did = cur.lastrowid

    if with_gap:
        # [0..5) известно, [5..10) пропущено, [10..15) известно.
        cur.execute(
            """INSERT INTO packets
               (direction_id, frame_number, abs_seq, tcp_len,
                flags_syn, flags_ack, flags_fin, flags_rst,
                payload_sha256, payload_inline, stream_offset)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (did, 1, 1, 5, 0, 0, 0, 0, None, b"AAAAA", 0),
        )
        cur.execute(
            """INSERT INTO packets
               (direction_id, frame_number, abs_seq, tcp_len,
                flags_syn, flags_ack, flags_fin, flags_rst,
                payload_sha256, payload_inline, stream_offset)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (did, 3, 11, 5, 0, 0, 0, 0, None, b"BBBBB", 10),
        )
    else:
        cur.execute(
            """INSERT INTO packets
               (direction_id, frame_number, abs_seq, tcp_len,
                flags_syn, flags_ack, flags_fin, flags_rst,
                payload_sha256, payload_inline, stream_offset)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (did, 1, 1, 15, 0, 0, 0, 0, None, b"AAAAAAAAAAAAAAA", 0),
        )

    framing = json.dumps({"kind": "fixed", "size": 5, "max_message": 1024})
    fields = json.dumps({"name": "m", "fields": [
        {"name": "raw", "type": "bytes", "offset": 0, "size": 5},
    ]})
    cur.execute(
        """INSERT INTO interpretations
           (name, version, kind, source_yaml, source_hash,
            framing_json, fields_json, constraints_json, semantics_json)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        ("fixed5", 1, "declarative", "{}", "h", framing, fields, "[]", "{}"),
    )
    interp_id = cur.lastrowid

    # Дублируем direction + packet для второй сессии, чтобы корпус её тоже
    # выбрал по критерию any_ports.
    # Дублируем direction + packet для второй сессии.
    if sid2 is not None:
        cur.execute(
            """INSERT INTO directions
               (session_id, direction, stream_start_abs_seq, reassembled_bytes,
                gaps_json, ambiguities_json, overlap_policy)
               VALUES (?,?,?,?,?,?,?)""",
            (sid2, "a_to_b", 1, 15, "[]", "[]", "first_wins"),
        )
        did2 = cur.lastrowid
        cur.execute(
            """INSERT INTO packets
               (direction_id, frame_number, abs_seq, tcp_len,
                flags_syn, flags_ack, flags_fin, flags_rst,
                payload_sha256, payload_inline, stream_offset)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (did2, 4, 1, 15, 0, 0, 0, 0, None, b"AAAAAAAAAAAAAAA", 0),
        )

    # any_ports содержит 2001 всегда — если второй сессии нет, фильтр
    # просто не найдёт её, а первая сессия (2000) подойдёт.
    cur.execute(
        "INSERT INTO corpora (name, criteria_json) VALUES (?,?)",
        ("c", json.dumps({"any_ports": [2000, 2001]})),
    )
    corpus_id = cur.lastrowid

    conn.commit()
    conn.close()
    return corpus_id, interp_id, sid


@pytest.mark.skipif(
    not __import__("taptuna.native", fromlist=["HAS_NATIVE"]).HAS_NATIVE,
    reason="requires native",
)
def test_verify_cancel_sets_status_cancelled(tmp_path):
    """Отмена прогона сохраняет status='cancelled' (ТЗ §10)."""
    from taptuna.verification import verify_corpus

    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)
    # Вторая сессия обязательна: cancel_check должен сработать
    # на второй итерации, а не на первой.
    corpus_id, interp_id, _ = _seed_project(project, with_second_session=True)

    calls = [0]
    def _cancel():
        calls[0] += 1
        return calls[0] > 1

    with pytest.raises(ValidationError) as ei:
        verify_corpus(project, corpus_id=corpus_id,
                      interpretation_id=interp_id, cancel_check=_cancel)
    assert ei.value.code == "CANCELLED"

    conn = open_db(project)
    try:
        row = conn.execute(
            "SELECT status FROM verification_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row["status"] == "cancelled", (
        f"ожидался cancelled, получили {row['status']}"
    )


@pytest.mark.skipif(
    not __import__("taptuna.native", fromlist=["HAS_NATIVE"]).HAS_NATIVE,
    reason="requires native",
)
def test_verify_unknown_ranges_filled_from_gaps(tmp_path):
    """Сообщения, попавшие в gap, получают status=incomplete и
    непустой unknown_ranges_json (ТЗ §6.4, §11.1)."""
    from taptuna.verification import verify_corpus

    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)
    # Только одна сессия: 3 сообщения (по 5 байт), ожидаем ровно 3.
    corpus_id, interp_id, _ = _seed_project(project, with_gap=True)

    result = verify_corpus(project, corpus_id=corpus_id,
                           interpretation_id=interp_id)
    assert result["messages"] == 3

    conn = open_db(project)
    try:
        rows = conn.execute(
            """SELECT message_index, status, unknown_ranges_json
               FROM verification_results
               WHERE run_id = ? ORDER BY message_index""",
            (result["run_id"],),
        ).fetchall()
    finally:
        conn.close()

    # Сообщение #0: bytes [0..5) — вне gap → ok
    assert rows[0]["status"] == "ok", rows[0]["status"]
    assert json.loads(rows[0]["unknown_ranges_json"]) == []

    # Сообщение #1: bytes [5..10) — полностью в gap → incomplete + [5,10)
    assert rows[1]["status"] == "incomplete", rows[1]["status"]
    ranges_1 = json.loads(rows[1]["unknown_ranges_json"])
    assert ranges_1 == [[5, 10]], ranges_1

    # Сообщение #2: bytes [10..15) — gap закончился на 10 → ok
    assert rows[2]["status"] == "ok", rows[2]["status"]
    assert json.loads(rows[2]["unknown_ranges_json"]) == []