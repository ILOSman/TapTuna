"""Тесты executable hypotheses (ТЗ §9)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from taptuna.manifest import create_manifest
from taptuna.store import init_db, open_db, migrate


def _seed_project(project: Path) -> tuple[int, int]:
    """Проект с одним capture, сессией, интерпретацией, прогоном и
    результатами с полями. Возвращает (run_id, interp_id)."""
    conn = open_db(project)
    cur = conn.cursor()

    pcap_dir = project / "captures"
    pcap_dir.mkdir(exist_ok=True)
    (pcap_dir / ("a" * 64 + ".pcap")).write_bytes(b"\x00" * 100)

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

    cur.execute(
        """INSERT INTO directions
           (session_id, direction, stream_start_abs_seq, reassembled_bytes,
            gaps_json, ambiguities_json, overlap_policy)
           VALUES (?,?,?,?,?,?,?)""",
        (sid, "a_to_b", 1, 15, "[]", "[]", "first_wins"),
    )
    did = cur.lastrowid

    framing = json.dumps({"kind": "fixed", "size": 5, "max_message": 1024})
    fields = json.dumps({"name": "m", "fields": [
        {"name": "temp", "type": "i16be", "offset": 0, "size": 2},
        {"name": "magic", "type": "u8", "offset": 2, "size": 1},
    ]})
    cur.execute(
        """INSERT INTO interpretations
           (name, version, kind, source_yaml, source_hash,
            framing_json, fields_json, constraints_json, semantics_json)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        ("sensor", 1, "declarative", "{}", "h", framing, fields, "[]", "{}"),
    )
    interp_id = cur.lastrowid

    cur.execute(
        "INSERT INTO corpora (name, criteria_json) VALUES (?,?)",
        ("c", json.dumps({"any_ports": [2000]})),
    )
    corpus_id = cur.lastrowid

    cur.execute(
        """INSERT INTO verification_runs
           (corpus_id, interpretation_id, seed, status, params_json)
           VALUES (?,?,?,?,?)""",
        (corpus_id, interp_id, 0, "completed", "{}"),
    )
    run_id = cur.lastrowid

    # Три сообщения: temp = 5, -10, 100 (последнее вне [-20, 20])
    for i, (temp, magic) in enumerate([(5, 0x48), (-10, 0x48), (100, 0x48)]):
        cur.execute(
            """INSERT INTO verification_results
               (run_id, session_id, direction_id, message_index,
                stream_offset, length, status, message_name,
                fields_json, result_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (run_id, sid, did, i, i * 5, 5, "ok", "sensor",
             json.dumps({"temp": temp, "magic": magic}), f"h{i}"),
        )

    conn.commit()
    conn.close()
    return run_id, interp_id


# ---------------------------------------------------------------------------
# Парсер выражений
# ---------------------------------------------------------------------------

def test_parse_simple_comparison():
    from taptuna.hypotheses import parse_expression
    ast = parse_expression("temp >= -20")
    assert ast["op"] == "ge"
    assert ast["a"] == {"op": "field", "name": "temp"}
    assert ast["b"] == {"op": "const", "value": -20}


def test_parse_and_or():
    from taptuna.hypotheses import parse_expression
    ast = parse_expression("temp >= -20 and temp <= 20")
    assert ast["op"] == "and"
    assert ast["a"]["op"] == "ge"
    assert ast["b"]["op"] == "le"


def test_parse_hex():
    from taptuna.hypotheses import parse_expression
    ast = parse_expression("magic == 0x48")
    assert ast["b"] == {"op": "const", "value": 0x48}


def test_parse_bad_syntax():
    from taptuna.hypotheses import parse_expression
    from taptuna.errors import ValidationError
    with pytest.raises(ValidationError) as ei:
        parse_expression("temp >= ")
    assert "Syntax" in ei.value.message


def test_parse_unknown_function():
    from taptuna.hypotheses import parse_expression
    from taptuna.errors import ValidationError
    with pytest.raises(ValidationError):
        parse_expression("eval(malicious)")


# ---------------------------------------------------------------------------
# Миграция
# ---------------------------------------------------------------------------

def test_migration_v2_creates_tables(tmp_path):
    from taptuna.store import SCHEMA_VERSION

    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)

    conn = open_db(project)
    cur = conn.cursor()
    cur.execute("PRAGMA user_version")
    # После всех миграций user_version == SCHEMA_VERSION (текущая версия).
    assert cur.fetchone()[0] == SCHEMA_VERSION
    ...

    # hypothesis_checks существует
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='hypothesis_checks'"
    )
    assert cur.fetchone() is not None

    # Новые столбцы в hypotheses
    cur.execute("PRAGMA table_info(hypotheses)")
    cols = {row[1] for row in cur.fetchall()}
    for c in ("expression_json", "expression_text", "interpretation_id",
              "auto_status", "checked_count"):
        assert c in cols, f"missing column: {c}"
    conn.close()


# ---------------------------------------------------------------------------
# Проверка гипотезы
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not __import__("taptuna.native", fromlist=["HAS_NATIVE"]).HAS_NATIVE,
    reason="requires native",
)
def test_check_hypothesis_supported(tmp_path):
    """Все сообщения внутри [-20, 20] → supported."""
    from taptuna.hypotheses import check_hypothesis

    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)
    run_id, interp_id = _seed_project(project)

    # Меняем третье сообщение на -15 (всё в диапазоне)
    conn = open_db(project)
    cur = conn.cursor()
    cur.execute(
        """UPDATE verification_results
           SET fields_json = ?
           WHERE message_index = 2""",
        (json.dumps({"temp": -15, "magic": 0x48}),),
    )
    conn.commit()
    conn.close()

    # Создаём гипотезу
    conn = open_db(project)
    cur = conn.cursor()
    from taptuna.hypotheses import parse_expression
    expr = parse_expression("temp >= -20 and temp <= 20")
    cur.execute(
        """INSERT INTO hypotheses
           (formulation, status, expression_json, expression_text,
            interpretation_id, auto_status)
           VALUES (?,?,?,?,?,?)""",
        ("Температура в [-20, 20]", "open",
         json.dumps(expr), "temp >= -20 and temp <= 20",
         interp_id, "unknown"),
    )
    hyp_id = cur.lastrowid
    conn.commit()
    conn.close()

    result = check_hypothesis(project, hyp_id, run_id=run_id)
    assert result["status"] == "supported"
    assert result["satisfied"] == 3
    assert result["violated"] == 0


@pytest.mark.skipif(
    not __import__("taptuna.native", fromlist=["HAS_NATIVE"]).HAS_NATIVE,
    reason="requires native",
)
def test_check_hypothesis_refuted(tmp_path):
    """Есть сообщение вне [-20, 20] → refuted."""
    from taptuna.hypotheses import check_hypothesis, parse_expression

    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)
    run_id, interp_id = _seed_project(project)

    conn = open_db(project)
    cur = conn.cursor()
    expr = parse_expression("temp >= -20 and temp <= 20")
    cur.execute(
        """INSERT INTO hypotheses
           (formulation, status, expression_json, expression_text,
            interpretation_id, auto_status)
           VALUES (?,?,?,?,?,?)""",
        ("Температура в [-20, 20]", "open",
         json.dumps(expr), "temp >= -20 and temp <= 20",
         interp_id, "unknown"),
    )
    hyp_id = cur.lastrowid
    conn.commit()
    conn.close()

    result = check_hypothesis(project, hyp_id, run_id=run_id)
    assert result["status"] == "refuted"
    assert result["satisfied"] == 2
    assert result["violated"] == 1


@pytest.mark.skipif(
    not __import__("taptuna.native", fromlist=["HAS_NATIVE"]).HAS_NATIVE,
    reason="requires native",
)
def test_check_hypothesis_inconclusive(tmp_path):
    """Все сообщения not_applicable → inconclusive."""
    from taptuna.hypotheses import check_hypothesis, parse_expression

    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)
    run_id, interp_id = _seed_project(project)

    # Меняем все verify status на partial (не ok)
    conn = open_db(project)
    cur = conn.cursor()
    cur.execute("UPDATE verification_results SET status = 'incomplete'")
    conn.commit()
    cur.execute(
        """INSERT INTO hypotheses
           (formulation, status, expression_json, expression_text,
            interpretation_id, auto_status)
           VALUES (?,?,?,?,?,?)""",
        ("test", "open",
         json.dumps(parse_expression("temp >= -20")), "temp >= -20",
         interp_id, "unknown"),
    )
    hyp_id = cur.lastrowid
    conn.commit()
    conn.close()

    result = check_hypothesis(project, hyp_id, run_id=run_id)
    assert result["status"] == "inconclusive"
    assert result["not_applicable"] == 3