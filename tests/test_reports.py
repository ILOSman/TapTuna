"""Тесты генерации отчётов (§11.1, §11.2 ТЗ)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from taptuna.manifest import create_manifest
from taptuna.reports import generate_report, build_machine_model
from taptuna.store import init_db, open_db


def _seed_project(project: Path) -> int:
    """Проект с одним capture, сессией, интерпретацией, корпусом,
    прогоном и результатами разных статусов. Возвращает run_id."""
    conn = open_db(project)
    cur = conn.cursor()

    pcap_dir = project / "captures"
    pcap_dir.mkdir(exist_ok=True)
    (pcap_dir / ("a" * 64 + ".pcap")).write_bytes(b"\x00" * 100)

    cur.execute(
        """INSERT INTO captures
           (sha256, filename, file_size, packet_count, tshark_version)
           VALUES (?,?,?,?,?)""",
        ("a" * 64, "demo.pcap", 100, 10, "TShark 4.7.4"),
    )
    cap_id = cur.lastrowid

    cur.execute(
        """INSERT INTO sessions
           (capture_id, stream_index, ip_src, ip_dst, port_src, port_dst,
            roles_established, syn_frame, first_frame, last_frame,
            start_time, end_time, packets_a2b, packets_b2a, bytes_a2b, bytes_b2a)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cap_id, 0, "10.0.0.1", "10.0.0.2", 1234, 80,
         1, 1, 1, 5, 1.0, 5.0, 3, 2, 100, 200),
    )
    sid = cur.lastrowid

    cur.execute(
        """INSERT INTO directions
           (session_id, direction, stream_start_abs_seq, reassembled_bytes,
            gaps_json, ambiguities_json, overlap_policy)
           VALUES (?,?,?,?,?,?,?)""",
        (sid, "a_to_b", 1, 100, "[]", "[]", "first_wins"),
    )
    did = cur.lastrowid

    framing = json.dumps({"kind": "fixed", "size": 13, "max_message": 1024})
    fields = json.dumps({"name": "message", "fields": [
        {"name": "raw", "type": "bytes", "offset": 0, "size": 13},
    ]})
    cur.execute(
        """INSERT INTO interpretations
           (name, version, kind, source_yaml, source_hash,
            framing_json, fields_json, constraints_json, semantics_json)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        ("t", 1, "declarative", "{}", "h", framing, fields, "[]", "{}"),
    )
    interp_id = cur.lastrowid

    cur.execute(
        "INSERT INTO corpora (name, criteria_json) VALUES (?,?)",
        ("c", json.dumps({"any_ports": [80]})),
    )
    corpus_id = cur.lastrowid

    cur.execute(
        """INSERT INTO verification_runs
           (corpus_id, interpretation_id, seed, status, params_json)
           VALUES (?,?,?,?,?)""",
        (corpus_id, interp_id, 0, "completed", "{}"),
    )
    run_id = cur.lastrowid

    # Разные статусы
    cur.execute(
        """INSERT INTO verification_results
           (run_id, session_id, direction_id, message_index,
            stream_offset, length, status, message_name, result_hash)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (run_id, sid, did, 0, 0, 13, "ok", "t", "h1"),
    )
    cur.execute(
        """INSERT INTO verification_results
           (run_id, session_id, direction_id, message_index,
            stream_offset, length, status, message_name, result_hash)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (run_id, sid, did, 1, 20, 13, "violation", "t", "h2"),
    )
    cur.execute(
        """INSERT INTO verification_results
           (run_id, session_id, direction_id, message_index,
            stream_offset, length, status, message_name, result_hash)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (run_id, sid, did, 2, 40, 10, "incomplete", "t", "h3"),
    )

    # Гипотеза
    cur.execute(
        "INSERT INTO hypotheses (formulation, status) VALUES (?,?)",
        ("Первое поле — magic", "open"),
    )

    # Наблюдение
    cur.execute(
        """INSERT INTO observations
           (target_type, target_id, description, byte_range_start, byte_range_end)
           VALUES (?,?,?,?,?)""",
        ("range", sid, "Первый байт = 0x48", 0, 0),
    )

    conn.commit()
    conn.close()
    return run_id


def test_generate_report_md_has_all_sections(tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)
    run_id = _seed_project(project)

    result = generate_report(project, run_id=run_id, formats=("md",))
    md = result["md_path"].read_text(encoding="utf-8")

    required_sections = [
        "## 1. Цели и границы",
        "## 2. Метод",
        "## 3. Корпус",
        "## 4. Проверенные примеры",
        "## 5. Контрпримеры",
        "## 6. Неизвестные участки",
        "## 7. Область применимости",
        "## 8. Открытые вопросы",
        "## 9. Гипотезы",
        "## 10. Предупреждение о checksum offloading",
    ]
    for section in required_sections:
        assert section in md, f"missing section: {section}"


def test_report_contains_verification_data(tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)
    run_id = _seed_project(project)

    result = generate_report(project, run_id=run_id, formats=("md",))
    md = result["md_path"].read_text(encoding="utf-8")

    # Контрпример должен быть в §5
    assert "violation" in md.lower()
    # Неизвестные участки — в §6
    assert "incomplete" in md.lower()


def test_report_contains_hypotheses(tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)
    run_id = _seed_project(project)

    result = generate_report(project, run_id=run_id, formats=("md",))
    md = result["md_path"].read_text(encoding="utf-8")

    assert "Первое поле — magic" in md


def test_machine_model_has_required_keys(tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)
    run_id = _seed_project(project)

    result = generate_report(project, run_id=run_id, formats=("json",))
    model = json.loads(result["machine_model_path"].read_text(encoding="utf-8"))

    for key in ("format_version", "interpretation", "framing", "fields",
                "constraints", "semantics", "verification", "provenance"):
        assert key in model, f"missing key: {key}"


def test_report_html_valid(tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)
    run_id = _seed_project(project)

    result = generate_report(project, run_id=run_id, formats=("html",))
    html = result["html_path"].read_text(encoding="utf-8")

    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html
    assert "<h1>" in html


def test_report_no_run_raises(tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)

    from taptuna.errors import ValidationError
    with pytest.raises(ValidationError) as ei:
        generate_report(project, run_id=999, formats=("md",))
    assert "RUN_NOT_FOUND" in str(ei.value.code) or "not found" in str(ei.value)