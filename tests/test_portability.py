"""Переносимость проекта: каталог → другой каталог → повторное открытие (§7.1 R5)."""
from __future__ import annotations

import gc
import json
import shutil
import time
from pathlib import Path

import pytest

from taptuna.manifest import create_manifest, load_manifest
from taptuna.store import init_db, open_db, write_blob, read_blob


def _safe_rmtree(path: Path, max_attempts: int = 10, delay: float = 0.2) -> None:
    """Удаляет каталог с ретраями.

    На Windows SQLite может держать handle project.sqlite до следующего GC.
    Решение — gc.collect() + повторные попытки.
    """
    for attempt in range(max_attempts):
        gc.collect()
        try:
            shutil.rmtree(path)
            return
        except PermissionError:
            if attempt == max_attempts - 1:
                raise
            time.sleep(delay)


def _seed_project(project: Path) -> tuple[int, int]:
    """Наполняет проект: capture + session + direction + packet +
    interpretation + corpus. Возвращает (corpus_id, interp_id)."""
    conn = open_db(project)
    cur = conn.cursor()

    pcap_dir = project / "captures"
    pcap_dir.mkdir(exist_ok=True)
    pcap_bytes = b"\x00\x01\x02\x03" * 100
    import hashlib
    sha = hashlib.sha256(pcap_bytes).hexdigest()
    (pcap_dir / f"{sha}.pcap").write_bytes(pcap_bytes)

    cur.execute(
        """INSERT INTO captures
           (sha256, filename, file_size, packet_count, tshark_version)
           VALUES (?,?,?,?,?)""",
        (sha, "test.pcap", len(pcap_bytes), 2, "TShark 4.7.4"),
    )
    cap_id = cur.lastrowid

    cur.execute(
        """INSERT INTO sessions
           (capture_id, stream_index, ip_src, ip_dst, port_src, port_dst,
            roles_established, syn_frame, first_frame, last_frame,
            start_time, end_time, packets_a2b, packets_b2a, bytes_a2b, bytes_b2a)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cap_id, 0, "10.0.0.1", "10.0.0.2", 12345, 8080,
         1, 1, 1, 2, 1.0, 2.0, 2, 0, 13, 0),
    )
    sid = cur.lastrowid

    cur.execute(
        """INSERT INTO directions
           (session_id, direction, stream_start_abs_seq, reassembled_bytes,
            gaps_json, ambiguities_json, overlap_policy)
           VALUES (?,?,?,?,?,?,?)""",
        (sid, "a_to_b", 1001, 13, "[]", "[]", "first_wins"),
    )
    did = cur.lastrowid

    big_payload = b"B" * 8192
    blob_sha = write_blob(project, big_payload)

    cur.execute(
        """INSERT INTO packets
           (direction_id, frame_number, abs_seq, tcp_len,
            flags_syn, flags_ack, flags_fin, flags_rst,
            payload_sha256, payload_inline, stream_offset)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (did, 2, 1001, 13, 0, 1, 0, 0, blob_sha, None, 0),
    )

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

    cur.execute(
        "INSERT INTO corpora (name, criteria_json) VALUES (?,?)",
        ("c1", json.dumps({"any_ports": [8080]})),
    )
    corpus_id = cur.lastrowid

    al_dir = project / "action_log"
    al_dir.mkdir(exist_ok=True)
    (al_dir / "test.entries.json").write_text("[]", encoding="utf-8")
    cur.execute(
        """INSERT INTO action_log
           (name, source_path, sha256, row_count, columns_json)
           VALUES (?,?,?,?,?)""",
        ("test", "action_log/test.entries.json", "deadbeef", 0, "[]"),
    )

    conn.commit()
    conn.close()
    return corpus_id, interp_id


def _check_project_consistent(project: Path) -> None:
    """Проверяет, что все ссылки на файлы в БД разрешаются."""
    conn = open_db(project)
    try:
        cur = conn.cursor()

        cur.execute("SELECT sha256, filename FROM captures")
        for row in cur.fetchall():
            pcap = project / "captures" / f"{row['sha256']}.pcap"
            assert pcap.exists(), f"missing capture: {pcap}"

        cur.execute(
            "SELECT payload_sha256 FROM packets WHERE payload_sha256 IS NOT NULL"
        )
        for row in cur.fetchall():
            sha = row["payload_sha256"]
            cur.execute(
                """SELECT payload_inline FROM packets
                   WHERE payload_sha256 = ? LIMIT 1""",
                (sha,),
            )
            inline = cur.fetchone()["payload_inline"]
            if inline is None:
                blob = project / "blobs" / f"{sha}.bin"
                assert blob.exists(), f"missing blob: {blob}"
    finally:
        conn.close()


def test_copy_preserves_project(tmp_path):
    """Проект открывается после копирования в другой каталог."""
    src = tmp_path / "src" / "proj"
    src.mkdir(parents=True)
    create_manifest(src)
    init_db(src)
    corpus_id, interp_id = _seed_project(src)

    _check_project_consistent(src)

    dst = tmp_path / "dst" / "proj_moved"
    shutil.copytree(src, dst)
    _safe_rmtree(src)

    _check_project_consistent(dst)

    m = load_manifest(dst)
    assert m["schema_version"] == 1

    from taptuna.verification import verify_corpus
    result = verify_corpus(
        project_dir=dst,
        corpus_id=corpus_id,
        interpretation_id=interp_id,
        seed=42,
    )
    assert result["run_hash"]
    assert len(result["run_hash"]) == 64


def test_run_hash_identical_after_move(tmp_path):
    """run_hash до и после переноса совпадает."""
    src = tmp_path / "src" / "proj"
    src.mkdir(parents=True)
    create_manifest(src)
    init_db(src)
    corpus_id, interp_id = _seed_project(src)

    from taptuna.verification import verify_corpus
    r1 = verify_corpus(src, corpus_id=corpus_id,
                       interpretation_id=interp_id, seed=42)

    dst = tmp_path / "dst" / "proj_moved"
    shutil.copytree(src, dst)
    _safe_rmtree(src)

    r2 = verify_corpus(dst, corpus_id=corpus_id,
                       interpretation_id=interp_id, seed=42)

    assert r1["run_hash"] == r2["run_hash"], (
        f"run_hash изменился после переноса:\n"
        f"  src: {r1['run_hash']}\n"
        f"  dst: {r2['run_hash']}"
    )


def test_blob_cas_survives_move(tmp_path):
    """Blob > 4 КиБ читается из нового каталога."""
    src = tmp_path / "src" / "proj"
    src.mkdir(parents=True)
    create_manifest(src)
    init_db(src)

    data = b"X" * 8192
    sha = write_blob(src, data)
    assert read_blob(src, sha) == data

    dst = tmp_path / "dst" / "proj_moved"
    shutil.copytree(src, dst)
    _safe_rmtree(src)

    assert read_blob(dst, sha) == data


def test_relative_paths_in_manifest(tmp_path):
    """В манифесте и БД нет абсолютных путей."""
    project = tmp_path / "proj"
    project.mkdir(parents=True)
    create_manifest(project)
    init_db(project)
    _seed_project(project)

    m = load_manifest(project)
    text = json.dumps(m)
    assert str(project) not in text, "manifest содержит абсолютный путь проекта"

    conn = open_db(project)
    try:
        cur = conn.cursor()
        cur.execute("SELECT source_path FROM action_log")
        for row in cur.fetchall():
            sp = row["source_path"]
            assert not sp.startswith("/"), f"абсолютный путь в action_log: {sp}"
    finally:
        conn.close()