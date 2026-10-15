"""REST API + SSE (ТЗ §15).

Формат ошибок: {"error": {"code": "...", "message": "...", "details": {...}}}
Все долгие операции (ingest, verify, generate_report) — через jobs (§15).
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

import tempfile
import shutil
from werkzeug.utils import secure_filename

from flask import Blueprint, Flask, Response, jsonify, request, current_app

from .action_log import (
    get_action_entries,
    get_action_logs,
    import_action_log,
)
from .errors import ProtocolLabError, ValidationError
from .ingest import ingest_capture
from .jobs import JobCancelled, JobState, get_job_manager, sse_stream
from .manifest import create_manifest, load_manifest, update_manifest
from .reports import generate_report, list_reports
from .store import (
    get_db,
    get_directions,
    get_packets,
    get_sessions,
    get_stream_segments,
    init_db,
    open_db,
    read_blob,
)
from .verification import (
    CorpusCriteria,
    get_results,
    get_run_summary,
    select_sessions,
    verify_corpus,
    worst_status,
)


# ---------------------------------------------------------------------------
# Хелперы
# ---------------------------------------------------------------------------

# Реестр открытых проектов: project_id -> Path. Singleton в памяти.
_PROJECTS: dict[str, Path] = {}


def _error(code: str, message: str, http_status: int = 400,
           details: Optional[dict] = None) -> Response:
    return jsonify({"error": {
        "code": code,
        "message": message,
        "details": details or {},
    }}), http_status


def _ok(data: Any, status: int = 200) -> Response:
    return jsonify(data), status


def _get_project(project_id: str) -> Path:
    """Возвращает каталог проекта.

    Если project_id совпадает с дефолтным проектом из app.config —
    возвращает его. Иначе ищет в реестре, пополняемом через
    POST /projects.
    """
    default = current_app.config.get("PROJECT_DIR")
    if default is not None:
        default = Path(default)
        # Совпадение по имени каталога
        if default.name == project_id:
            return default
    p = _PROJECTS.get(project_id)
    if p is None:
        raise ValidationError(
            code="PROJECT_NOT_FOUND",
            message=f"Project {project_id} not found",
            details={"project_id": project_id},
        )
    return p


def _body() -> dict:
    return request.get_json(silent=True) or {}


# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

bp = Blueprint("taptuna", __name__)


# --- Projects ---

@bp.route("/projects", methods=["POST"])
def api_create_project():
    body = _body()
    project_dir = body.get("path")
    if not project_dir:
        return _error("MISSING_PATH", "Field 'path' is required")
    project_path = Path(project_dir).resolve()
    project_path.mkdir(parents=True, exist_ok=True)

    if not (project_path / "manifest.json").exists():
        create_manifest(project_path)
    init_db(project_path)

    project_id = body.get("project_id") or project_path.name
    _PROJECTS[project_id] = project_path

    # Если в конфиге проекта ещё нет — привязываем этот
    if current_app.config.get("PROJECT_DIR") is None:
        current_app.config["PROJECT_DIR"] = project_path

    return _ok({
        "project_id": project_id,
        "path": str(project_path),
        "manifest": load_manifest(project_path),
    }, 201)

@bp.route("/projects", methods=["GET"])
def api_list_projects():
    """Список проектов в реестре + дефолтный из конфига."""
    out: list[dict] = []
    seen: set[str] = set()

    default = current_app.config.get("PROJECT_DIR")
    if default is not None:
        default = Path(default)
        seen.add(default.name)
        out.append({
            "project_id": default.name,
            "path": str(default),
            "is_default": True,
        })

    for pid, path in _PROJECTS.items():
        if pid in seen:
            continue
        out.append({
            "project_id": pid,
            "path": str(path),
            "is_default": False,
        })
    return _ok({"projects": out})


# --- Ingest (job-based) ---

@bp.route("/projects/<project_id>/upload", methods=["POST"])
def api_upload_capture(project_id: str):
    """Загрузка PCAP через multipart/form-data и запуск ingest через job.

    Принимает form-data с полем 'file'. Файл сохраняется во временный
    каталог; ingest_capture сам решает, копировать его в project/captures/
    (no_copy=False, по умолчанию) или ссылаться по абсолютному пути.
    Временный каталог удаляется после завершения job'а.

    Возвращает {job_id, state, filename, size} — прогресс через SSE.
    """
    p = _get_project(project_id)

    if "file" not in request.files:
        return _error("MISSING_FILE", "form field 'file' is required")
    f = request.files["file"]
    if not f.filename:
        return _error("EMPTY_FILENAME", "uploaded file has no name")

    suffix = Path(f.filename).suffix.lower()
    if suffix not in (".pcap", ".pcapng", ".cap"):
        return _error(
            "BAD_EXTENSION",
            f"expected .pcap / .pcapng / .cap, got {suffix!r}",
            details={"filename": f.filename},
        )

    # Сохраняем во временный каталог
    tmpdir = Path(tempfile.mkdtemp(prefix="taptuna_upload_"))
    safe_name = secure_filename(f.filename) or f"upload{suffix}"
    tmp_path = tmpdir / safe_name
    f.save(str(tmp_path))

    size = tmp_path.stat().st_size
    if size == 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return _error("EMPTY_FILE", "uploaded file is empty")

    no_copy = request.form.get("no_copy", "false").lower() in ("1", "true", "yes")

    mgr = get_job_manager()

    def worker(job):
        def _progress(msg: str, frac: float) -> None:
            if job.is_cancelled():
                raise JobCancelled()
            job.progress(msg, frac)

        try:
            return ingest_capture(
                project_dir=p,
                input_path=tmp_path,
                no_copy=no_copy,
                progress=_progress,
                cancel_check=lambda: job.is_cancelled(),
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    job = mgr.run("ingest", worker, params={
        "project_id": project_id,
        "filename": f.filename,
        "size": size,
        "source": "upload",
    })

    return _ok({
        "job_id": job.id,
        "state": job.state.value,
        "filename": f.filename,
        "size": size,
    }, 202)

@bp.route("/projects/<project_id>/captures", methods=["POST"])
def api_ingest_capture(project_id: str):
    p = _get_project(project_id)
    body = _body()
    input_path = body.get("input_path")
    if not input_path:
        return _error("MISSING_INPUT", "'input_path' is required")
    no_copy = bool(body.get("no_copy", False))

    mgr = get_job_manager()

    def worker(job):
        def _progress(msg: str, frac: float) -> None:
            if job.is_cancelled():
                raise JobCancelled()
            job.progress(msg, frac)

        def _cancel_check() -> bool:
            return job.is_cancelled()

        result = ingest_capture(
            project_dir=p,
            input_path=Path(input_path),
            no_copy=no_copy,
            progress=_progress,
            cancel_check=_cancel_check,
        )
        return result

    job = mgr.run("ingest", worker, params={
        "project_id": project_id,
        "input_path": input_path,
        "no_copy": no_copy,
    })
    return _ok({"job_id": job.id, "state": job.state.value}, 202)


@bp.route("/projects/<project_id>/captures", methods=["GET"])
def api_list_captures(project_id: str):
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM captures ORDER BY id")
        return _ok({"captures": [dict(r) for r in cur.fetchall()]})
    finally:
        conn.close()


# --- Sessions / packets ---

@bp.route("/captures/<int:capture_id>/sessions", methods=["GET"])
def api_capture_sessions(capture_id: int):
    project_id = request.args.get("project_id")
    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' query param required")
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        sessions = get_sessions(conn, capture_id)
        return _ok({"sessions": sessions})
    finally:
        conn.close()

@bp.route("/sessions/<int:session_id>/byte-info", methods=["GET"])
def api_byte_info(session_id: int):
    """Возвращает информацию о пакете, из которого пришёл байт.

    Query params:
        project_id
        direction: a_to_b | b_to_a
        offset:    offset в reassembled потоке

    Ответ:
        {
            "offset": N,
            "packet": {frame_number, abs_seq, tcp_len, stream_offset,
                       flags_*, payload_sha256} | null,
        }
    """
    project_id = request.args.get("project_id")
    direction = request.args.get("direction")
    offset = int(request.args.get("offset", "0"))

    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' required")
    if direction not in ("a_to_b", "b_to_a"):
        return _error("BAD_DIRECTION", "direction must be a_to_b or b_to_a")

    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM directions WHERE session_id = ? AND direction = ?",
            (session_id, direction),
        )
        drow = cur.fetchone()
        if drow is None:
            return _error("DIRECTION_NOT_FOUND", "direction not found", 404)
        direction_id = drow["id"]

        # Ищем пакет, чей диапазон [stream_offset, stream_offset+tcp_len)
        # содержит offset.
        cur.execute(
            """SELECT frame_number, abs_seq, tcp_len, stream_offset,
                      flags_syn, flags_ack, flags_fin, flags_rst,
                      payload_sha256
               FROM packets
               WHERE direction_id = ?
                 AND stream_offset IS NOT NULL
                 AND stream_offset <= ?
                 AND stream_offset + tcp_len > ?
               LIMIT 1""",
            (direction_id, offset, offset),
        )
        row = cur.fetchone()
        packet = dict(row) if row is not None else None
        return _ok({"offset": offset, "packet": packet})
    finally:
        conn.close()

@bp.route("/captures/<int:capture_id>/packets/<int:frame>", methods=["GET"])
def api_point_lookup_packet(capture_id: int, frame: int):
    """Быстрый поиск пакета по номеру кадра.

    Возвращает packet + метаданные сессии/направления, чтобы UI мог
    сразу перейти к нужному месту потока. Point-lookup вне hot-path,
    отдельный запрос по требованию (ТЗ §15).
    """
    project_id = request.args.get("project_id")
    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' query param required")
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT p.*, d.direction, d.session_id, s.stream_index,
                      s.ip_src, s.ip_dst, s.port_src, s.port_dst
               FROM packets p
               JOIN directions d ON d.id = p.direction_id
               JOIN sessions s ON s.id = d.session_id
               WHERE s.capture_id = ? AND p.frame_number = ?
               LIMIT 1""",
            (capture_id, frame),
        )
        row = cur.fetchone()
        if row is None:
            return _error("PACKET_NOT_FOUND",
                          f"frame {frame} not found in capture {capture_id}",
                          404)
        return _ok({"packet": dict(row)})
    finally:
        conn.close()

@bp.route("/sessions/<int:session_id>", methods=["GET"])
def api_get_session(session_id: int):
    project_id = request.args.get("project_id")
    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' query param required")
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        session = cur.fetchone()
        if session is None:
            return _error("SESSION_NOT_FOUND", f"Session {session_id} not found", 404)
        directions = get_directions(conn, session_id)
        return _ok({"session": dict(session), "directions": directions})
    finally:
        conn.close()

@bp.route("/sessions/<int:session_id>/framing-preview", methods=["POST"])
def api_framing_preview(session_id: int):
    """Применяет framing-стратегию к потоку сессии и возвращает границы сообщений.

    Тело: {"project_id": "...", "direction": "a_to_b", "framing": {...}}
    Ответ: {"messages": [{"index", "offset", "length", "hex_head"}],
             "total_bytes", "framing_error"}
    """
    body = _body()
    project_id = body.get("project_id")
    direction = body.get("direction", "a_to_b")
    framing = body.get("framing") or {}

    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' required")
    if direction not in ("a_to_b", "b_to_a"):
        return _error("BAD_DIRECTION", "direction must be a_to_b or b_to_a")

    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM directions WHERE session_id = ? AND direction = ?",
            (session_id, direction),
        )
        drow = cur.fetchone()
        if drow is None:
            return _error("DIRECTION_NOT_FOUND", "direction not found", 404)
        drow = dict(drow)
    finally:
        conn.close()

    # Загружаем поток
    from .verification import _load_stream
    stream = _load_stream(p, drow)
    if not stream:
        return _ok({"messages": [], "total_bytes": 0, "framing_error": None})

    # Применяем framing
    from . import native as _nat
    if not _nat.HAS_NATIVE or _nat._native is None:
        return _error("NO_NATIVE", "framing требует native core", 503)

    try:
        out = _nat._native.framing.frame_stream(stream, framing)
    except Exception as e:
        return _ok({
            "messages": [],
            "total_bytes": len(stream),
            "framing_error": str(e),
            "framing_error_type": type(e).__name__,
        })

    messages = []
    for idx, m in enumerate(out["messages"]):
        # PyO3 отдаёт Vec<u8> как list[int]; приводим к bytes
        raw = bytes(m["bytes"]) if not isinstance(m["bytes"], (bytes, bytearray)) else m["bytes"]
        head = raw[:32].hex()
        messages.append({
            "index": idx,
            "offset": m["offset"],
            "length": m["length"],
            "hex_head": head,
            "hex_head_len": min(32, len(raw)),
        })

    return _ok({
        "messages": messages,
        "total_bytes": len(stream),
        "leftover_bytes": len(out.get("leftover", b"")),
        "framing_error": None,
    })

@bp.route("/sessions/<int:session_id>/stream/<direction>", methods=["GET"])
def api_get_stream(session_id: int, direction: str):
    project_id = request.args.get("project_id")
    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' query param required")
    if direction not in ("a_to_b", "b_to_a"):
        return _error("BAD_DIRECTION", "direction must be a_to_b or b_to_a")

    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM directions WHERE session_id = ? AND direction = ?",
            (session_id, direction),
        )
        d = cur.fetchone()
        if d is None:
            return _error("DIRECTION_NOT_FOUND", "direction not found", 404)
        d = dict(d)
        # Мета без байт
        return _ok({
            "direction": d,
            "gaps": json.loads(d["gaps_json"] or "[]"),
            "ambiguities": json.loads(d["ambiguities_json"] or "[]"),
            "segments": get_stream_segments(conn, d["id"]),
        })
    finally:
        conn.close()


@bp.route("/sessions/<int:session_id>/stream/<direction>/bytes", methods=["GET"])
def api_get_stream_bytes(session_id: int, direction: str):
    """Возвращает reassembled байты направления (или диапазон)."""
    project_id = request.args.get("project_id")
    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' query param required")
    if direction not in ("a_to_b", "b_to_a"):
        return _error("BAD_DIRECTION", "direction must be a_to_b or b_to_a")

    offset = int(request.args.get("offset", 0))
    length = int(request.args.get("length", 65536))

    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM directions WHERE session_id = ? AND direction = ?",
            (session_id, direction),
        )
        d = cur.fetchone()
        if d is None:
            return _error("DIRECTION_NOT_FOUND", "direction not found", 404)
        d = dict(d)
        size = d.get("reassembled_bytes") or 0
        packets = get_packets(conn, d["id"])

        buf = bytearray(size)
        for pkt in packets:
            pkt_offset = pkt.get("stream_offset")
            if pkt_offset is None:
                continue
            sha = pkt.get("payload_sha256")
            inline = pkt.get("payload_inline")
            payload = inline if inline is not None else (
                read_blob(p, sha) if sha else b""
            )
            if not payload:
                continue
            end = min(pkt_offset + len(payload), size)
            buf[pkt_offset:end] = payload[:end - pkt_offset]

        chunk = bytes(buf[offset:offset + length])
        return Response(chunk, mimetype="application/octet-stream")
    finally:
        conn.close()


@bp.route("/sessions/<int:session_id>/packets", methods=["GET"])
def api_session_packets(session_id: int):
    project_id = request.args.get("project_id")
    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' query param required")
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        directions = get_directions(conn, session_id)
        all_packets: list[dict] = []
        for d in directions:
            for pkt in get_packets(conn, d["id"]):
                # payload_inline — BLOB (bytes), Flask 3.x не сериализует его
                # в JSON. Заменяем на длину + sha256 (клиенту этого достаточно).
                inline = pkt.pop("payload_inline", None)
                pkt["payload_inline_len"] = len(inline) if inline is not None else 0
                all_packets.append(pkt)
        all_packets.sort(key=lambda x: x["frame_number"])
        return _ok({"packets": all_packets})
    finally:
        conn.close()


# --- Interpretations ---

@bp.route("/projects/<project_id>/interpretations", methods=["GET"])
def api_list_interpretations(project_id: str):
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT id, name, version, kind, source_hash, created_at
               FROM interpretations ORDER BY name, version DESC"""
        )
        return _ok({"interpretations": [dict(r) for r in cur.fetchall()]})
    finally:
        conn.close()

@bp.route("/interpretations/<int:interpretation_id>/apply", methods=["POST"])
def api_apply_interpretation(interpretation_id: int):
    """Применить интерпретацию к конкретной сессии/направлению.

    Тело: {project_id, session_id, direction}
    Возвращает список распознанных сообщений (не сохраняет — preview).
    """
    body = _body()
    project_id = body.get("project_id")
    session_id = body.get("session_id")
    direction = body.get("direction", "a_to_b")

    if not project_id or session_id is None:
        return _error("MISSING_FIELDS", "project_id and session_id are required")
    if direction not in ("a_to_b", "b_to_a"):
        return _error("BAD_DIRECTION", "direction must be a_to_b or b_to_a")

    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()

        # Загружаем интерпретацию
        cur.execute("SELECT * FROM interpretations WHERE id = ?",
                    (interpretation_id,))
        row = cur.fetchone()
        if row is None:
            return _error("NOT_FOUND", "interpretation not found", 404)
        interp = dict(row)

        # Направление
        cur.execute(
            "SELECT * FROM directions WHERE session_id = ? AND direction = ?",
            (session_id, direction),
        )
        drow = cur.fetchone()
        if drow is None:
            return _error("DIRECTION_NOT_FOUND", "direction not found", 404)
        drow = dict(drow)

        # Загружаем stream
        from .verification import _load_stream
        stream = _load_stream(p, drow)
        if not stream:
            return _ok({"messages": [], "note": "empty stream"})

        # Собираем спеку
        spec = {
            "framing": json.loads(interp["framing_json"] or "{}"),
            "fields": json.loads(interp["fields_json"] or "{}"),
            "constraints": json.loads(interp["constraints_json"] or "[]"),
            "semantics": json.loads(interp["semantics_json"] or "{}"),
        }
        if interp["kind"] == "script":
            spec["code"] = interp["source_yaml"]

        # Интерпретатор
        from .interpreters import DeclarativeInterpreter, ScriptInterpreter
        interp_obj = (
            DeclarativeInterpreter(spec, interp["name"], interp["version"])
            if interp["kind"] == "declarative"
            else ScriptInterpreter(spec, interp["name"], interp["version"])
        )

        msgs = interp_obj.interpret(stream, drow["id"])
        return _ok({
            "interpretation_id": interpretation_id,
            "session_id": session_id,
            "direction": direction,
            "messages": [m.to_dict() for m in msgs],
        })
    finally:
        conn.close()

@bp.route("/projects/<project_id>/interpretations", methods=["POST"])
def api_add_interpretation(project_id: str):
    """Добавляет интерпретацию. Тело: {name, kind, source_yaml,
    framing, fields, constraints, semantics}."""
    import hashlib
    p = _get_project(project_id)
    body = _body()

    name = body.get("name")
    kind = body.get("kind")
    if not name or not kind:
        return _error("MISSING_FIELDS", "'name' and 'kind' are required")
    if kind not in ("declarative", "script"):
        return _error("BAD_KIND", "kind must be declarative or script")

    source_yaml = body.get("source_yaml", "")
    source_hash = hashlib.sha256(source_yaml.encode("utf-8")).hexdigest()

    # Если блоки не переданы отдельно — попробуем распарсить source_yaml
    framing_obj = body.get("framing")
    fields_obj = body.get("fields")
    constraints_obj = body.get("constraints")
    semantics_obj = body.get("semantics")

    if (framing_obj is None and fields_obj is None and source_yaml.strip()):
        import yaml as _yaml  # type: ignore
        try:
            parsed = _yaml.safe_load(source_yaml) or {}
            if isinstance(parsed, dict):
                framing_obj = parsed.get("framing") or {}
                fields_obj = parsed.get("fields") or {}
                constraints_obj = parsed.get("constraints") or []
                semantics_obj = parsed.get("semantics") or {}
                # Для script-интерпретаций: user code лежит в поле code
                if kind == "script" and isinstance(parsed.get("code"), str):
                    pass  # source_yaml и так хранит код целиком
        except Exception as e:
            return _error("BAD_YAML", f"YAML parse error: {e}",
                          details={"source_yaml_head": source_yaml[:200]})

    framing = json.dumps(framing_obj or {})
    fields = json.dumps(fields_obj or {})
    constraints = json.dumps(constraints_obj or [])
    semantics = json.dumps(semantics_obj or {})

    # Базовая валидация: framing обязателен и должен содержать 'kind'
    if not framing_obj or not isinstance(framing_obj, dict) or "kind" not in framing_obj:
        return _error(
            "BAD_FRAMING",
            "framing spec must be a dict with 'kind' field; "
            "проверьте YAML или передайте framing явно",
            details={"framing": framing_obj},
        )

    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute("SELECT MAX(version) FROM interpretations WHERE name = ?", (name,))
        row = cur.fetchone()
        version = (row[0] or 0) + 1
        cur.execute(
            """INSERT INTO interpretations
               (name, version, kind, source_yaml, source_hash,
                framing_json, fields_json, constraints_json, semantics_json)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (name, version, kind, source_yaml, source_hash,
             framing, fields, constraints, semantics),
        )
        conn.commit()
        return _ok({"id": cur.lastrowid, "name": name, "version": version}, 201)
    finally:
        conn.close()


@bp.route("/interpretations/<int:interpretation_id>", methods=["GET"])
def api_get_interpretation(interpretation_id: int):
    project_id = request.args.get("project_id")
    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' query param required")
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM interpretations WHERE id = ?", (interpretation_id,))
        row = cur.fetchone()
        if row is None:
            return _error("NOT_FOUND", "interpretation not found", 404)
        return _ok({"interpretation": dict(row)})
    finally:
        conn.close()


# --- Corpora ---

@bp.route("/projects/<project_id>/corpora", methods=["GET"])
def api_list_corpora(project_id: str):
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM corpora ORDER BY id")
        return _ok({"corpora": [dict(r) for r in cur.fetchall()]})
    finally:
        conn.close()

@bp.route("/corpora/<int:corpus_id>", methods=["GET"])
def api_get_corpus(corpus_id: int):
    project_id = request.args.get("project_id")
    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' query param required")
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM corpora WHERE id = ?", (corpus_id,))
        row = cur.fetchone()
        if row is None:
            return _error("NOT_FOUND", "corpus not found", 404)
        return _ok({"corpus": dict(row)})
    finally:
        conn.close()

@bp.route("/projects/<project_id>/corpora/<int:corpus_id>", methods=["DELETE"])
def api_delete_corpus(project_id: str, corpus_id: int):
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM corpora WHERE id = ?", (corpus_id,))
        if cur.fetchone() is None:
            return _error("NOT_FOUND", "corpus not found", 404)
        cur.execute("DELETE FROM corpora WHERE id = ?", (corpus_id,))
        conn.commit()
        return _ok({"deleted": corpus_id})
    finally:
        conn.close()

@bp.route("/projects/<project_id>/corpora", methods=["POST"])
def api_create_corpus(project_id: str):
    p = _get_project(project_id)
    body = _body()
    name = body.get("name")
    criteria = body.get("criteria") or {}
    if not name:
        return _error("MISSING_NAME", "'name' is required")
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO corpora (name, criteria_json) VALUES (?,?)",
            (name, json.dumps(criteria, ensure_ascii=False)),
        )
        conn.commit()
        return _ok({"id": cur.lastrowid, "name": name}, 201)
    finally:
        conn.close()


@bp.route("/projects/<project_id>/corpora/<int:corpus_id>/preview", methods=["POST"])
def api_preview_corpus(project_id: str, corpus_id: int):
    """Показывает, сколько сессий попадёт в корпус по критериям."""
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM corpora WHERE id = ?", (corpus_id,))
        row = cur.fetchone()
        if row is None:
            return _error("NOT_FOUND", "corpus not found", 404)
        criteria = CorpusCriteria.from_dict(json.loads(row["criteria_json"]))
        sessions = select_sessions(conn, criteria)
        return _ok({
            "corpus_id": corpus_id,
            "matched_sessions": len(sessions),
            "sample": sessions[:10],
        })
    finally:
        conn.close()


# --- Verification ---

@bp.route("/projects/<project_id>/verify", methods=["POST"])
def api_verify(project_id: str):
    p = _get_project(project_id)
    body = _body()
    corpus_id = body.get("corpus_id")
    interpretation_id = body.get("interpretation_id")
    seed = int(body.get("seed", 0))

    if not corpus_id or not interpretation_id:
        return _error("MISSING_FIELDS", "corpus_id and interpretation_id are required")

    mgr = get_job_manager()

    def worker(job):
        def _progress(msg: str, frac: float) -> None:
            if job.is_cancelled():
                raise JobCancelled()
            job.progress(msg, frac)

        return verify_corpus(
            project_dir=p,
            corpus_id=int(corpus_id),
            interpretation_id=int(interpretation_id),
            seed=seed,
            progress=_progress,
            cancel_check=lambda: job.is_cancelled(),
        )

    job = mgr.run("verify", worker, params={
        "project_id": project_id,
        "corpus_id": corpus_id,
        "interpretation_id": interpretation_id,
        "seed": seed,
    })
    return _ok({"job_id": job.id, "state": job.state.value}, 202)

@bp.route("/verification_runs", methods=["GET"])
def api_list_verification_runs():
    """Список прогонов верификации с фильтрацией.

    Query params:
        project_id (обязательно)
        corpus_id (опционально)
        status (опционально): running|completed|cancelled|failed
        offset, limit (пагинация)
    """
    project_id = request.args.get("project_id")
    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' query param required")
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        sql = "SELECT * FROM verification_runs WHERE 1=1"
        params: list = []
        corpus_id = request.args.get("corpus_id")
        if corpus_id:
            sql += " AND corpus_id = ?"
            params.append(int(corpus_id))
        status = request.args.get("status")
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.append(int(request.args.get("limit", 50)))
        params.append(int(request.args.get("offset", 0)))

        cur = conn.cursor()
        cur.execute(sql, params)
        return _ok({"runs": [dict(r) for r in cur.fetchall()]})
    finally:
        conn.close()

@bp.route("/verification_runs/<int:run_id>", methods=["GET"])
def api_get_run(run_id: int):
    project_id = request.args.get("project_id")
    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' query param required")
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        summary = get_run_summary(conn, run_id)
        if not summary:
            return _error("NOT_FOUND", f"run {run_id} not found", 404)
        return _ok({"run": summary})
    finally:
        conn.close()


@bp.route("/verification_runs/<int:run_id>/results", methods=["GET"])
def api_get_run_results(run_id: int):
    project_id = request.args.get("project_id")
    if not project_id:
        return _error("MISSING_PROJECT", "'project_id' query param required")
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        status = request.args.get("status")
        offset = int(request.args.get("offset", 0))
        limit = int(request.args.get("limit", 100))
        results = get_results(conn, run_id, status=status, offset=offset, limit=limit)
        return _ok({"results": results})
    finally:
        conn.close()


# --- Observations / hypotheses ---

@bp.route("/projects/<project_id>/observations", methods=["GET"])
def api_list_observations(project_id: str):
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM observations ORDER BY id")
        return _ok({"observations": [dict(r) for r in cur.fetchall()]})
    finally:
        conn.close()


@bp.route("/projects/<project_id>/observations", methods=["POST"])
def api_create_observation(project_id: str):
    p = _get_project(project_id)
    body = _body()
    target_type = body.get("target_type")
    target_id = body.get("target_id")
    description = body.get("description")
    if not target_type or target_id is None or not description:
        return _error("MISSING_FIELDS",
                      "target_type, target_id, description required")
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO observations
               (target_type, target_id, description,
                byte_range_start, byte_range_end, action_log_id)
               VALUES (?,?,?,?,?,?)""",
            (target_type, int(target_id), description,
             body.get("byte_range_start"), body.get("byte_range_end"),
             body.get("action_log_id")),
        )
        conn.commit()
        return _ok({"id": cur.lastrowid}, 201)
    finally:
        conn.close()


@bp.route("/projects/<project_id>/hypotheses", methods=["GET"])
def api_list_hypotheses(project_id: str):
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM hypotheses ORDER BY id")
        return _ok({"hypotheses": [dict(r) for r in cur.fetchall()]})
    finally:
        conn.close()


@bp.route("/projects/<project_id>/hypotheses", methods=["POST"])
def api_create_hypothesis(project_id: str):
    p = _get_project(project_id)
    body = _body()
    formulation = body.get("formulation")
    if not formulation:
        return _error("MISSING_FORMULATION", "'formulation' required")
    status = body.get("status", "open")
    conn = open_db(p)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO hypotheses (formulation, status) VALUES (?,?)",
            (formulation, status),
        )
        conn.commit()
        return _ok({"id": cur.lastrowid, "status": status}, 201)
    finally:
        conn.close()


# --- Action log ---

@bp.route("/projects/<project_id>/action_log", methods=["GET"])
def api_list_action_log(project_id: str):
    p = _get_project(project_id)
    conn = open_db(p)
    try:
        return _ok({"action_logs": get_action_logs(conn)})
    finally:
        conn.close()


@bp.route("/projects/<project_id>/action_log", methods=["POST"])
def api_import_action_log(project_id: str):
    p = _get_project(project_id)
    body = _body()
    path = body.get("path")
    if not path:
        return _error("MISSING_PATH", "'path' is required")
    try:
        result = import_action_log(
            project_dir=p,
            path=Path(path),
            name=body.get("name"),
            no_copy=bool(body.get("no_copy", False)),
        )
        return _ok(result, 201)
    except ProtocolLabError as e:
        return _error(e.code, e.message, getattr(e, "http_status", 400), e.details)

@bp.route("/projects/<project_id>/action_log/<int:log_id>/entries", methods=["GET"])
def api_action_log_entries(project_id: str, log_id: int):
    """Возвращает записи журнала.

    Query params:
        with_sessions=1 — обогатить каждую запись списком сессий,
                          активных в момент действия (± window секунд).
        window=0.5      — допуск в секундах (по умолчанию 0.5).
        limit=500       — максимум записей (по умолчанию 500).
    """
    from .action_log import get_action_entries, annotate_actions_with_sessions

    p = _get_project(project_id)
    with_sessions = request.args.get("with_sessions", "0") in ("1", "true", "yes")
    window = float(request.args.get("window", "0.5"))
    limit = int(request.args.get("limit", "500"))

    try:
        entries = get_action_entries(p, log_id)
    except Exception as e:
        return _error("ENTRIES_LOAD_FAILED", str(e), 404)

    if not entries:
        return _ok({"entries": [], "total": 0})

    total = len(entries)
    entries = entries[:limit]

    if with_sessions:
        conn = open_db(p)
        try:
            entries = annotate_actions_with_sessions(conn, entries, window=window)
        finally:
            conn.close()

    return _ok({"entries": entries, "total": total, "window": window})

# --- Reports ---

@bp.route("/projects/<project_id>/reports", methods=["GET"])
def api_list_reports(project_id: str):
    p = _get_project(project_id)
    return _ok({"reports": list_reports(p)})


@bp.route("/projects/<project_id>/reports", methods=["POST"])
def api_generate_report(project_id: str):
    p = _get_project(project_id)
    body = _body()
    run_id = body.get("run_id")
    formats = tuple(body.get("formats", ["md", "html", "json"]))

    mgr = get_job_manager()

    def worker(job):
        return generate_report(
            project_dir=p,
            run_id=int(run_id) if run_id is not None else None,
            formats=formats,
            progress=lambda msg, frac: (
                job.progress(msg, frac) if not job.is_cancelled()
                else (_ for _ in ()).throw(JobCancelled())
            ),
        )

    job = mgr.run("report", worker, params={
        "project_id": project_id, "run_id": run_id, "formats": list(formats),
    })
    return _ok({"job_id": job.id, "state": job.state.value}, 202)


# --- Jobs ---

@bp.route("/jobs", methods=["GET"])
def api_list_jobs():
    mgr = get_job_manager()
    kind = request.args.get("kind")
    state_str = request.args.get("state")
    state = JobState(state_str) if state_str else None
    jobs = mgr.list(kind=kind, state=state)
    return _ok({"jobs": [j.to_dict() for j in jobs]})


@bp.route("/jobs/<job_id>", methods=["GET"])
def api_get_job(job_id: str):
    mgr = get_job_manager()
    job = mgr.get(job_id)
    if job is None:
        return _error("JOB_NOT_FOUND", f"job {job_id} not found", 404)
    return _ok(job.to_dict())


@bp.route("/jobs/<job_id>/events", methods=["GET"])
def api_job_events(job_id: str):
    mgr = get_job_manager()
    job = mgr.get(job_id)
    if job is None:
        return _error("JOB_NOT_FOUND", f"job {job_id} not found", 404)

    def _generate():
        for chunk in sse_stream(job):
            yield chunk

    return Response(
        _generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@bp.route("/jobs/<job_id>/cancel", methods=["POST"])
def api_cancel_job(job_id: str):
    mgr = get_job_manager()
    ok = mgr.cancel(job_id)
    if not ok:
        return _error("CANCEL_FAILED",
                      f"job {job_id} not cancellable or not found", 404)
    return _ok({"cancelled": True})

@bp.route("/projects/<project_id>", methods=["GET"])
def api_get_project(project_id: str):
    p = _get_project(project_id)
    manifest_path = p / "manifest.json"
    if not manifest_path.exists():
        return _error(
            "PROJECT_NOT_INITIALIZED",
            f"Project {project_id} has no manifest.json — "
            f"run POST /api/projects or `taptuna init`",
            409,
            details={"path": str(p)},
        )
    return _ok({
        "project_id": project_id,
        "path": str(p),
        "manifest": load_manifest(p),
    })
# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(ProtocolLabError)
    def _handle_lab_error(e: ProtocolLabError):
        return jsonify({"error": {
            "code": e.code,
            "message": e.message,
            "details": e.details,
        }}), getattr(e, "http_status", 400)

    @app.errorhandler(ValidationError)
    def _handle_validation(e: ValidationError):
        return jsonify({"error": {
            "code": e.code,
            "message": e.message,
            "details": e.details,
        }}), 400

    @app.errorhandler(404)
    def _handle_404(_e):
        return jsonify({"error": {
            "code": "NOT_FOUND",
            "message": "Endpoint not found",
            "details": {},
        }}), 404

    @app.errorhandler(FileNotFoundError)
    def _handle_fnf(e: FileNotFoundError):
        return jsonify({"error": {
            "code": "FILE_NOT_FOUND",
            "message": str(e),
            "details": {},
        }}), 404

    @app.errorhandler(500)
    def _handle_500(e):
        import traceback
        return jsonify({"error": {
            "code": "INTERNAL_ERROR",
            "message": str(e),
            "details": {"traceback": traceback.format_exc()},
        }}), 500


def register_routes(app: Flask) -> None:
    app.register_blueprint(bp)
    register_error_handlers(app)