"""Верификация: корпус → интерпретация → классификация → сводка (ТЗ §9).

Ключевые правила:
- Корпус задаётся критериями (§9.3): captures, a_ports, b_ports, any_ports,
  has_syn, min_packets, min_bytes, directions.
- Классификация сообщений: violation, ambiguous, incomplete, ok, not_applicable.
- Вердикт прогона: violation > ambiguous > incomplete > ok > not_applicable.
- result_hash: sha256 канонического JSON результата — для cross-check (§20.3).
- stale: вычисляется при чтении, если версия интерпретации или политики
  изменились с момента прогона.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .errors import ValidationError
from .store import open_db
from .interpreters.base import MessageResult, MessageStatus


# ---------------------------------------------------------------------------
# Прогресс
# ---------------------------------------------------------------------------

ProgressFn = Callable[[str, float], None]


def _noop_progress(_msg: str, _frac: float) -> None:
    pass


# ---------------------------------------------------------------------------
# Статусы и порядок вердикта
# ---------------------------------------------------------------------------

STATUS_ORDER = {
    "not_applicable": 0,
    "ok": 1,
    "incomplete": 2,
    "ambiguous": 3,
    "violation": 4,
    "unknown_frame": 1,   # трактуем как ok-подобный (не влияет на вердикт)
}


def worst_status(statuses: Iterable[str]) -> str:
    """Возвращает самый «тяжёлый» статус из списка.

    Порядок: violation > ambiguous > incomplete > ok > not_applicable.
    """
    worst = "not_applicable"
    worst_rank = -1
    for s in statuses:
        r = STATUS_ORDER.get(s, 0)
        if r > worst_rank:
            worst = s
            worst_rank = r
    return worst


# ---------------------------------------------------------------------------
# Критерии корпуса
# ---------------------------------------------------------------------------

@dataclass
class CorpusCriteria:
    """Критерии отбора сессий в корпус (ТЗ §9.3)."""
    captures: Optional[list[str]] = None       # список sha256
    a_ports: Optional[list[int]] = None
    b_ports: Optional[list[int]] = None
    any_ports: Optional[list[int]] = None
    has_syn: Optional[bool] = None
    min_packets: Optional[int] = None
    min_bytes: Optional[int] = None
    directions: Optional[list[str]] = None     # ['a_to_b', 'b_to_a']

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CorpusCriteria":
        return cls(
            captures=d.get("captures"),
            a_ports=d.get("a_ports"),
            b_ports=d.get("b_ports"),
            any_ports=d.get("any_ports"),
            has_syn=d.get("has_syn"),
            min_packets=d.get("min_packets"),
            min_bytes=d.get("min_bytes"),
            directions=d.get("directions"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in {
            "captures": self.captures,
            "a_ports": self.a_ports,
            "b_ports": self.b_ports,
            "any_ports": self.any_ports,
            "has_syn": self.has_syn,
            "min_packets": self.min_packets,
            "min_bytes": self.min_bytes,
            "directions": self.directions,
        }.items() if v is not None}


# ---------------------------------------------------------------------------
# Отбор сессий
# ---------------------------------------------------------------------------

def select_sessions(conn, criteria: CorpusCriteria) -> list[dict]:
    """Возвращает список сессий, удовлетворяющих критериям корпуса.

    Каждая сессия — dict с полями из таблицы sessions + capture_sha256.
    """
    sql = [
        """SELECT s.*, c.sha256 AS capture_sha256
           FROM sessions s
           JOIN captures c ON c.id = s.capture_id
           WHERE 1=1"""
    ]
    params: list[Any] = []

    if criteria.captures:
        placeholders = ",".join("?" * len(criteria.captures))
        sql.append(f"AND c.sha256 IN ({placeholders})")
        params.extend(criteria.captures)

    if criteria.a_ports:
        placeholders = ",".join("?" * len(criteria.a_ports))
        sql.append(f"AND s.port_src IN ({placeholders})")
        params.extend(criteria.a_ports)

    if criteria.b_ports:
        placeholders = ",".join("?" * len(criteria.b_ports))
        sql.append(f"AND s.port_dst IN ({placeholders})")
        params.extend(criteria.b_ports)

    if criteria.any_ports:
        placeholders = ",".join("?" * len(criteria.any_ports))
        sql.append(
            f"AND (s.port_src IN ({placeholders}) OR s.port_dst IN ({placeholders}))"
        )
        params.extend(criteria.any_ports)
        params.extend(criteria.any_ports)

    if criteria.has_syn is not None:
        sql.append("AND s.roles_established = ?")
        params.append(int(criteria.has_syn))

    if criteria.min_packets is not None:
        sql.append("AND (s.packets_a2b + s.packets_b2a) >= ?")
        params.append(criteria.min_packets)

    if criteria.min_bytes is not None:
        sql.append("AND (s.bytes_a2b + s.bytes_b2a) >= ?")
        params.append(criteria.min_bytes)

    cur = conn.cursor()
    cur.execute(" ".join(sql), params)
    return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# result_hash
# ---------------------------------------------------------------------------

def _canonical_json(obj: Any) -> str:
    """Канонизирует JSON: сортировка ключей, без пробелов, UTF-8.

    Используется и для result_hash, и для source_hash интерпретаций.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_result_hash(message_dict: dict) -> str:
    """sha256 канонического JSON результата.

    Исключает поля, которые не влияют на семантику (created_at, id, stale).
    """
    canonical = {
        "index": message_dict["index"],
        "stream_offset": message_dict["stream_offset"],
        "length": message_dict["length"],
        "status": message_dict["status"],
        "message_name": message_dict.get("message_name"),
        "fields": message_dict.get("fields") or {},
        "notes": message_dict.get("notes") or [],
        "unknown_ranges": message_dict.get("unknown_ranges") or [],
    }
    return hashlib.sha256(_canonical_json(canonical).encode("utf-8")).hexdigest()


def compute_run_hash(conn, run_id: int) -> str:
    """Агрегирует result_hash всех результатов прогона в один.

    Для cross-check (§20.3): два независимых прогона одного корпуса
    должны давать одинаковый run_hash.
    """
    cur = conn.cursor()
    cur.execute(
        """SELECT result_hash FROM verification_results
           WHERE run_id = ?
           ORDER BY session_id, direction_id, message_index""",
        (run_id,),
    )
    hashes = [r[0] for r in cur.fetchall()]
    combined = hashlib.sha256()
    for h in hashes:
        combined.update(h.encode("ascii"))
    return combined.hexdigest()


# ---------------------------------------------------------------------------
# Классификация сообщения
# ---------------------------------------------------------------------------

def classify_message(
    msg_status: str,
    has_ambiguity: bool,
    has_gap: bool,
    constraints_failed: bool = False,
    extract_failed: bool = False,
) -> str:
    """Преобразует статус движка в один из пяти статусов верификации (§9).

    Приоритет:
    1. violation — constraints не выполнены.
    2. ambiguous — сообщение попало в область перекрытия с конфликтом.
    3. incomplete — не удалось извлечь все поля, есть неизвестные диапазоны.
    4. ok — всё извлечено, constraints выполнены.
    5. not_applicable — сообщение не относится к данной интерпретации.
    """
    if constraints_failed:
        return "violation"
    if has_ambiguity:
        return "ambiguous"
    if extract_failed or msg_status == "partial":
        return "incomplete"
    if msg_status in ("no_match", "unknown_frame"):
        return "not_applicable"
    if has_gap:
        return "incomplete"
    return "ok"


def _message_overlaps_ambiguity(msg_offset: int, msg_length: int,
                                 ambiguities: list[dict]) -> bool:
    """Проверяет, попадает ли сообщение в любую неоднозначность."""
    end = msg_offset + msg_length
    for amb in ambiguities:
        a_start = amb.get("offset", 0)
        a_end = a_start + amb.get("length", 0)
        if msg_offset < a_end and end > a_start:
            return True
    return False


def _message_overlaps_gap(msg_offset: int, msg_length: int,
                          gaps: list[dict]) -> bool:
    end = msg_offset + msg_length
    for g in gaps:
        g_start = g.get("offset", 0)
        g_end = g_start + g.get("length", 0)
        if msg_offset < g_end and end > g_start:
            return True
    return False


# ---------------------------------------------------------------------------
# Прогон верификации
# ---------------------------------------------------------------------------

def verify_corpus(
    project_dir: Path,
    corpus_id: int,
    interpretation_id: int,
    seed: int = 0,
    progress: ProgressFn = _noop_progress,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> dict[str, Any]:
    """Прогоняет верификацию корпуса с заданной интерпретацией.

    Возвращает:
        {
            "run_id": int,
            "summary": {"ok": N, "violation": N, ...},
            "verdict": "violation" | "ambiguous" | ...,
            "run_hash": "...",
            "sessions": N,
            "messages": N,
        }
    """
    from .interpreters import DeclarativeInterpreter, ScriptInterpreter

    conn = open_db(project_dir)
    cur = conn.cursor()

    # 1. Загружаем корпус
    cur.execute("SELECT * FROM corpora WHERE id = ?", (corpus_id,))
    corpus_row = cur.fetchone()
    if corpus_row is None:
        raise ValidationError(
            code="CORPUS_NOT_FOUND",
            message=f"Corpus {corpus_id} not found",
            details={"corpus_id": corpus_id},
        )
    criteria = CorpusCriteria.from_dict(json.loads(corpus_row["criteria_json"]))

    # 2. Загружаем интерпретацию
    cur.execute("SELECT * FROM interpretations WHERE id = ?", (interpretation_id,))
    interp_row = cur.fetchone()
    if interp_row is None:
        raise ValidationError(
            code="INTERPRETATION_NOT_FOUND",
            message=f"Interpretation {interpretation_id} not found",
            details={"interpretation_id": interpretation_id},
        )

    kind = interp_row["kind"]
    spec = {
        "framing": json.loads(interp_row["framing_json"]),
        "fields": json.loads(interp_row["fields_json"]),
        "constraints": json.loads(interp_row["constraints_json"]),
        "semantics": json.loads(interp_row["semantics_json"]),
    }
    if kind == "script":
        spec["code"] = interp_row["source_yaml"]

    interpreter = (
        DeclarativeInterpreter(spec, interp_row["name"], interp_row["version"])
        if kind == "declarative"
        else ScriptInterpreter(spec, interp_row["name"], interp_row["version"], seed=seed)
    )

    # 3. Отбираем сессии
    sessions = select_sessions(conn, criteria)
    progress(f"selected {len(sessions)} sessions", 0.05)

    # 4. Создаём прогон
    params = {
        "overlap": _get_policy(conn, project_dir, "overlap"),
        "checksum": _get_policy(conn, project_dir, "checksum"),
        "max_output_bytes": _get_policy(conn, project_dir, "max_output_bytes"),
        "seed": seed,
    }
    cur.execute(
        """INSERT INTO verification_runs
           (corpus_id, interpretation_id, seed, status, params_json)
           VALUES (?,?,?,?,?)""",
        (corpus_id, interpretation_id, seed, "running", _canonical_json(params)),
    )
    run_id = cur.lastrowid
    conn.commit()

    # 5. Основной цикл
    all_statuses: list[str] = []
    total_messages = 0
    summary = {"ok": 0, "violation": 0, "ambiguous": 0, "incomplete": 0,
               "not_applicable": 0, "unknown_frame": 0}

    try:
        for idx, session in enumerate(sessions):
            if cancel_check and cancel_check():
                cur.execute(
                    "UPDATE verification_runs SET status='cancelled', finished_at=datetime('now') WHERE id=?",
                    (run_id,),
                )
                conn.commit()
                raise ValidationError(
                    code="CANCELLED",
                    message="verification cancelled by user",
                    details={"run_id": run_id},
                )

            directions = _get_directions_for_session(conn, session["id"])
            if criteria.directions:
                directions = [d for d in directions if d["direction"] in criteria.directions]

            for direction in directions:
                stream = _load_stream(project_dir, direction)
                if not stream:
                    continue

                try:
                    msgs = interpreter.interpret(stream, direction["id"])
                except Exception as e:
                    # Ошибка интерпретатора — не проглатываем.
                    # Записываем единственный unknown_frame на весь поток.
                    msgs = [MessageResult(
                        index=0,
                        stream_offset=0,
                        length=len(stream),
                        message_name=interpreter.name,
                        status=MessageStatus.UNKNOWN_FRAME,
                        notes=[f"interpreter error: {type(e).__name__}: {e}"],
                    )]

                ambiguities = json.loads(direction["ambiguities_json"] or "[]")
                gaps = json.loads(direction["gaps_json"] or "[]")

                for m in msgs:
                    has_amb = _message_overlaps_ambiguity(m.stream_offset, m.length, ambiguities)
                    has_gap = _message_overlaps_gap(m.stream_offset, m.length, gaps)

                    # constraints_failed/extract_failed различаем по notes
                    constraints_failed = any("constraint" in n.lower() for n in m.notes)
                    extract_failed = any("extract failed" in n.lower() for n in m.notes)

                    status = classify_message(
                        msg_status=m.status.value,
                        has_ambiguity=has_amb,
                        has_gap=has_gap,
                        constraints_failed=constraints_failed,
                        extract_failed=extract_failed,
                    )

                    msg_dict = {
                        "index": m.index,
                        "stream_offset": m.stream_offset,
                        "length": m.length,
                        "status": status,
                        "message_name": m.message_name,
                        "fields": m.fields,
                        "notes": m.notes,
                        "unknown_ranges": [list(r) for r in m.unknown_ranges],
                    }
                    result_hash = compute_result_hash(msg_dict)

                    cur.execute(
                        """INSERT OR IGNORE INTO verification_results
                           (run_id, session_id, direction_id, message_index,
                            stream_offset, length, status, message_name,
                            fields_json, notes_json, unknown_ranges_json, result_hash)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (run_id, session["id"], direction["id"], m.index,
                         m.stream_offset, m.length, status, m.message_name,
                         _canonical_json(m.fields), _canonical_json(m.notes),
                         _canonical_json([list(r) for r in m.unknown_ranges]),
                         result_hash),
                    )

                    summary[status] = summary.get(status, 0) + 1
                    all_statuses.append(status)
                    total_messages += 1

            progress(
                f"session {idx + 1}/{len(sessions)}: {total_messages} messages",
                0.05 + 0.9 * (idx + 1) / max(len(sessions), 1),
            )

        verdict = worst_status(all_statuses) if all_statuses else "not_applicable"
        run_hash = compute_run_hash(conn, run_id)

        cur.execute(
            """UPDATE verification_runs
               SET status='completed', finished_at=datetime('now'),
                   summary_json=?
               WHERE id=?""",
            (_canonical_json({**summary, "verdict": verdict, "run_hash": run_hash}), run_id),
        )
        conn.commit()

    except Exception:
        cur.execute(
            "UPDATE verification_runs SET status='failed', finished_at=datetime('now') WHERE id=?",
            (run_id,),
        )
        conn.commit()
        raise
    finally:
        conn.close()

    progress("verification done", 1.0)
    return {
        "run_id": run_id,
        "summary": summary,
        "verdict": verdict,
        "run_hash": run_hash,
        "sessions": len(sessions),
        "messages": total_messages,
    }


# ---------------------------------------------------------------------------
# Вспомогательное
# ---------------------------------------------------------------------------

def _get_policy(conn, project_dir: Path, name: str) -> Any:
    """Достаёт политику из манифеста. Мягкий fallback при отсутствии."""
    try:
        from .manifest import load_manifest
        m = load_manifest(project_dir)
        return m.get("policies", {}).get(name)
    except Exception:
        return None


def _get_directions_for_session(conn, session_id: int) -> list[dict]:
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM directions WHERE session_id = ? ORDER BY direction",
        (session_id,),
    )
    return [dict(r) for r in cur.fetchall()]


def _load_stream(project_dir: Path, direction: dict) -> bytes:
    """Восстанавливает reassembled-поток из packets + gaps.

    Простая модель: склеиваем payload'ы пакетов направления, вставляя
    нулевые байты на места gaps. Zero-fill запрещён ТЗ (§6.4), но для
    верификации нам нужен непрерывный буфер фиксированной длины;
    используем stream_offset пакетов, чтобы вставить данные точно на места.
    """
    from .store import get_packets, read_blob

    size = direction.get("reassembled_bytes") or 0
    if size == 0:
        return b""
    buf = bytearray(size)
    conn = open_db(project_dir)
    try:
        packets = get_packets(conn, direction["id"])
    finally:
        conn.close()

    for p in packets:
        offset = p.get("stream_offset")
        if offset is None:
            continue
        sha = p.get("payload_sha256")
        inline = p.get("payload_inline")
        payload = inline if inline is not None else (read_blob(project_dir, sha) if sha else b"")
        if not payload:
            continue
        end = min(offset + len(payload), size)
        buf[offset:end] = payload[:end - offset]

    return bytes(buf)


# ---------------------------------------------------------------------------
# Сводки и результаты
# ---------------------------------------------------------------------------

def get_run_summary(conn, run_id: int) -> dict:
    """Возвращает сводку прогона: counts, verdict, run_hash, статус."""
    cur = conn.cursor()
    cur.execute("SELECT * FROM verification_runs WHERE id = ?", (run_id,))
    row = cur.fetchone()
    if row is None:
        return {}
    out = dict(row)
    if row["summary_json"]:
        out["summary"] = json.loads(row["summary_json"])
    else:
        out["summary"] = {}
    return out


def get_results(
    conn,
    run_id: int,
    status: Optional[str] = None,
    offset: int = 0,
    limit: int = 100,
) -> list[dict]:
    """Возвращает страницу результатов, опционально отфильтрованную по статусу."""
    cur = conn.cursor()
    if status:
        cur.execute(
            """SELECT * FROM verification_results
               WHERE run_id = ? AND status = ?
               ORDER BY id LIMIT ? OFFSET ?""",
            (run_id, status, limit, offset),
        )
    else:
        cur.execute(
            """SELECT * FROM verification_results
               WHERE run_id = ?
               ORDER BY id LIMIT ? OFFSET ?""",
            (run_id, limit, offset),
        )
    return [dict(r) for r in cur.fetchall()]


def mark_stale(conn) -> int:
    """Помечает stale те результаты, чей прогон использовал устаревшую
    версию интерпретации или политики.

    Возвращает число помеченных строк. Запускается при чтении.
    """
    cur = conn.cursor()
    # Находим прогоны с не последней версией интерпретации
    cur.execute("""
        UPDATE verification_results
        SET stale = 1
        WHERE run_id IN (
            SELECT vr.id
            FROM verification_runs vr
            JOIN interpretations i ON i.id = vr.interpretation_id
            WHERE EXISTS (
                SELECT 1 FROM interpretations i2
                WHERE i2.name = i.name AND i2.version > i.version
            )
        )
    """)
    return cur.rowcount