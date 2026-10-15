"""Журнал действий (ТЗ §13).

Импорт из CSV/YAML, хранение в SQLite, связь с наблюдениями и сессиями.
Формат входа: список записей {ts, action, params, result}.

CSV: колонки ts, action, params_json, result_json.
YAML: список словарей с теми же полями (params/result как вложенные структуры).
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Optional

import yaml  # type: ignore

from .errors import ValidationError
from .store import open_db


# ---------------------------------------------------------------------------
# Парсинг
# ---------------------------------------------------------------------------

def _parse_ts(value: Any) -> float:
    """Преобразует ts в float (unix time). Принимает int/float/str."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            # ISO 8601 через datetime
            from datetime import datetime, timezone
            try:
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return dt.timestamp()
            except ValueError:
                raise ValidationError(
                    code="BAD_TS",
                    message=f"Cannot parse timestamp: {value!r}",
                    details={"value": value},
                )
    raise ValidationError(
        code="BAD_TS",
        message=f"Unsupported ts type: {type(value).__name__}",
        details={"value": value},
    )


def _parse_entry(entry: dict) -> dict:
    """Нормализует одну запись журнала."""
    if "ts" not in entry or "action" not in entry:
        raise ValidationError(
            code="BAD_ENTRY",
            message="Each entry must have 'ts' and 'action' fields",
            details={"entry": entry},
        )
    return {
        "ts": _parse_ts(entry["ts"]),
        "action": str(entry["action"]),
        "params": entry.get("params") or {},
        "result": entry.get("result") or {},
    }


def load_csv(path: Path) -> list[dict]:
    """Читает CSV с колонками ts, action, params_json, result_json."""
    entries: list[dict] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entry = {
                "ts": row.get("ts"),
                "action": row.get("action"),
                "params": json.loads(row["params_json"]) if row.get("params_json") else {},
                "result": json.loads(row["result_json"]) if row.get("result_json") else {},
            }
            entries.append(_parse_entry(entry))
    return entries


def load_yaml(path: Path) -> list[dict]:
    """Читает YAML: либо список записей, либо {entries: [...]}."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "entries" in raw:
        raw = raw["entries"]
    if not isinstance(raw, list):
        raise ValidationError(
            code="BAD_YAML",
            message="YAML must be a list of entries or {entries: [...]}",
            details={"type": type(raw).__name__},
        )
    return [_parse_entry(e) for e in raw]


def parse_action_log(path: Path) -> list[dict]:
    """Определяет формат по расширению и парсит."""
    path = Path(path)
    if not path.is_file():
        raise ValidationError(
            code="ACTION_LOG_NOT_FOUND",
            message=f"Action log file not found: {path}",
            details={"path": str(path)},
        )
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return load_csv(path)
    if suffix in (".yaml", ".yml"):
        return load_yaml(path)
    raise ValidationError(
        code="BAD_FORMAT",
        message=f"Unsupported action log format: {suffix}",
        details={"path": str(path), "suffix": suffix},
    )


# ---------------------------------------------------------------------------
# Импорт
# ---------------------------------------------------------------------------

def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def import_action_log(
    project_dir: Path,
    path: Path,
    name: Optional[str] = None,
    no_copy: bool = False,
) -> dict[str, Any]:
    """Импортирует журнал действий в проект.

    Args:
        project_dir: корень проекта taptuna.
        path: путь к CSV/YAML.
        name: имя импорта; по умолчанию — stem файла.
        no_copy: если True — не копировать файл в project/action_log/.

    Returns:
        {action_log_id, name, entries, sha256, source_path}
    """
    path = Path(path).resolve()
    entries = parse_action_log(path)
    sha = _file_sha256(path)

    project_dir = Path(project_dir)
    dest_dir = project_dir / "action_log"
    dest_dir.mkdir(parents=True, exist_ok=True)

    if no_copy:
        stored_path = str(path)
    else:
        dest = dest_dir / f"{sha}{path.suffix}"
        if not dest.exists():
            import shutil
            shutil.copy2(path, dest)
        stored_path = str(dest.relative_to(project_dir))

    entry_name = name or path.stem
    columns = sorted({k for e in entries for k in e.get("params", {}).keys()})

    conn = open_db(project_dir)
    try:
        cur = conn.cursor()
        # ← ИЗМЕНЕНО: теперь при повторном sha256 запись не создаётся
        # (UNIQUE-индекс), SELECT вернёт существующий id.
        cur.execute(
            """INSERT INTO action_log
               (name, source_path, sha256, row_count, columns_json)
               VALUES (?,?,?,?,?)
               ON CONFLICT(sha256) DO NOTHING""",
            (entry_name, stored_path, sha, len(entries),
             json.dumps(columns, ensure_ascii=False)),
        )
        conn.commit()

        cur.execute("SELECT id FROM action_log WHERE sha256 = ?", (sha,))
        row = cur.fetchone()
        if row is None:
            raise ValidationError(
                code="ACTION_LOG_INSERT_FAILED",
                message="Failed to insert action_log row",
                details={"sha256": sha},
            )
        action_log_id = row[0]

        # Сохраняем сами записи в файл рядом с проектом (в БД их не храним —
        # таблица action_log описывает импорт, а не сами действия).
        entries_path = dest_dir / f"{sha}.entries.json"
        entries_path.write_text(
            json.dumps(entries, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    finally:
        conn.close()

    return {
        "action_log_id": action_log_id,
        "name": entry_name,
        "entries": len(entries),
        "sha256": sha,
        "source_path": stored_path,
    }


# ---------------------------------------------------------------------------
# Чтение
# ---------------------------------------------------------------------------

def get_action_logs(conn) -> list[dict]:
    """Список импортированных журналов."""
    cur = conn.cursor()
    cur.execute("SELECT * FROM action_log ORDER BY id")
    return [dict(r) for r in cur.fetchall()]


def get_action_entries(project_dir: Path, action_log_id: int) -> list[dict]:
    """Читает записи конкретного журнала из файла."""
    project_dir = Path(project_dir)
    conn = open_db(project_dir)
    try:
        cur = conn.cursor()
        cur.execute("SELECT sha256 FROM action_log WHERE id = ?", (action_log_id,))
        row = cur.fetchone()
        if row is None:
            raise ValidationError(
                code="ACTION_LOG_NOT_FOUND",
                message=f"action_log_id={action_log_id} not found",
                details={"action_log_id": action_log_id},
            )
        sha = row[0]
    finally:
        conn.close()

    entries_path = project_dir / "action_log" / f"{sha}.entries.json"
    if not entries_path.exists():
        return []
    return json.loads(entries_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Связь с наблюдениями
# ---------------------------------------------------------------------------

def link_observation_to_action(
    conn,
    observation_id: int,
    action_log_id: int,
) -> None:
    """Связывает наблюдение с журналом действий.

    Используется, когда наблюдение получено при выполнении действия
    из журнала (например, при replay-анализе).
    """
    cur = conn.cursor()
    cur.execute(
        "UPDATE observations SET action_log_id = ? WHERE id = ?",
        (action_log_id, observation_id),
    )
    conn.commit()


def find_sessions_in_window(
    conn,
    ts_start: float,
    ts_end: float,
) -> list[dict]:
    """Находит сессии, активные в заданном интервале времени.

    Используется для наложения журнала действий на таймлайн:
    для каждого действия находим сессии, которые шли в этот момент.
    """
    cur = conn.cursor()
    cur.execute(
        """SELECT s.*, c.sha256 AS capture_sha256
           FROM sessions s
           JOIN captures c ON c.id = s.capture_id
           WHERE s.start_time <= ? AND s.end_time >= ?
           ORDER BY s.start_time""",
        (ts_end, ts_start),
    )
    return [dict(r) for r in cur.fetchall()]


def annotate_actions_with_sessions(
    conn,
    entries: list[dict],
    window: float = 0.5,
) -> list[dict]:
    """Обогащает записи журнала списком сессий, активных в момент действия.

    window — допуск в секундах вокруг ts (по умолчанию ±0.5с).
    """
    out: list[dict] = []
    for e in entries:
        ts = e["ts"]
        sessions = find_sessions_in_window(conn, ts - window, ts + window)
        e2 = dict(e)
        e2["sessions"] = [
            {
                "id": s["id"],
                "stream_index": s["stream_index"],
                "ip_src": s["ip_src"],
                "ip_dst": s["ip_dst"],
                "port_src": s["port_src"],
                "port_dst": s["port_dst"],
            }
            for s in sessions
        ]
        out.append(e2)
    return out