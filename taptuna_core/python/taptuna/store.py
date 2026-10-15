"""SQLite store: connection, PRAGMA user_version, migrations.

Schema v1 (ТЗ §14): 14 tables + indexes.
"""

from __future__ import annotations

import sqlite3
import hashlib
from pathlib import Path


SCHEMA_VERSION = 4

# --- DDL: 14 tables from ТЗ §14 ---

DDL_TABLES = [
    # captures — исходные записи трафика (read-only, sha256)
    """
    CREATE TABLE IF NOT EXISTS captures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sha256 TEXT NOT NULL UNIQUE,
        filename TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        packet_count INTEGER NOT NULL,
        tshark_version TEXT NOT NULL,
        ingested_at TEXT NOT NULL DEFAULT (datetime('now')),
        notes TEXT
    )
    """,

    # sessions — TCP-сессии (5-tuple, один экземпляр соединения)
    """
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        capture_id INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
        stream_index INTEGER NOT NULL,
        ip_src TEXT NOT NULL,
        ip_dst TEXT NOT NULL,
        port_src INTEGER NOT NULL,
        port_dst INTEGER NOT NULL,
        roles_established BOOLEAN NOT NULL DEFAULT 0,
        syn_frame INTEGER,
        first_frame INTEGER NOT NULL,
        last_frame INTEGER NOT NULL,
        start_time REAL NOT NULL,
        end_time REAL NOT NULL,
        packets_a2b INTEGER NOT NULL DEFAULT 0,
        packets_b2a INTEGER NOT NULL DEFAULT 0,
        bytes_a2b INTEGER NOT NULL DEFAULT 0,
        bytes_b2a INTEGER NOT NULL DEFAULT 0,
        UNIQUE(capture_id, stream_index)
    )
    """,

    # directions — направленные потоки (a_to_b, b_to_a)
    """
    CREATE TABLE IF NOT EXISTS directions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        direction TEXT NOT NULL CHECK (direction IN ('a_to_b', 'b_to_a')),
        stream_start_abs_seq INTEGER NOT NULL,
        reassembled_bytes INTEGER NOT NULL DEFAULT 0,
        gaps_json TEXT NOT NULL DEFAULT '[]',      -- JSON: [{offset, length, frames[]}, ...]
        ambiguities_json TEXT NOT NULL DEFAULT '[]', -- JSON: [{offset, length, frames[], policy}, ...]
        overlap_policy TEXT NOT NULL DEFAULT 'first_wins',
        CHECK (direction IN ('a_to_b', 'b_to_a')),
        UNIQUE(session_id, direction)
    )
    """,

    # stream_segments — непрерывные сегменты после reassembly
    """
    CREATE TABLE IF NOT EXISTS stream_segments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        direction_id INTEGER NOT NULL REFERENCES directions(id) ON DELETE CASCADE,
        stream_offset INTEGER NOT NULL,        -- offset от stream_start
        length INTEGER NOT NULL,
        abs_seq_start INTEGER NOT NULL,
        abs_seq_end INTEGER NOT NULL,          -- inclusive
        status TEXT NOT NULL CHECK (status IN ('clean', 'overlap', 'gap_before')),
        first_frame INTEGER NOT NULL,
        last_frame INTEGER NOT NULL
    )
    """,

    # packets — исходные пакеты tshark (для byte_map и point-lookup)
    """
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        direction_id INTEGER NOT NULL REFERENCES directions(id) ON DELETE CASCADE,
        frame_number INTEGER NOT NULL,
        abs_seq INTEGER NOT NULL,
        tcp_len INTEGER NOT NULL,
        flags_syn BOOLEAN NOT NULL DEFAULT 0,
        flags_ack BOOLEAN NOT NULL DEFAULT 0,
        flags_fin BOOLEAN NOT NULL DEFAULT 0,
        flags_rst BOOLEAN NOT NULL DEFAULT 0,
        payload_sha256 TEXT,                   -- SHA256 payload, для CAS > 4KiB
        payload_inline BLOB,                   -- inline payload ≤ 4KiB
        stream_offset INTEGER,                 -- offset в reassembled потоке (NULL если gap/overlap)
        UNIQUE(direction_id, frame_number)
    )
    """,

    # interpretations — интерпретации (YAML/JSON, версии immutable)
    """
    CREATE TABLE IF NOT EXISTS interpretations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        version INTEGER NOT NULL,
        parent_id INTEGER REFERENCES interpretations(id),
        schema_version INTEGER NOT NULL DEFAULT 1,
        kind TEXT NOT NULL CHECK (kind IN ('declarative', 'script')),
        source_yaml TEXT NOT NULL,
        source_hash TEXT NOT NULL,             -- sha256 канонизированного YAML
        framing_json TEXT NOT NULL,            -- нормализованный framing блок
        fields_json TEXT NOT NULL,             -- нормализованный fields блок
        constraints_json TEXT NOT NULL,        -- нормализованный constraints блок
        semantics_json TEXT NOT NULL,          -- нормализованный semantics блок
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(name, version)
    )
    """,

    # corpora — корпуса для проверки
    """
    CREATE TABLE IF NOT EXISTS corpora (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        criteria_json TEXT NOT NULL,           -- критерии отбора (captures, ports, etc.)
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,

    # verification_runs — прогоны проверки
    """
    CREATE TABLE IF NOT EXISTS verification_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        corpus_id INTEGER NOT NULL REFERENCES corpora(id) ON DELETE CASCADE,
        interpretation_id INTEGER NOT NULL REFERENCES interpretations(id) ON DELETE CASCADE,
        seed INTEGER NOT NULL DEFAULT 0,
        started_at TEXT NOT NULL DEFAULT (datetime('now')),
        finished_at TEXT,
        status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'cancelled', 'failed')),
        summary_json TEXT,                     -- сводка: ok/violation/ambiguous/incomplete/na counts
        params_json TEXT NOT NULL,             -- снапшот политик (overlap, checksum, etc.)
        error_message TEXT
    )
    """,

    # verification_results — результаты по сообщениям
    """
    CREATE TABLE IF NOT EXISTS verification_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL REFERENCES verification_runs(id) ON DELETE CASCADE,
        session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        direction_id INTEGER NOT NULL REFERENCES directions(id) ON DELETE CASCADE,
        message_index INTEGER NOT NULL,
        stream_offset INTEGER NOT NULL,
        length INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('ok', 'violation', 'ambiguous', 'incomplete', 'not_applicable', 'unknown_frame')),
        message_name TEXT,
        fields_json TEXT,                      -- извлечённые поля
        notes_json TEXT,                       -- примечания движка
        unknown_ranges_json TEXT,              -- неизвестные диапазоны
        result_hash TEXT NOT NULL,             -- sha256 канонического JSON результата
        stale BOOLEAN NOT NULL DEFAULT 0,      -- вычисляется при чтении
        UNIQUE(run_id, session_id, direction_id, message_index)
    )
    """,

    # observations — наблюдения (то, что видно в байтах)
    """
    CREATE TABLE IF NOT EXISTS observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_type TEXT NOT NULL CHECK (target_type IN ('session', 'direction', 'message', 'range')),
        target_id INTEGER NOT NULL,
        description TEXT NOT NULL,
        byte_range_start INTEGER,
        byte_range_end INTEGER,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        action_log_id INTEGER REFERENCES action_log(id)
    )
    """,

    # hypotheses — гипотезы о назначении
    """
    CREATE TABLE IF NOT EXISTS hypotheses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        formulation TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('open', 'supported', 'refuted', 'superseded')),
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,

    # hypothesis_observations — связи гипотеза ↔ наблюдения
    """
    CREATE TABLE IF NOT EXISTS hypothesis_observations (
        hypothesis_id INTEGER NOT NULL REFERENCES hypotheses(id) ON DELETE CASCADE,
        observation_id INTEGER NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK (role IN ('evidence', 'counterexample', 'context')),
        PRIMARY KEY (hypothesis_id, observation_id)
    )
    """,

    # action_log — журнал действий
    """
    CREATE TABLE IF NOT EXISTS action_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        source_path TEXT,                      -- путь к CSV/YAML (ref-режим: относительный)
        sha256 TEXT,                           -- sha256 файла
        row_count INTEGER NOT NULL DEFAULT 0,
        columns_json TEXT NOT NULL,            -- список колонок
        imported_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,

    # meta — ключ-значение для служебных данных проекта
    """
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
]

# --- Indexes from ТЗ §14 ---

DDL_INDEXES = [
    # verification_results
    "CREATE INDEX IF NOT EXISTS idx_vres_run_status ON verification_results(run_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_vres_run_id ON verification_results(run_id, id)",

    # sessions
    "CREATE INDEX IF NOT EXISTS idx_sessions_capture_stream ON sessions(capture_id, stream_index)",

    # interpretations
    "CREATE INDEX IF NOT EXISTS idx_interp_name_version ON interpretations(name, version DESC)",

    # stream_segments
    "CREATE INDEX IF NOT EXISTS idx_seg_dir_offset ON stream_segments(direction_id, stream_offset)",

    # observations
    "CREATE INDEX IF NOT EXISTS idx_obs_target ON observations(target_type, target_id)",

    # Additional useful indexes
    "CREATE INDEX IF NOT EXISTS idx_directions_session ON directions(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_packets_direction ON packets(direction_id)",
    "CREATE INDEX IF NOT EXISTS idx_verification_runs_corpus ON verification_runs(corpus_id)",
    "CREATE INDEX IF NOT EXISTS idx_verification_runs_interp ON verification_runs(interpretation_id)",
]

# --- Migration 2: executable hypotheses (ТЗ §9) ---
#
# Гипотеза = safe-eval выражение, вычисляемое на извлечённых полях
# сообщения. Результаты проверки сохраняются в hypothesis_checks.
DDL_V2 = [
    # Добавляем поля в hypotheses
    "ALTER TABLE hypotheses ADD COLUMN expression_json TEXT",
    "ALTER TABLE hypotheses ADD COLUMN expression_text TEXT",
    "ALTER TABLE hypotheses ADD COLUMN interpretation_id INTEGER REFERENCES interpretations(id)",
    "ALTER TABLE hypotheses ADD COLUMN scope_json TEXT",
    "ALTER TABLE hypotheses ADD COLUMN auto_status TEXT",
    "ALTER TABLE hypotheses ADD COLUMN checked_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE hypotheses ADD COLUMN satisfied_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE hypotheses ADD COLUMN violated_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE hypotheses ADD COLUMN error_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE hypotheses ADD COLUMN last_check_at TEXT",

    # Таблица результатов проверки
    """
    CREATE TABLE IF NOT EXISTS hypothesis_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hypothesis_id INTEGER NOT NULL REFERENCES hypotheses(id) ON DELETE CASCADE,
        session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        direction_id INTEGER NOT NULL REFERENCES directions(id) ON DELETE CASCADE,
        message_index INTEGER,
        stream_offset INTEGER,
        length INTEGER,
        result TEXT NOT NULL CHECK (result IN ('satisfied', 'violated', 'not_applicable', 'error')),
        fields_json TEXT,
        notes TEXT,
        checked_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_hyp_checks_hyp_result ON hypothesis_checks(hypothesis_id, result)",
    "CREATE INDEX IF NOT EXISTS idx_hyp_checks_hyp_id ON hypothesis_checks(hypothesis_id, id)",
]

# --- Migration 3: source of constraints as text (для редактора) ---
#
# constraints_json хранит AST. Чтобы редактор мог показать исходные
# строки, которые ввёл пользователь, сохраняем их отдельно.
DDL_V3 = [
    "ALTER TABLE interpretations ADD COLUMN constraints_text_json TEXT",
]

# --- Migration 4: связи гипотез с наблюдениями, заметки, stale ---
DDL_V4 = [
    # Заметки исследователя и точные счётчики
    "ALTER TABLE hypotheses ADD COLUMN notes TEXT",
    "ALTER TABLE hypotheses ADD COLUMN not_applicable_count INTEGER NOT NULL DEFAULT 0",

    # stale для устаревших проверок гипотез (новая версия интерпретации)
    "ALTER TABLE hypothesis_checks ADD COLUMN stale BOOLEAN NOT NULL DEFAULT 0",
    "CREATE INDEX IF NOT EXISTS idx_hyp_checks_stale ON hypothesis_checks(stale)",
]

def get_db(project_dir: Path) -> sqlite3.Connection:
    """Открывает соединение с project.sqlite в каталоге проекта.
    Включает foreign_keys и row_factory.
    """
    db_path = project_dir / "project.sqlite"
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def get_user_version(conn: sqlite3.Connection) -> int:
    """Возвращает PRAGMA user_version."""
    row = conn.execute("PRAGMA user_version").fetchone()
    return row[0] if row else 0

# --- CAS (Content-Addressed Storage) ---

def write_blob(project_dir: Path, data: bytes) -> str:
    """Записывает blob в blobs/.bin, возвращает sha256.
    Если blob уже существует — не перезаписывает."""
    sha = hashlib.sha256(data).hexdigest()
    blobs_dir = project_dir / "blobs"
    blobs_dir.mkdir(parents=True, exist_ok=True)
    path = blobs_dir / f"{sha}.bin"
    if not path.exists():
        path.write_bytes(data)
    return sha

def read_blob(project_dir: Path, sha: str) -> bytes:
    """Читает blob по sha256. Поднимает FileNotFoundError, если нет."""
    path = project_dir / "blobs" / f"{sha}.bin"
    if not path.exists():
        raise FileNotFoundError(f"Blob not found: {sha}")
    return path.read_bytes()

# --- Captures ---

def insert_capture(conn, sha256, filename, file_size, packet_count,
                   tshark_version, notes=None) -> int:
    """Возвращает capture_id. При повторном sha256 — возвращает существующий id
    и НЕ перезаписывает (ТЗ §10: повторный импорт — явное предупреждение)."""
    cur = conn.cursor()
    cur.execute(
        """INSERT OR IGNORE INTO captures
           (sha256, filename, file_size, packet_count, tshark_version, notes)
           VALUES (?,?,?,?,?,?)""",
        (sha256, filename, file_size, packet_count, tshark_version, notes),
    )
    conn.commit()
    cur.execute("SELECT id FROM captures WHERE sha256 = ?", (sha256,))
    return cur.fetchone()[0]

def get_capture_by_sha(conn, sha256: str) -> dict | None:
    cur = conn.cursor()
    cur.execute("SELECT * FROM captures WHERE sha256 = ?", (sha256,))
    row = cur.fetchone()
    return dict(row) if row else None

# --- Sessions / Directions / Packets ---

def insert_session(conn, capture_id, stream_index, ip_src, ip_dst,
                   port_src, port_dst, roles_established, syn_frame,
                   first_frame, last_frame, start_time, end_time,
                   packets_a2b, packets_b2a, bytes_a2b, bytes_b2a) -> int:
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO sessions
           (capture_id, stream_index, ip_src, ip_dst, port_src, port_dst,
            roles_established, syn_frame, first_frame, last_frame,
            start_time, end_time, packets_a2b, packets_b2a, bytes_a2b, bytes_b2a)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (capture_id, stream_index, ip_src, ip_dst, port_src, port_dst,
         int(roles_established), syn_frame, first_frame, last_frame,
         start_time, end_time, packets_a2b, packets_b2a, bytes_a2b, bytes_b2a),
    )
    conn.commit()
    return cur.lastrowid

def insert_direction(conn, session_id, direction, stream_start_abs_seq,
                     reassembled_bytes, gaps_json, ambiguities_json,
                     overlap_policy) -> int:
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO directions
           (session_id, direction, stream_start_abs_seq, reassembled_bytes,
            gaps_json, ambiguities_json, overlap_policy)
           VALUES (?,?,?,?,?,?,?)""",
        (session_id, direction, stream_start_abs_seq, reassembled_bytes,
         gaps_json, ambiguities_json, overlap_policy),
    )
    conn.commit()
    return cur.lastrowid

def insert_stream_segment(conn, direction_id, stream_offset, length,
                          abs_seq_start, abs_seq_end, status,
                          first_frame, last_frame) -> int:
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO stream_segments
           (direction_id, stream_offset, length, abs_seq_start, abs_seq_end,
            status, first_frame, last_frame)
           VALUES (?,?,?,?,?,?,?,?)""",
        (direction_id, stream_offset, length, abs_seq_start, abs_seq_end,
         status, first_frame, last_frame),
    )
    conn.commit()
    return cur.lastrowid

def insert_packet(conn, direction_id, frame_number, abs_seq, tcp_len,
                  flags_syn, flags_ack, flags_fin, flags_rst,
                  payload_sha256, payload_inline, stream_offset) -> int:
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO packets
           (direction_id, frame_number, abs_seq, tcp_len,
            flags_syn, flags_ack, flags_fin, flags_rst,
            payload_sha256, payload_inline, stream_offset)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (direction_id, frame_number, abs_seq, tcp_len,
         int(flags_syn), int(flags_ack), int(flags_fin), int(flags_rst),
         payload_sha256, payload_inline, stream_offset),
    )
    conn.commit()
    return cur.lastrowid

# --- Query helpers ---

def get_sessions(conn, capture_id: int) -> list[dict]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM sessions WHERE capture_id = ? ORDER BY stream_index",
                (capture_id,))
    return [dict(r) for r in cur.fetchall()]

def get_directions(conn, session_id: int) -> list[dict]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM directions WHERE session_id = ?", (session_id,))
    return [dict(r) for r in cur.fetchall()]

def get_packets(conn, direction_id: int) -> list[dict]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM packets WHERE direction_id = ? ORDER BY frame_number",
                (direction_id,))
    return [dict(r) for r in cur.fetchall()]

def get_stream_segments(conn, direction_id: int) -> list[dict]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM stream_segments WHERE direction_id = ? ORDER BY stream_offset",
                (direction_id,))
    return [dict(r) for r in cur.fetchall()]

def set_user_version(conn: sqlite3.Connection, version: int) -> None:
    """Устанавливает PRAGMA user_version."""
    conn.execute(f"PRAGMA user_version = {version}")


def migrate(db_path: Path) -> int:
    """Запускает миграции до SCHEMA_VERSION.
    Возвращает итоговый user_version.
    """
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")

    current = get_user_version(conn)

    if current >= SCHEMA_VERSION:
        conn.close()
        return current

    # Миграция 1: создание всех таблиц и индексов
    if current == 0:
        for ddl in DDL_TABLES:
            conn.execute(ddl)
        for ddl in DDL_INDEXES:
            conn.execute(ddl)
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
        set_user_version(conn, 1)
        conn.commit()
        current = 1   # ← обновляем локальную переменную

    # Миграция 2
    if current == 1:
        for ddl in DDL_V2:
            conn.execute(ddl)
        conn.execute(
            "UPDATE hypotheses SET auto_status = 'unknown' WHERE auto_status IS NULL"
        )
        set_user_version(conn, 2)
        conn.commit()
        current = 2
    
    if current == 2:
        for ddl in DDL_V3:
            conn.execute(ddl)
        set_user_version(conn, 3)
        conn.commit()
        current = 3

    if current == 3:
        for ddl in DDL_V4:
            conn.execute(ddl)
        set_user_version(conn, 4)
        conn.commit()
        current = 4

    # Будущие миграции добавлять здесь как elif current == 1: ...

    final = get_user_version(conn)
    conn.close()
    return final


def init_db(project_dir: Path) -> sqlite3.Connection:
    """Инициализирует БД проекта: создаёт файл, запускает миграции.
    Возвращает открытое соединение.
    """
    project_dir.mkdir(parents=True, exist_ok=True)
    db_path = project_dir / "project.sqlite"
    migrate(db_path)
    return get_db(project_dir)


def open_db(project_dir: Path) -> sqlite3.Connection:
    """Открывает существующую БД проекта и применяет недостающие миграции.

    Если проект создан старой версией taptuna — миграция выполнится
    прозрачно при первом обращении. Проверка через PRAGMA user_version:
    если версия актуальна — второй connection не открывается.
    """
    db_path = project_dir / "project.sqlite"
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    conn = get_db(project_dir)
    try:
        current = get_user_version(conn)
    except Exception:
        current = 0
    if current >= SCHEMA_VERSION:
        return conn

    # Версия устарела — закрываем, мигрируем, открываем заново
    conn.close()
    migrate(db_path)
    return get_db(project_dir)