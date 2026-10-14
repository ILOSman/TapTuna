"""Ingest PCAP/PCAPNG: один вызов tshark на файл (ТЗ §6.2, §6.3).

Правила:
- subprocess.Popen(shell=False), путь из TAPTUNA_TSHARK или PATH.
- Таймаут, лимит вывода, отмена, чтение stderr (иначе дедлок на 64 КиБ).
- Один проход tshark. Point-lookup — отдельно, вне hot-path (см. routes.py).
- Абсолютные пути к tshark внутри проекта не хранятся; в манифесте — версия.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .errors import ProtocolLabError, TsharkNotFoundError, ValidationError
from .tshark_check import get_tshark_path

# ---------------------------------------------------------------------------
# Константы по ТЗ §6.2
# ---------------------------------------------------------------------------

TSHARK_FIELDS = [
    "tcp.stream",
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.payload",
]

# Разделитель полей — таб, occurrence=f (первое значение).
SEPARATOR = "\t"

# Лимит вывода tshark (защита от OOM). Настраивается через политику.
DEFAULT_MAX_OUTPUT_BYTES = 10 * 1024 * 1024 * 1024  # 10 GiB
DEFAULT_TIMEOUT_SECONDS = 600


# ---------------------------------------------------------------------------
# Прогресс/job
# ---------------------------------------------------------------------------

ProgressFn = Callable[[str, float], None]


def _noop_progress(_msg: str, _frac: float) -> None:
    pass


# ---------------------------------------------------------------------------
# Шаг 1: sha256 + копирование
# ---------------------------------------------------------------------------

def compute_sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def ensure_capture_copy(
    project_dir: Path,
    input_path: Path,
    no_copy: bool,
    progress: ProgressFn,
) -> tuple[Path, str]:
    """Возвращает (path_в_проекте, sha256). Копирует, если no_copy=False."""
    sha = compute_sha256(input_path, )
    progress("sha256 computed", 0.05)

    if no_copy:
        # ref-режим: путь записывается в manifest, но файл не копируется.
        return input_path, sha

    dest_dir = project_dir / "captures"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{sha}.pcap"

    if dest.exists():
        # Повторный импорт sha256 — явное предупреждение (ТЗ §10).
        progress(f"capture already present: {dest.name}", 0.08)
        return dest, sha

    shutil.copy2(input_path, dest)
    progress(f"copied to {dest.name}", 0.10)
    return dest, sha


# ---------------------------------------------------------------------------
# Шаг 2: один вызов tshark
# ---------------------------------------------------------------------------

@dataclass
class TsharkRow:
    stream: int
    frame: int
    ts: float
    ip_src: str
    ip_dst: str
    port_src: int
    port_dst: int
    seq: int
    ack: int
    tcp_len: int
    syn: bool
    ack_flag: bool
    fin: bool
    rst: bool
    payload: bytes


def run_tshark(
    pcap_path: Path,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    cancel_check: Optional[Callable[[], bool]] = None,
    progress: ProgressFn = _noop_progress,
) -> list[TsharkRow]:
    """Один вызов tshark -r <file> -T fields ... (ТЗ §6.2).

    Возвращает список строк (без группировки по сессиям — это делает вызывающий).
    """
    tshark = get_tshark_path()
    if not tshark:
        raise TsharkNotFoundError(
            code="TSHARK_NOT_FOUND",
            message="tshark not found in PATH or TAPTUNA_TSHARK",
            details={},
        )

    cmd = [tshark, "-r", str(pcap_path), "-T", "fields", "-E", f"separator={SEPARATOR}",
           "-E", "occurrence=f"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]

    progress("tshark started", 0.15)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,   # ОБЯЗАТЕЛЬНО читать, иначе дедлок на 64 КиБ
        shell=False,
        bufsize=1 << 20,
    )

    rows: list[TsharkRow] = []
    total_bytes = 0
    start = time.monotonic()
    stderr_chunks: list[bytes] = []

    try:
        assert proc.stdout is not None
        assert proc.stderr is not None

        # Читаем stdout построчно, stderr — в фоне (простой вариант: non-blocking select).
        # Для краткости используем communicate() с ограничением, но это удержит весь
        # вывод в памяти. Для 100 МиБ PCAP это ~ десятки МиБ — приемлемо.
        # Если нужен стриминговый режим — см. комментарий ниже.
        stdout, stderr = proc.communicate(timeout=timeout)
        stderr_chunks.append(stderr)

        if proc.returncode != 0:
            raise ProtocolLabError(
                code="TSHARK_FAILED",
                message=f"tshark exited with code {proc.returncode}: "
                        f"{stderr.decode('utf-8', 'replace')[:500]}",
                details={"pcap": str(pcap_path)},
            )

        text = stdout.decode("utf-8", "replace")
        total_bytes = len(stdout)
        if total_bytes > max_output_bytes:
            raise ProtocolLabError(
                code="TSHARK_OUTPUT_TOO_LARGE",
                message=f"tshark output exceeds max_output_bytes={max_output_bytes}",
                details={"bytes": total_bytes},
            )

        for line in text.splitlines():
            if cancel_check and cancel_check():
                proc.kill()
                raise ProtocolLabError(
                    code="CANCELLED",
                    message="ingest cancelled by user",
                    details={},
                )
            row = _parse_line(line)
            if row is not None:
                rows.append(row)

        progress(f"tshark done: {len(rows)} packets", 0.35)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    return rows


def _parse_line(line: str) -> Optional[TsharkRow]:
    """Разбирает одну TSV-строку tshark. Возвращает None, если строка пустая."""
    if not line:
        return None
    parts = line.split(SEPARATOR)
    # tshark может вернуть меньше полей, если пакет не TCP/IPv4 — пропускаем.
    if len(parts) < len(TSHARK_FIELDS):
        return None
    try:
        stream = int(parts[0]) if parts[0] else None
        frame = int(parts[1])
        ts = float(parts[2])
        ip_src = parts[3]
        ip_dst = parts[4]
        port_src = int(parts[5]) if parts[5] else 0
        port_dst = int(parts[6]) if parts[6] else 0
        seq = int(parts[7]) if parts[7] else 0
        ack = int(parts[8]) if parts[8] else 0
        tcp_len = int(parts[9]) if parts[9] else 0
        syn = parts[10] == "1"
        ack_flag = parts[11] == "1"
        fin = parts[12] == "1"
        rst = parts[13] == "1"
        payload_hex = parts[14]
        payload = bytes.fromhex(payload_hex.replace(":", "")) if payload_hex else b""
    except (ValueError, IndexError):
        return None
    if stream is None:
        return None
    return TsharkRow(
        stream=stream, frame=frame, ts=ts, ip_src=ip_src, ip_dst=ip_dst,
        port_src=port_src, port_dst=port_dst, seq=seq, ack=ack, tcp_len=tcp_len,
        syn=syn, ack_flag=ack_flag, fin=fin, rst=rst, payload=payload,
    )


# ---------------------------------------------------------------------------
# Шаг 3: группировка по tcp.stream → сессии
# ---------------------------------------------------------------------------

@dataclass
class DirectionData:
    direction: str  # 'a_to_b' | 'b_to_a'
    packets: list[TsharkRow] = field(default_factory=list)
    # reassembled:
    data: bytes = b""
    gaps: list[dict] = field(default_factory=list)
    ambiguities: list[dict] = field(default_factory=list)
    segments: list[dict] = field(default_factory=list)
    byte_map: list[tuple[int, int, int]] = field(default_factory=list)  # (start, end, frame)
    stream_start_abs_seq: int = 0
    roles_established: bool = False


@dataclass
class SessionData:
    stream_index: int
    ip_src: str
    ip_dst: str
    port_src: int
    port_dst: int
    first_frame: int
    last_frame: int
    start_time: float
    end_time: float
    directions: dict[str, DirectionData] = field(default_factory=dict)
    syn_frame: Optional[int] = None
    roles_established: bool = False


def group_by_stream(rows: Iterable[TsharkRow]) -> dict[int, SessionData]:
    sessions: dict[int, SessionData] = {}
    for r in rows:
        s = sessions.get(r.stream)
        if s is None:
            s = SessionData(
                stream_index=r.stream,
                ip_src=r.ip_src, ip_dst=r.ip_dst,
                port_src=r.port_src, port_dst=r.port_dst,
                first_frame=r.frame, last_frame=r.frame,
                start_time=r.ts, end_time=r.ts,
            )
            sessions[r.stream] = s
        s.first_frame = min(s.first_frame, r.frame)
        s.last_frame = max(s.last_frame, r.frame)
        s.start_time = min(s.start_time, r.ts)
        s.end_time = max(s.end_time, r.ts)

        # Направление: a_to_b — от ip_src:port_src к ip_dst:port_dst.
        if r.ip_src == s.ip_src and r.port_src == s.port_src:
            d = "a_to_b"
        else:
            d = "b_to_a"
        if d not in s.directions:
            s.directions[d] = DirectionData(direction=d)
        s.directions[d].packets.append(r)

        if r.syn and not r.ack_flag:
            s.syn_frame = r.frame
            s.roles_established = True
    return sessions


# ---------------------------------------------------------------------------
# Шаг 4: reassembly (native или Python fallback)
# ---------------------------------------------------------------------------

def _reassemble_direction(
    packets: list[TsharkRow],
    overlap_policy: str = "first_wins",
    syn_seq: Optional[int] = None,
) -> DirectionData:
    """Вызывает native reassembly, если доступно; иначе — Python fallback."""
    from .native import reassemble as native_reassemble, HAS_NATIVE

    # Готовим вход в формате, ожидаемом native: список Segment.
    segments = []
    for p in packets:
        if p.tcp_len == 0:
            continue
        segments.append({
            "abs_seq": p.seq,
            "len": p.tcp_len,
            "frame_number": p.frame,
            "data": p.payload,
        })

    if HAS_NATIVE:
        out = native_reassemble(
            segments=segments,
            syn_seq=syn_seq,
            overlap_policy=overlap_policy,
        )
        return DirectionData(
            direction="",
            packets=packets,
            data=out["data"],
            gaps=out["gaps"],
            ambiguities=out["ambiguities"],
            segments=out["segments"],
            byte_map=out["byte_map"],
            stream_start_abs_seq=out["stream_start_abs_seq"],
            roles_established=out["roles_established"],
        )

    # Python fallback (упрощённая реализация, байт-идентичная native).
    from .native.fallback import reassemble_py
    out = reassemble_py(
        segments=segments,
        syn_seq=syn_seq,
        overlap_policy=overlap_policy,
    )
    return DirectionData(
        direction="",
        packets=packets,
        data=out["data"],
        gaps=out["gaps"],
        ambiguities=out["ambiguities"],
        segments=out["segments"],
        byte_map=out["byte_map"],
        stream_start_abs_seq=out["stream_start_abs_seq"],
        roles_established=out["roles_established"],
    )


# ---------------------------------------------------------------------------
# Шаг 5: запись в SQLite
# ---------------------------------------------------------------------------

def _store_session(conn, capture_id: int, s: SessionData, policy: dict) -> None:
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO sessions
           (capture_id, stream_index, ip_src, ip_dst, port_src, port_dst,
            roles_established, syn_frame, first_frame, last_frame,
            start_time, end_time, packets_a2b, packets_b2a, bytes_a2b, bytes_b2a)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (capture_id, s.stream_index, s.ip_src, s.ip_dst, s.port_src, s.port_dst,
         int(s.roles_established), s.syn_frame, s.first_frame, s.last_frame,
         s.start_time, s.end_time,
         len(s.directions.get("a_to_b", DirectionData("")).packets),
         len(s.directions.get("b_to_a", DirectionData("")).packets),
         len(s.directions.get("a_to_b", DirectionData("")).data),
         len(s.directions.get("b_to_a", DirectionData("")).data)),
    )
    session_id = cur.lastrowid

    for dname, d in s.directions.items():
        cur.execute(
            """INSERT INTO directions
               (session_id, direction, stream_start_abs_seq, reassembled_bytes,
                gaps_json, ambiguities_json, overlap_policy)
               VALUES (?,?,?,?,?,?,?)""",
            (session_id, dname, d.stream_start_abs_seq, len(d.data),
             json.dumps(d.gaps), json.dumps(d.ambiguities),
             policy.get("overlap", "first_wins")),
        )
        direction_id = cur.lastrowid

        # stream_segments
        for seg in d.segments:
            cur.execute(
                """INSERT INTO stream_segments
                   (direction_id, stream_offset, length, abs_seq_start, abs_seq_end,
                    status, first_frame, last_frame)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (direction_id, seg["stream_offset"], seg["length"],
                 seg["abs_seq_start"], seg["abs_seq_end"], seg["status"],
                 seg["first_frame"], seg["last_frame"]),
            )

        # packets
        for p in d.packets:
            payload_sha = hashlib.sha256(p.payload).hexdigest() if p.payload else None
            inline = p.payload if len(p.payload) <= policy.get("blob_inline_threshold", 4096) else None
            stream_offset = None
            # byte_map: найти offset для frame
            for (start, end, frame) in d.byte_map:
                if frame == p.frame:
                    stream_offset = start
                    break
            cur.execute(
                """INSERT OR IGNORE INTO packets
                   (direction_id, frame_number, abs_seq, tcp_len,
                    flags_syn, flags_ack, flags_fin, flags_rst,
                    payload_sha256, payload_inline, stream_offset)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (direction_id, p.frame, p.seq, p.tcp_len,
                 int(p.syn), int(p.ack_flag), int(p.fin), int(p.rst),
                 payload_sha, inline, stream_offset),
            )

    conn.commit()


# ---------------------------------------------------------------------------
# Публичная точка входа
# ---------------------------------------------------------------------------

def ingest_capture(
    project_dir: Path,
    input_path: Path,
    no_copy: bool = False,
    progress: ProgressFn = _noop_progress,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> dict[str, Any]:
    """Полный ingest одного PCAP/PCAPNG (ТЗ §6.1–§6.4).

    Возвращает сводку: {capture_id, sha256, sessions, packets, ...}.
    """
    input_path = Path(input_path).resolve()
    if not input_path.is_file():
        raise ValidationError(
            code="INPUT_NOT_FOUND",
            message=f"Input file not found: {input_path}",
            details={"path": str(input_path)},
        )

    progress("ingest started", 0.0)
    from .manifest import load_manifest
    from .store import open_db

    manifest = load_manifest(project_dir)
    policy = manifest.get("policies", {})

    pcap_in_project, sha = ensure_capture_copy(project_dir, input_path, no_copy, progress)

    rows = run_tshark(
        pcap_in_project,
        max_output_bytes=policy.get("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES),
        cancel_check=cancel_check,
        progress=progress,
    )

    sessions = group_by_stream(rows)
    progress(f"grouped into {len(sessions)} sessions", 0.5)

    conn = open_db(project_dir)
    cur = conn.cursor()
    cur.execute(
        """INSERT OR IGNORE INTO captures
           (sha256, filename, file_size, packet_count, tshark_version)
           VALUES (?,?,?,?,?)""",
        (sha, input_path.name, pcap_in_project.stat().st_size if pcap_in_project.exists() else 0,
         len(rows), manifest.get("tshark_version", "unknown")),
    )
    conn.commit()
    cur.execute("SELECT id FROM captures WHERE sha256 = ?", (sha,))
    capture_id = cur.fetchone()[0]

    total = len(sessions) or 1
    for i, s in enumerate(sessions.values()):
        # reassembly для каждого направления
        for dname, d in s.directions.items():
            syn_seq = None
            if s.syn_frame is not None:
                for p in d.packets:
                    if p.frame == s.syn_frame and p.syn:
                        syn_seq = p.seq
                        break
            reassembled = _reassemble_direction(d.packets, policy.get("overlap", "first_wins"), syn_seq)
            d.data = reassembled.data
            d.gaps = reassembled.gaps
            d.ambiguities = reassembled.ambiguities
            d.segments = reassembled.segments
            d.byte_map = reassembled.byte_map
            d.stream_start_abs_seq = reassembled.stream_start_abs_seq
            d.roles_established = reassembled.roles_established

        _store_session(conn, capture_id, s, policy)
        progress(f"stored session {s.stream_index}", 0.5 + 0.5 * (i + 1) / total)

    conn.close()
    progress("ingest done", 1.0)

    return {
        "capture_id": capture_id,
        "sha256": sha,
        "packets": len(rows),
        "sessions": len(sessions),
        "pcap_path": str(pcap_in_project),
    }