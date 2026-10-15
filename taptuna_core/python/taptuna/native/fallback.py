"""Чистая Python-реализация reassembly.

Байт-идентична нативной `reassembly.rs`. Любое расхождение — баг,
который ловится в tests/test_cross_validation.py (ТЗ §20.3).
"""
from __future__ import annotations

import hashlib
from typing import Any, Optional

SEQ_WINDOW = 1 << 31  # 2^31


# ---------------------------------------------------------------------------
# RFC 9293 serial number arithmetic
# ---------------------------------------------------------------------------

def _cmp_seq(a: int, b: int) -> int:
    """Сравнение sequence numbers по RFC 9293.

    Возвращает -1, 0, 1. a > b, если (a - b) mod 2^32 < 2^31.
    """
    diff = (a - b) & 0xFFFFFFFF
    if diff == 0:
        return 0
    return 1 if diff < SEQ_WINDOW else -1


# ---------------------------------------------------------------------------
# Вход/выход
# ---------------------------------------------------------------------------

def _to_rust_segment(d: dict) -> dict:
    """Нормализует входной dict. Ключ 'len' — длина, 'data' — bytes."""
    return {
        "abs_seq": int(d["abs_seq"]) & 0xFFFFFFFF,
        "len": int(d["len"]),
        "frame_number": int(d["frame_number"]),
        "data": bytes(d["data"]),
    }

def reassemble_py(
    segments: list[dict],
    syn_seq: Optional[int] = None,
    overlap_policy: str = "first_wins",
    max_stream_bytes: Optional[int] = None,
) -> dict:
    segs = [_to_rust_segment(s) for s in segments]
    segs = [s for s in segs if s["len"] > 0]

    # Сортировка по (abs_seq, frame_number) с учётом wraparound
    _sort_segments(segs)

    # Дедупликация идентичных (abs_seq, len, data) — оставляем первый
    deduped: list[dict] = []
    for s in segs:
        if deduped:
            last = deduped[-1]
            if (last["abs_seq"] == s["abs_seq"]
                    and last["len"] == s["len"]
                    and last["data"] == s["data"]):
                continue
        deduped.append(s)
    segs = deduped

    # Инициализация tracker
    roles_established = syn_seq is not None
    if roles_established:
        reference = (int(syn_seq) + 1) & 0xFFFFFFFF
        initialized = True
    elif segs:
        reference = (segs[0]["abs_seq"] - 1) & 0xFFFFFFFF
        initialized = True
    else:
        reference = 0
        initialized = False

    stream_start_abs_seq = reference if roles_established else (segs[0]["abs_seq"] if segs else 0)

    # ← ИЗМЕНЕНО: вместо списка (offset, byte) — bytearray + интервалы.
    # Было: ~60 байт Python-объекта на каждый байт потока. Для 10 МиБ
    # потока это ~600 МиБ. Стало: 1 байт на байт + список (start, end).
    data_buf = bytearray()
    written: list[tuple[int, int]] = []   # [start, end), отсортированы, не пересекаются

    def _write_range(offset: int, bs: bytes) -> None:
        if not bs:
            return
        end = offset + len(bs)
        if len(data_buf) < end:
            data_buf.extend(b"\x00" * (end - len(data_buf)))
        data_buf[offset:end] = bs

        if not written:
            written.append((offset, end))
            return
        i = 0
        while i < len(written) and written[i][0] <= offset:
            i += 1
        new_start, new_end = offset, end
        from_idx = i
        if i > 0:
            s, e = written[i - 1]
            if e >= offset:
                new_start = s
                new_end = max(new_end, e)
                from_idx = i - 1
        to_idx = i
        while to_idx < len(written) and written[to_idx][0] <= new_end:
            new_end = max(new_end, written[to_idx][1])
            to_idx += 1
        written[from_idx:to_idx] = [(new_start, new_end)]

    def _read_range(offset: int, length: int) -> bytes:
        out = bytearray(length)
        end = offset + length
        for (s, e) in written:
            if e <= offset:
                continue
            if s >= end:
                break
            rs = max(s, offset)
            re = min(e, end)
            out[rs - offset:re - offset] = data_buf[rs:re]
        return bytes(out)

    gaps: list[dict] = []
    ambiguities: list[dict] = []
    stream_segments: list[dict] = []
    byte_map: list[tuple[int, int, int]] = []

    contiguous_end_offset = 0
    max_bytes = max_stream_bytes if max_stream_bytes is not None else (1 << 64)

    def _seq_to_offset(abs_seq: int) -> Optional[int]:
        if not initialized:
            return None
        c = _cmp_seq(abs_seq, reference)
        if c <= 0:
            diff = (reference - abs_seq) & 0xFFFFFFFF
            return diff if diff < SEQ_WINDOW else None
        else:
            diff = (abs_seq - reference) & 0xFFFFFFFF
            return diff if diff < SEQ_WINDOW else None

    def _offset_to_seq(offset: int) -> Optional[int]:
        if not initialized or offset >= SEQ_WINDOW:
            return None
        return (reference + offset) & 0xFFFFFFFF

    for seg in segs:
        seg_offset = _seq_to_offset(seg["abs_seq"])
        if seg_offset is None:
            continue
        seg_end_seq = (seg["abs_seq"] + seg["len"]) & 0xFFFFFFFF

        if seg_offset + seg["len"] > max_bytes:
            continue

        # Gap перед сегментом
        if seg_offset > contiguous_end_offset:
            gap_len = seg_offset - contiguous_end_offset
            gaps.append({
                "offset": contiguous_end_offset,
                "length": gap_len,
                "frames": [seg["frame_number"]],
            })
            stream_segments.append({
                "stream_offset": contiguous_end_offset,
                "length": 0,
                "abs_seq_start": _offset_to_seq(contiguous_end_offset) or 0,
                "abs_seq_end": ((_offset_to_seq(contiguous_end_offset) or 0) - 1) & 0xFFFFFFFF,
                "status": "gap_before",
                "first_frame": seg["frame_number"],
                "last_frame": seg["frame_number"],
            })
            contiguous_end_offset = seg_offset

        # Overlap с уже записанными данными
        data_end_offset = seg_offset + seg["len"]
        if data_end_offset >= contiguous_end_offset and seg_offset < contiguous_end_offset:
            overlap_len = contiguous_end_offset - seg_offset
        else:
            overlap_len = 0

        if 0 < overlap_len <= seg["len"]:
            existing = _read_range(seg_offset, overlap_len)
            new_bytes = seg["data"][:overlap_len]
            conflict = existing != new_bytes
            if conflict:
                ambiguities.append({
                    "offset": seg_offset,
                    "length": overlap_len,
                    "frames": [seg["frame_number"]],
                    "policy": overlap_policy,
                })
                if overlap_policy == "last_wins":
                    _write_range(seg_offset, new_bytes)
                # first_wins и halt_and_mark оставляют existing

        # Хвост без перекрытия
        tail_start = overlap_len
        if tail_start < seg["len"]:
            tail = seg["data"][tail_start:]
            tail_offset = seg_offset + tail_start
            _write_range(tail_offset, tail)
            byte_map.append(
                (tail_offset, tail_offset + len(tail), seg["frame_number"])
            )

        # Обновление contiguous
        if seg_offset <= contiguous_end_offset and data_end_offset > contiguous_end_offset:
            contiguous_end_offset = data_end_offset
        elif seg_offset == contiguous_end_offset:
            contiguous_end_offset = data_end_offset

        # Запись сегмента
        if overlap_len > 0:
            status = "overlap"
        elif seg_offset > contiguous_end_offset:
            status = "gap_before"
        else:
            status = "clean"
        stream_segments.append({
            "stream_offset": seg_offset,
            "length": seg["len"],
            "abs_seq_start": seg["abs_seq"],
            "abs_seq_end": (seg_end_seq - 1) & 0xFFFFFFFF,
            "status": status,
            "first_frame": seg["frame_number"],
            "last_frame": seg["frame_number"],
        })

    # Сборка данных: склеиваем known-интервалы по порядку, gaps пропускаем.
    result_data = b"".join(data_buf[s:e] for (s, e) in written)
    byte_map.sort(key=lambda x: x[0])

    return {
        "data": result_data,
        "gaps": gaps,
        "ambiguities": ambiguities,
        "segments": stream_segments,
        "byte_map": byte_map,
        "stream_start_abs_seq": stream_start_abs_seq,
        "roles_established": roles_established,
    }


def _sort_segments(segs: list[dict]) -> None:
    """Сортировка по (abs_seq, frame_number) с учётом wraparound.

    Используем key через 2^32, чтобы sorted был стабилен.
    Простейший корректный подход: сортируем обычным cmp через functools.
    """
    from functools import cmp_to_key

    def _cmp(a: dict, b: dict) -> int:
        c = _cmp_seq(a["abs_seq"], b["abs_seq"])
        if c != 0:
            return c
        return (a["frame_number"] > b["frame_number"]) - (a["frame_number"] < b["frame_number"])

    segs.sort(key=cmp_to_key(_cmp))