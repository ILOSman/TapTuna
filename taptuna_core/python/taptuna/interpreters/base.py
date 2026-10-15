"""Базовые типы движков интерпретации (ТЗ §8.4).

Контракт: движок принимает поток байт + спеку и возвращает список
MessageResult. Каждый результат соответствует одному сообщению.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MessageStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    NO_MATCH = "no_match"
    UNKNOWN_FRAME = "unknown_frame"


@dataclass
class MessageResult:
    index: int
    stream_offset: int
    length: int
    message_name: str
    status: MessageStatus
    fields: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    unknown_ranges: list[tuple[int, int]] = field(default_factory=list)
    # ← ДОБАВЛЕНО: структурный признак причины отказа.
    #   None          — нет ошибки;
    #   "extract"     — не удалось извлечь поля;
    #   "constraint"  — constraints не выполнены или упали;
    #   "framing"     — не удалось разбить поток.
    # Нужен для classify_message вместо матчинга подстрок в notes.
    failure_kind: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "stream_offset": self.stream_offset,
            "length": self.length,
            "message_name": self.message_name,
            "status": self.status.value,
            "fields": self.fields,
            "notes": self.notes,
            "unknown_ranges": [list(r) for r in self.unknown_ranges],
            "failure_kind": self.failure_kind,
        }


class InterpretationError(Exception):
    """Ошибка интерпретации (не путать с ошибкой верификации)."""


class BaseInterpreter:
    """Абстрактный интерпретатор. Наследники реализуют `interpret`."""

    def __init__(self, spec: dict[str, Any], name: str, version: int = 1):
        self.spec = spec
        self.name = name
        self.version = version

    def interpret(self, stream: bytes, direction_id: int) -> list[MessageResult]:
        raise NotImplementedError

    def close(self) -> None:
        """Освобождение ресурсов. По умолчанию — ничего."""
        return None