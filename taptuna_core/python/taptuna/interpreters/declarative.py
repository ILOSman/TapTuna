"""Declarative-интерпретатор (ТЗ §8.2, §8.3).

Работает через native:
- framing → `_native.framing.frame_stream`
- extract → `_native.extract.extract_fields`
- constraints → `_native.safe_eval.eval_constraints_py`

Если native недоступен — поднимаем InterpretationError.
"""
from __future__ import annotations

from typing import Any

from .base import (
    BaseInterpreter,
    InterpretationError,
    MessageResult,
    MessageStatus,
)


class DeclarativeInterpreter(BaseInterpreter):
    """Интерпретатор по декларативной спеке."""

    def __init__(self, spec: dict[str, Any], name: str, version: int = 1):
        super().__init__(spec, name, version)
        self._validate_spec()

    def _validate_spec(self) -> None:
        if "framing" not in self.spec:
            raise InterpretationError(f"{self.name}: missing 'framing' block")
        if "fields" not in self.spec:
            raise InterpretationError(f"{self.name}: missing 'fields' block")

    def interpret(self, stream: bytes, direction_id: int) -> list[MessageResult]:
        from .. import native as _nat

        if not _nat.HAS_NATIVE or _nat._native is None:
            raise InterpretationError(
                "declarative interpreter requires native core; "
                "install taptuna-core or use TAPTUNA_NATIVE=0 with a Python engine"
            )

        native = _nat._native

        # 1. Framing
        framing_out = native.framing.frame_stream(stream, self.spec["framing"])
        messages = framing_out["messages"]

        results: list[MessageResult] = []
        for idx, m in enumerate(messages):
            offset = m["offset"]
            length = m["length"]
            raw = m["bytes"]

            # 2. Extract
            try:
                fields = native.extract.extract_fields(self.spec["fields"], raw)
            except Exception as e:
                results.append(MessageResult(
                    index=idx,
                    stream_offset=offset,
                    length=length,
                    message_name=self.name,
                    status=MessageStatus.PARTIAL,
                    notes=[f"extract failed: {e}"],
                    failure_kind="extract",   # ← ДОБАВЛЕНО
                ))
                continue

            # 3. Constraints
            constraints = self.spec.get("constraints") or []
            if constraints:
                try:
                    ok = native.safe_eval.eval_constraints_py(constraints, fields)
                except Exception as e:
                    results.append(MessageResult(
                        index=idx,
                        stream_offset=offset,
                        length=length,
                        message_name=self.name,
                        status=MessageStatus.PARTIAL,
                        fields=fields,
                        notes=[f"constraint eval failed: {e}"],
                        failure_kind="constraint",   # ← ДОБАВЛЕНО
                    ))
                    continue

                if not ok:
                    results.append(MessageResult(
                        index=idx,
                        stream_offset=offset,
                        length=length,
                        message_name=self.name,
                        status=MessageStatus.NO_MATCH,
                        fields=fields,
                        notes=["constraints not satisfied"],
                        # ← ДОБАВЛЕНО: именно это сообщение становится
                        #   violation в верификации.
                        failure_kind="constraint",
                    ))
                    continue

            results.append(MessageResult(
                index=idx,
                stream_offset=offset,
                length=length,
                message_name=self.name,
                status=MessageStatus.OK,
                fields=fields,
            ))

        return results