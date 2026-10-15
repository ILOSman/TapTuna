"""Проверка гипотез как исполняемых выражений (ТЗ §9).

Гипотеза = safe-eval выражение над полями сообщения. Результаты:
- satisfied    — выражение истинно
- violated     — выражение ложно
- not_applicable — сообщение не относится к интерпретации,
                   либо поле не извлекалось (FieldNotFound)
- error        — ошибка вычисления (переполнение, деление на ноль)

Автоматический статус:
- supported    — есть satisfied, нет violated
- refuted      — есть violated
- inconclusive — нет ни satisfied, ни violated (все not_applicable/error)
- unknown      — гипотеза ещё не проверялась

История проверок сохраняется. При повторном прогоне старые записи
помечаются stale=1, новые — stale=0. Это позволяет сравнить результаты
до и после изменения интерпретации (ТЗ §7.1 R4).
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any, Callable, Optional

from .errors import ValidationError
from .store import open_db


ProgressFn = Callable[[str, float], None]


def _noop_progress(_msg: str, _frac: float) -> None:
    pass


# ---------------------------------------------------------------------------
# Парсер выражений: Python-подобный синтаксис → JSON AST для safe_eval
# ---------------------------------------------------------------------------

def parse_expression(text: str) -> dict:
    """Парсит выражение на Python-подобном синтаксисе в safe_eval AST.

    Поддерживаемые конструкции:
        - целые числа: 42, -10, 0x48
        - строки: "WRONG", 'abc'
        - байты: b"\\x00\\x01"
        - имена полей: temp, magic, payload
        - бинарные: + - * / // % & | ^ << >>
        - сравнения: == != < <= > >=
        - логические: and or not
        - тернарный: a if cond else b
        - len(x)       — длина bytes/str
        - exists(x)    — поле определено в сообщении
        - contains(a,b)— подстрока/подпоследовательность
    """
    try:
        tree = ast.parse(text.strip(), mode="eval")
    except SyntaxError as e:
        raise ValidationError(
            code="BAD_EXPRESSION",
            message=f"Syntax error: {e}",
            details={"text": text, "line": e.lineno, "col": e.offset},
        )
    return _convert(tree.body)


def extract_field_names(expr: dict) -> set[str]:
    """Возвращает имена полей, на которые ссылается выражение.

    Учитывает как `{"op":"field"}`, так и `{"op":"exists"}` — оба
    ссылаются на поле по имени. Используется в POST /hypotheses
    для проверки, что выражение ссылается только на поля, извлекаемые
    выбранной интерпретацией.
    """
    out: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            op = node.get("op")
            if op in ("field", "exists") and isinstance(node.get("name"), str):
                out.add(node["name"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(expr)
    return out


def _convert(node: ast.AST) -> dict:
    """Рекурсивно конвертирует ast.Node в safe_eval JSON AST."""

    if isinstance(node, ast.Constant):
        v = node.value
        if isinstance(v, bool):
            return {"op": "const", "value": v}
        if isinstance(v, int):
            return {"op": "const", "value": v}
        if isinstance(v, str):
            return {"op": "const", "value": v}
        if isinstance(v, bytes):
            return {"op": "const", "value": list(v)}
        if v is None:
            return {"op": "const", "value": None}
        if isinstance(v, float):
            raise ValidationError(
                code="BAD_EXPRESSION",
                message="Floats not supported, use integers",
                details={"value": v},
            )
        raise ValidationError(
            code="BAD_EXPRESSION",
            message=f"Unsupported constant: {type(v).__name__}",
            details={"value": str(v)},
        )

    if isinstance(node, ast.Name):
        return {"op": "field", "name": node.id}

    if isinstance(node, ast.BinOp):
        return {
            "op": _binop_name(node.op),
            "a": _convert(node.left),
            "b": _convert(node.right),
        }

    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.USub):
            # Свёртка отрицательной константы: -20 → const(-20)
            if isinstance(node.operand, ast.Constant) and \
                    isinstance(node.operand.value, int):
                return {"op": "const", "value": -node.operand.value}
            return {"op": "neg", "a": _convert(node.operand)}
        if isinstance(node.op, ast.Not):
            return {"op": "not", "a": _convert(node.operand)}
        if isinstance(node.op, ast.Invert):
            return {
                "op": "bitxor",
                "a": {"op": "const", "value": -1},
                "b": _convert(node.operand),
            }
        raise ValidationError(
            code="BAD_EXPRESSION",
            message=f"Unsupported unary op: {type(node.op).__name__}",
            details={},
        )

    if isinstance(node, ast.BoolOp):
        op = "and" if isinstance(node.op, ast.And) else "or"
        values = [_convert(v) for v in node.values]
        result = values[-1]
        for v in reversed(values[:-1]):
            result = {"op": op, "a": v, "b": result}
        return result

    if isinstance(node, ast.Compare):
        if len(node.ops) != 1:
            # a < b < c → and(lt(a,b), lt(b,c))
            parts = []
            left = _convert(node.left)
            for op, right_node in zip(node.ops, node.comparators):
                right = _convert(right_node)
                parts.append({"op": _cmpop_name(op), "a": left, "b": right})
                left = right
            result = parts[-1]
            for p in reversed(parts[:-1]):
                result = {"op": "and", "a": p, "b": result}
            return result
        return {
            "op": _cmpop_name(node.ops[0]),
            "a": _convert(node.left),
            "b": _convert(node.comparators[0]),
        }

    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ValidationError(
                code="BAD_EXPRESSION",
                message="Only simple function calls allowed",
                details={},
            )
        name = node.func.id
        args = [_convert(a) for a in node.args]

        if name == "len":
            if len(args) != 1:
                raise ValidationError(
                    code="BAD_EXPRESSION",
                    message="len() takes exactly 1 argument",
                    details={},
                )
            return {"op": "len", "a": args[0]}

        if name == "exists":
            if len(args) != 1 or args[0].get("op") != "field":
                raise ValidationError(
                    code="BAD_EXPRESSION",
                    message="exists(field_name) — expects a single field name",
                    details={},
                )
            # exists(a) → {"op":"exists","name":"a"}
            # Rust-сторона обрабатывает это через ctx.fields.contains_key(name)
            # и НЕ бросает FieldNotFound (в отличие от Expr::Field).
            return {"op": "exists", "name": args[0]["name"]}

        if name == "contains":
            if len(args) != 2:
                raise ValidationError(
                    code="BAD_EXPRESSION",
                    message="contains(a, b) takes exactly 2 arguments",
                    details={},
                )
            return {"op": "contains", "a": args[0], "b": args[1]}

        raise ValidationError(
            code="BAD_EXPRESSION",
            message=f"Unknown function: {name}",
            details={},
        )

    if isinstance(node, ast.IfExp):
        # x if c else y → or(and(c, x), and(not(c), y))
        cond = _convert(node.test)
        a = _convert(node.body)
        b = _convert(node.orelse)
        return {
            "op": "or",
            "a": {"op": "and", "a": cond, "b": a},
            "b": {"op": "and", "a": {"op": "not", "a": cond}, "b": b},
        }

    raise ValidationError(
        code="BAD_EXPRESSION",
        message=f"Unsupported syntax: {type(node).__name__}",
        details={},
    )


def _binop_name(op: ast.operator) -> str:
    return {
        ast.Add: "add", ast.Sub: "sub", ast.Mult: "mul",
        ast.Div: "div", ast.FloorDiv: "floordiv", ast.Mod: "mod",
        ast.BitAnd: "bitand", ast.BitOr: "bitor", ast.BitXor: "bitxor",
        ast.LShift: "shl", ast.RShift: "shr",
    }.get(type(op), "?")


def _cmpop_name(op: ast.cmpop) -> str:
    return {
        ast.Eq: "eq", ast.NotEq: "ne",
        ast.Lt: "lt", ast.LtE: "le",
        ast.Gt: "gt", ast.GtE: "ge",
    }.get(type(op), "?")


# ---------------------------------------------------------------------------
# Проверка гипотезы на корпусе
# ---------------------------------------------------------------------------

#: Признак "поле не найдено" в тексте исключения из native.safe_eval.
#: Rust-сторона формирует EvalError::FieldNotFound("name") → "field not found: name".
_FIELD_NOT_FOUND_MARKER = "field not found"


def _classify_eval_error(exc: BaseException) -> tuple[str, str]:
    """Различает FieldNotFound (not_applicable) и прочие ошибки (error).

    Возвращает (result, notes).
    """
    msg = str(exc)
    if _FIELD_NOT_FOUND_MARKER in msg.lower():
        return "not_applicable", f"field missing in this message: {msg}"
    return "error", f"{type(exc).__name__}: {msg}"


def _resolve_run(
    cur,
    interpretation_id: Optional[int],
    run_id: Optional[int],
) -> int:
    """Возвращает run_id: явный, либо последний завершённый для интерпретации.

    Проверяет, что у явного run_id interpretation_id совпадает — иначе
    fields_json в результатах относятся к другой интерпретации, и
    выражение бессмысленно.
    """
    if run_id is not None:
        cur.execute(
            "SELECT interpretation_id FROM verification_runs WHERE id = ?",
            (run_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise ValidationError(
                code="RUN_NOT_FOUND",
                message=f"Verification run {run_id} not found",
                details={"run_id": run_id},
            )
        if interpretation_id is not None and row["interpretation_id"] != interpretation_id:
            raise ValidationError(
                code="RUN_INTERPRETATION_MISMATCH",
                message=(
                    f"Run {run_id} uses interpretation "
                    f"{row['interpretation_id']}, "
                    f"but hypothesis references {interpretation_id}"
                ),
                details={
                    "run_id": run_id,
                    "run_interpretation_id": row["interpretation_id"],
                    "hypothesis_interpretation_id": interpretation_id,
                },
            )
        return int(run_id)

    if interpretation_id is None:
        raise ValidationError(
            code="NO_INTERPRETATION",
            message="Hypothesis has no interpretation_id; specify run_id",
            details={},
        )
    cur.execute(
        """SELECT id FROM verification_runs
           WHERE interpretation_id = ? AND status = 'completed'
           ORDER BY id DESC LIMIT 1""",
        (interpretation_id,),
    )
    rrow = cur.fetchone()
    if rrow is None:
        raise ValidationError(
            code="NO_RUN",
            message="No completed run found for this interpretation",
            details={"interpretation_id": interpretation_id},
        )
    return int(rrow["id"])


def check_hypothesis(
    project_dir: Path,
    hypothesis_id: int,
    run_id: Optional[int] = None,
    progress: ProgressFn = _noop_progress,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> dict:
    """Прогоняет гипотезу по результатам verify.

    История сохраняется: прошлые проверки этой гипотезы помечаются
    stale=1, новые вставляются с stale=0. Это позволяет сравнить
    результат до/после изменения интерпретации (ТЗ §7.1 R4).
    """
    project_dir = Path(project_dir)
    conn = open_db(project_dir)
    try:
        cur = conn.cursor()

        # 1. Гипотеза
        cur.execute("SELECT * FROM hypotheses WHERE id = ?", (hypothesis_id,))
        hrow = cur.fetchone()
        if hrow is None:
            raise ValidationError(
                code="HYPOTHESIS_NOT_FOUND",
                message=f"Hypothesis {hypothesis_id} not found",
                details={"id": hypothesis_id},
            )
        hyp = dict(hrow)

        if not hyp.get("expression_json"):
            raise ValidationError(
                code="NO_EXPRESSION",
                message="Hypothesis has no expression to check",
                details={"id": hypothesis_id},
            )
        expr = json.loads(hyp["expression_json"])
        interpretation_id = hyp.get("interpretation_id")

        # 2. Прогон
        run_id = _resolve_run(cur, interpretation_id, run_id)

        # 3. Результаты прогона
        cur.execute(
            """SELECT id, session_id, direction_id, message_index,
                      stream_offset, length, fields_json, status AS verify_status
               FROM verification_results
               WHERE run_id = ?
               ORDER BY id""",
            (run_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]

        # 4. Помечаем прошлые проверки stale, НЕ удаляем (история).
        cur.execute(
            "UPDATE hypothesis_checks SET stale = 1 WHERE hypothesis_id = ?",
            (hypothesis_id,),
        )

        # 5. Нужен native для safe_eval
        from . import native as _nat
        if not _nat.HAS_NATIVE or _nat._native is None:
            raise ValidationError(
                code="NO_NATIVE",
                message="Hypothesis check requires native core (safe_eval)",
                details={},
            )
        native = _nat._native

        stats = {"satisfied": 0, "violated": 0,
                 "not_applicable": 0, "error": 0}

        total = len(rows) or 1
        for i, row in enumerate(rows):
            if cancel_check and cancel_check():
                conn.rollback()
                raise ValidationError(
                    code="CANCELLED",
                    message="hypothesis check cancelled",
                    details={"hypothesis_id": hypothesis_id},
                )

            fields: dict[str, Any] = {}
            notes = ""

            if row["verify_status"] != "ok":
                # Сообщение не разобрано интерпретацией — гипотеза
                # к нему не применима.
                result = "not_applicable"
                notes = f"verify status: {row['verify_status']}"
            else:
                try:
                    fields = json.loads(row["fields_json"] or "{}")
                    val = native.safe_eval.eval_expr(expr, fields)
                    result = "satisfied" if bool(val) else "violated"
                except Exception as e:
                    result, notes = _classify_eval_error(e)
                    if result == "error":
                        fields = {}

            stats[result] += 1

            cur.execute(
                """INSERT INTO hypothesis_checks
                   (hypothesis_id, session_id, direction_id,
                    message_index, stream_offset, length,
                    result, fields_json, notes, stale)
                   VALUES (?,?,?,?,?,?,?,?,?, 0)""",
                (hypothesis_id,
                 row["session_id"], row["direction_id"],
                 row["message_index"], row["stream_offset"], row["length"],
                 result,
                 json.dumps(fields, ensure_ascii=False, default=str),
                 notes),
            )

            progress(
                f"checked {i + 1}/{len(rows)}",
                0.1 + 0.9 * (i + 1) / total,
            )

        # 6. Автоматический статус
        if stats["violated"] > 0:
            auto_status = "refuted"
        elif stats["satisfied"] > 0:
            auto_status = "supported"
        else:
            auto_status = "inconclusive"

        cur.execute(
            """UPDATE hypotheses
               SET auto_status = ?,
                   checked_count = ?,
                   satisfied_count = ?,
                   violated_count = ?,
                   error_count = ?,
                   not_applicable_count = ?,
                   last_check_at = datetime('now')
               WHERE id = ?""",
            (auto_status,
             sum(stats.values()),
             stats["satisfied"], stats["violated"], stats["error"],
             stats["not_applicable"],
             hypothesis_id),
        )
        conn.commit()

        return {
            "hypothesis_id": hypothesis_id,
            "run_id": run_id,
            "total": sum(stats.values()),
            "satisfied": stats["satisfied"],
            "violated": stats["violated"],
            "not_applicable": stats["not_applicable"],
            "error": stats["error"],
            "status": auto_status,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Чтение результатов
# ---------------------------------------------------------------------------

def get_hypothesis_checks(
    conn,
    hypothesis_id: int,
    result: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    only_current: bool = True,
) -> list[dict]:
    """Возвращает результаты проверки гипотезы.

    only_current=True (default) — только последний прогон (stale=0).
    only_current=False — вся история, включая stale.
    """
    sql = "SELECT * FROM hypothesis_checks WHERE hypothesis_id = ?"
    params: list = [hypothesis_id]
    if only_current:
        sql += " AND stale = 0"
    if result:
        sql += " AND result = ?"
        params.append(result)
    sql += " ORDER BY id LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def get_hypothesis_checks_history(
    conn,
    hypothesis_id: int,
    limit: int = 500,
    offset: int = 0,
) -> list[dict]:
    """Вся история проверок гипотезы, включая stale.
    Удобно для отчёта §9: «прогон 1 дал refuted, прогон 2 — supported»."""
    cur = conn.cursor()
    cur.execute(
        """SELECT * FROM hypothesis_checks
           WHERE hypothesis_id = ?
           ORDER BY id DESC LIMIT ? OFFSET ?""",
        (hypothesis_id, limit, offset),
    )
    return [dict(r) for r in cur.fetchall()]


def get_hypothesis_observations(conn, hypothesis_id: int) -> list[dict]:
    """Возвращает наблюдения, связанные с гипотезой."""
    cur = conn.cursor()
    cur.execute(
        """SELECT o.id, o.target_type, o.target_id, o.description,
                  o.byte_range_start, o.byte_range_end,
                  ho.role
           FROM hypothesis_observations ho
           JOIN observations o ON o.id = ho.observation_id
           WHERE ho.hypothesis_id = ?
           ORDER BY ho.role, o.id""",
        (hypothesis_id,),
    )
    return [dict(r) for r in cur.fetchall()]