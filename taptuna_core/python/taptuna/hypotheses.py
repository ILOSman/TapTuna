"""Проверка гипотез как исполняемых выражений (ТЗ §9).

Гипотеза = safe-eval выражение над полями сообщения. Результаты:
- satisfied    — выражение истинно
- violated     — выражение ложно
- not_applicable — сообщение не относится к интерпретации
- error        — ошибка вычисления (например, поле не найдено)

Автоматический статус:
- supported    — есть satisfied, нет violated
- refuted      — есть violated
- inconclusive — нет ни satisfied, ни violated (все not_applicable/error)
- unknown      — гипотеза ещё не проверялась
"""
from __future__ import annotations

import ast
import json
import time
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
        - числа: 42, -10, 3.14 (float превращаем в int * 100 — плохо,
          поэтому пока только целые)
        - шестнадцатеричные: 0x48
        - строки: "WRONG", 'abc'
        - имена полей: temp, magic, payload
        - бинарные: + - * / // % & | ^ << >>
        - сравнения: == != < <= > >=
        - логические: and or not
        - len(x) — длина bytes/str
        - встроенные предикаты: exists(x) — поле определено
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

def extract_field_names(ast: dict) -> set[str]:
    """Возвращает имена полей, на которые ссылается выражение."""
    out: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            if node.get("op") == "field" and "name" in node:
                out.add(node["name"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(ast)
    return out

def _convert(node: ast.AST) -> dict:
    """Рекурсивно конвертирует ast.Node в safe_eval JSON AST."""

    if isinstance(node, ast.Constant):
        v = node.value
        if isinstance(v, bool):
            return {"op": "const", "value": v}
        if isinstance(v, int):
            # Диапазон умещается в i64/u64 — ок
            return {"op": "const", "value": v}
        if isinstance(v, str):
            return {"op": "const", "value": v}
        if isinstance(v, bytes):
            return {"op": "const", "value": list(v)}
        if isinstance(v, float):
            # Простейший вариант: превратить в int * 100? Нет, ошибка.
            # Пока не поддерживаем float.
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
        op = _binop_name(node.op)
        return {
            "op": op,
            "a": _convert(node.left),
            "b": _convert(node.right),
        }

    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.USub):
            # Свёртка отрицательной константы: -20 → const(-20)
            if isinstance(node.operand, ast.Constant) and isinstance(node.operand.value, int):
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
        # Раскрываем цепочку a and b and c → and(a, and(b, c))
        values = [_convert(v) for v in node.values]
        result = values[-1]
        for v in reversed(values[:-1]):
            result = {"op": op, "a": v, "b": result}
        return result

    if isinstance(node, ast.Compare):
        # a < b < c → and(lt(a, b), lt(b, c))
        if len(node.ops) != 1:
            # Цепочки: разворачиваем в последовательность
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
            # exists → expr, который true если поле определено.
            # Реализуем через сравнение field != null
            return {"op": "ne", "a": args[0], "b": {"op": "const", "value": None}}
        raise ValidationError(
            code="BAD_EXPRESSION",
            message=f"Unknown function: {name}",
            details={},
        )

    if isinstance(node, ast.IfExp):
        # a if cond else b — раскрываем через or/and
        # x if c else y  →  or(and(c, x), and(not(c), y))
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

def check_hypothesis(
    project_dir: Path,
    hypothesis_id: int,
    run_id: Optional[int] = None,
    progress: ProgressFn = _noop_progress,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> dict:
    """Прогоняет гипотезу по результатам verify.

    Берём последний завершённый прогон для интерпретации гипотезы
    (или явно указанный run_id), читаем fields_json из verification_results
    и вычисляем выражение.

    Возвращает summary: {satisfied, violated, not_applicable, error, status}.
    """
    project_dir = Path(project_dir)
    conn = open_db(project_dir)
    try:
        cur = conn.cursor()

        # 1. Загружаем гипотезу
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

        # 2. Находим run
        if run_id is None:
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
            run_id = rrow["id"]

        # 3. Загружаем все результаты с fields_json
        cur.execute(
            """SELECT id, session_id, direction_id, message_index,
                      stream_offset, length, fields_json, status AS verify_status
               FROM verification_results
               WHERE run_id = ?
               ORDER BY id""",
            (run_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]

        # 4. Чистим старые проверки этой гипотезы
        cur.execute(
            "DELETE FROM hypothesis_checks WHERE hypothesis_id = ?",
            (hypothesis_id,),
        )

        # 5. Проверяем каждое сообщение
        stats = {"satisfied": 0, "violated": 0,
                 "not_applicable": 0, "error": 0}

        # safe_eval через native
        from . import native as _nat
        if not _nat.HAS_NATIVE or _nat._native is None:
            raise ValidationError(
                code="NO_NATIVE",
                message="Hypothesis check requires native core (safe_eval)",
                details={},
            )
        native = _nat._native

        total = len(rows) or 1
        for i, row in enumerate(rows):
            if cancel_check and cancel_check():
                raise ValidationError(
                    code="CANCELLED",
                    message="hypothesis check cancelled",
                    details={},
                )

            if row["verify_status"] != "ok":
                # Сообщение не разобрано интерпретацией — not_applicable
                result = "not_applicable"
                notes = f"verify status: {row['verify_status']}"
                fields = {}
            else:
                try:
                    fields = json.loads(row["fields_json"] or "{}")
                    # native.safe_eval.eval_expr ожидает (expr, fields)
                    val = native.safe_eval.eval_expr(expr, fields)
                    if isinstance(val, bool):
                        result = "satisfied" if val else "violated"
                    else:
                        # Не bool: трактуем по truthiness
                        result = "satisfied" if val else "violated"
                    notes = ""
                except Exception as e:
                    result = "error"
                    notes = f"{type(e).__name__}: {e}"
                    fields = {}

            stats[result] += 1

            cur.execute(
                """INSERT INTO hypothesis_checks
                   (hypothesis_id, session_id, direction_id,
                    message_index, stream_offset, length,
                    result, fields_json, notes)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
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
        # Помечаем stale старые проверки, если интерпретация гипотезы
        # получила новую версию
        if interpretation_id is not None:
            cur.execute(
                """UPDATE hypothesis_checks
                   SET stale = 1
                   WHERE hypothesis_id = ?
                     AND id NOT IN (
                         SELECT hc.id FROM hypothesis_checks hc
                         WHERE hc.hypothesis_id = ?
                         ORDER BY hc.id DESC LIMIT ?
                     )""",
                (hypothesis_id, hypothesis_id, sum(stats.values())),
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
) -> list[dict]:
    """Возвращает результаты проверки гипотезы (с фильтром по result)."""
    sql = "SELECT * FROM hypothesis_checks WHERE hypothesis_id = ?"
    params: list = [hypothesis_id]
    if result:
        sql += " AND result = ?"
        params.append(result)
    sql += " ORDER BY id LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    cur = conn.cursor()
    cur.execute(sql, params)
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