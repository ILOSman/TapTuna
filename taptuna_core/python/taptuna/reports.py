"""Отчёты: Markdown → HTML + machine_model.json (ТЗ §11.1, §11.2).

Markdown — source of truth. HTML собирается из него. machine_model.json —
воспроизводимая модель, применимая к новым данным независимо от taptuna.

Разделы отчёта (§11.1):
1. Цели и границы
2. Метод
3. Корпус
4. Проверенные примеры
5. Контрпримеры
6. Неизвестные участки
7. Область применимости
8. Открытые вопросы
9. Гипотезы (отдельно от правил)
10. Предупреждение о checksum offloading
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .errors import ValidationError
from .store import open_db


# ---------------------------------------------------------------------------
# Прогресс
# ---------------------------------------------------------------------------

ProgressFn = Callable[[str, float], None]


def _noop_progress(_msg: str, _frac: float) -> None:
    pass


# ---------------------------------------------------------------------------
# Сбор данных для отчёта
# ---------------------------------------------------------------------------

def _gather_report_data(
    project_dir: Path,
    run_id: Optional[int],
) -> dict[str, Any]:
    """Собирает все данные для шаблона из БД.

    Если run_id=None, берётся последний завершённый прогон.
    """
    from .manifest import load_manifest

    manifest = load_manifest(project_dir)
    conn = open_db(project_dir)
    try:
        cur = conn.cursor()

        # Прогон
        if run_id is None:
            cur.execute(
                """SELECT * FROM verification_runs
                   WHERE status = 'completed'
                   ORDER BY finished_at DESC LIMIT 1"""
            )
        else:
            cur.execute("SELECT * FROM verification_runs WHERE id = ?", (run_id,))
        run = cur.fetchone()
        if run is None:
            raise ValidationError(
                code="RUN_NOT_FOUND",
                message=f"Verification run not found (run_id={run_id})",
                details={"run_id": run_id},
            )
        run = dict(run)

        # Корпус
        cur.execute("SELECT * FROM corpora WHERE id = ?", (run["corpus_id"],))
        corpus = dict(cur.fetchone())

        # Интерпретация
        cur.execute("SELECT * FROM interpretations WHERE id = ?",
                    (run["interpretation_id"],))
        interp = dict(cur.fetchone())

        # Сводка результатов
        cur.execute(
            """SELECT status, COUNT(*) AS n
               FROM verification_results
               WHERE run_id = ?
               GROUP BY status""",
            (run["id"],),
        )
        status_counts = {r["status"]: r["n"] for r in cur.fetchall()}

        # Проверенные примеры: результаты со статусом ok (первые N)
        cur.execute(
            """SELECT * FROM verification_results
               WHERE run_id = ? AND status = 'ok'
               ORDER BY session_id, direction_id, message_index
               LIMIT 50""",
            (run["id"],),
        )
        verified_examples = [dict(r) for r in cur.fetchall()]

        # Контрпримеры: violation + ambiguous (первые N)
        cur.execute(
            """SELECT * FROM verification_results
               WHERE run_id = ? AND status IN ('violation', 'ambiguous')
               ORDER BY status DESC, id
               LIMIT 50""",
            (run["id"],),
        )
        counterexamples = [dict(r) for r in cur.fetchall()]

        # Неизвестные участки: incomplete + unknown_frame
        cur.execute(
            """SELECT * FROM verification_results
               WHERE run_id = ? AND status IN ('incomplete', 'unknown_frame')
               ORDER BY id
               LIMIT 50""",
            (run["id"],),
        )
        unknown_areas = [dict(r) for r in cur.fetchall()]

        # Наблюдения
        cur.execute(
            """SELECT * FROM observations
               WHERE target_type = 'message' OR target_type = 'range'
               ORDER BY id LIMIT 100"""
        )
        observations = [dict(r) for r in cur.fetchall()]

        # Гипотезы
        cur.execute("SELECT * FROM hypotheses ORDER BY id")
        hypotheses = [dict(r) for r in cur.fetchall()]

        # Связи гипотез и наблюдений
        cur.execute("SELECT * FROM hypothesis_observations")
        hyp_obs = [dict(r) for r in cur.fetchall()]

        # Журнал действий
        cur.execute("SELECT * FROM action_log ORDER BY id")
        actions = [dict(r) for r in cur.fetchall()]

        # Сессии для контекста
        cur.execute(
            """SELECT s.*, c.sha256 AS capture_sha256
               FROM sessions s
               JOIN captures c ON c.id = s.capture_id
               ORDER BY s.id LIMIT 200"""
        )
        sessions = [dict(r) for r in cur.fetchall()]

        # Капчуры
        cur.execute("SELECT * FROM captures ORDER BY id")
        captures = [dict(r) for r in cur.fetchall()]

    finally:
        conn.close()

    return {
        "manifest": manifest,
        "run": run,
        "corpus": corpus,
        "interpretation": interp,
        "status_counts": status_counts,
        "summary": json.loads(run["summary_json"]) if run.get("summary_json") else {},
        "verified_examples": verified_examples,
        "counterexamples": counterexamples,
        "unknown_areas": unknown_areas,
        "observations": observations,
        "hypotheses": hypotheses,
        "hypothesis_observations": hyp_obs,
        "actions": actions,
        "sessions": sessions,
        "captures": captures,
    }


# ---------------------------------------------------------------------------
# machine_model.json
# ---------------------------------------------------------------------------

def build_machine_model(data: dict[str, Any]) -> dict[str, Any]:
    """Собирает воспроизводимую модель интерпретации (ТЗ §11.2).

    Модель содержит только framing + fields + constraints + semantics,
    без привязки к конкретным данным. Применима к новым данным.
    """
    interp = data["interpretation"]
    framing = json.loads(interp["framing_json"]) if interp.get("framing_json") else {}
    fields = json.loads(interp["fields_json"]) if interp.get("fields_json") else {}
    constraints = json.loads(interp["constraints_json"]) if interp.get("constraints_json") else []
    semantics = json.loads(interp["semantics_json"]) if interp.get("semantics_json") else {}

    return {
        "format_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "interpretation": {
            "name": interp["name"],
            "version": interp["version"],
            "kind": interp["kind"],
            "source_hash": interp["source_hash"],
        },
        "framing": framing,
        "fields": fields,
        "constraints": constraints,
        "semantics": semantics,
        "verification": {
            "run_id": data["run"]["id"],
            "run_hash": data["summary"].get("run_hash"),
            "verdict": data["summary"].get("verdict"),
            "status_counts": data["status_counts"],
        },
        "provenance": {
            "app_version": data["manifest"].get("app_version"),
            "tshark_version": data["manifest"].get("tshark_version"),
            "python_version": data["manifest"].get("python_version"),
            "platform": data["manifest"].get("platform"),
            "policies": data["manifest"].get("policies", {}),
        },
    }


# ---------------------------------------------------------------------------
# Генерация Markdown
# ---------------------------------------------------------------------------

def _render_markdown(data: dict[str, Any], model: dict[str, Any]) -> str:
    """Рендерит Markdown по шаблону. Jinja2, если доступен; иначе f-string."""
    try:
        from jinja2 import Environment, PackageLoader, select_autoescape
        env = Environment(
            loader=PackageLoader("taptuna", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        tmpl = env.get_template("report.md.j2")
        return tmpl.render(**data, machine_model=model)
    except (ImportError, Exception):
        return _render_markdown_fallback(data, model)


def _render_markdown_fallback(data: dict[str, Any], model: dict[str, Any]) -> str:
    """Запасной рендер без Jinja2. Возвращает Markdown."""
    s = data["summary"]
    m = data["manifest"]
    interp = data["interpretation"]
    corpus = data["corpus"]
    run = data["run"]

    L: list[str] = []

    # Заголовок
    L.append("# Отчёт о верификации протокола\n")
    L.append(f"| | |")
    L.append(f"|---|---|")
    L.append(f"| Интерпретация | `{interp['name']}@v{interp['version']}` |")
    L.append(f"| Прогон | #{run['id']} |")
    L.append(f"| Вердикт | **{s.get('verdict', 'unknown')}** |")
    L.append(f"| Run hash | `{s.get('run_hash', '—')}` |")
    L.append(f"| Дата | {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} |\n")

    # 1. Цели и границы
    L.append("## 1. Цели и границы\n")
    L.append(f"Цель — верификация гипотез о структуре протокола на корпусе "
             f"`{corpus['name']}`.\n")
    L.append("Границы: анализ ограничен TCP-потоками и применением framing/"
             "fields в рамках выбранной интерпретации.\n")

    # 2. Метод
    L.append("## 2. Метод\n")
    L.append(f"- **Версия tshark:** `{m.get('tshark_version', 'unknown')}`")
    L.append(f"- **Python:** `{m.get('python_version', 'unknown')}`")
    L.append(f"- **Платформа:** `{m.get('platform', 'unknown')}`")
    policies = m.get("policies", {})
    L.append(f"- **Overlap policy:** `{policies.get('overlap', 'unknown')}`")
    L.append(f"- **Checksum policy:** `{policies.get('checksum', 'unknown')}`\n")
    L.append("Команда ingest (один вызов на файл, поля — §6.2):\n")
    L.append("```bash")
    L.append("tshark -r <file> -T fields \\")
    L.append("  -E separator=$'\\t' -E occurrence=f \\")
    fields = [
        "tcp.stream", "frame.number", "frame.time_epoch",
        "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
        "tcp.seq", "tcp.ack", "tcp.len",
        "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
        "tcp.payload",
    ]
    for f_ in fields:
        L.append(f"  -e {f_} \\")
    L.append("```\n")

    # 3. Корпус
    L.append("## 3. Корпус\n")
    L.append(f"- **Название:** `{corpus['name']}`")
    L.append(f"- **Критерии:** `{corpus['criteria_json']}`\n")
    L.append("Записи:\n")
    for c in data["captures"]:
        L.append(f"- `{c['sha256'][:16]}…` — `{c['filename']}` "
                 f"({c['packet_count']} пакетов)")
    L.append("")

    # 4. Проверенные примеры
    L.append("## 4. Проверенные примеры\n")
    if data["verified_examples"]:
        for ex in data["verified_examples"][:10]:
            L.append(f"- Сообщение #{ex['message_index']} @ offset "
                     f"`{ex['stream_offset']}`, длина `{ex['length']}`: "
                     f"`{ex['message_name']}`")
        L.append("")
    else:
        L.append("_Нет проверенных примеров._\n")

    # 5. Контрпримеры
    L.append("## 5. Контрпримеры\n")
    if data["counterexamples"]:
        for ex in data["counterexamples"][:10]:
            L.append(f"- **{ex['status']}** — сообщение #{ex['message_index']} "
                     f"@ offset `{ex['stream_offset']}`, "
                     f"`{ex['message_name']}`")
        L.append("")
    else:
        L.append("_Контрпримеры не обнаружены._\n")

    # 6. Неизвестные участки
    L.append("## 6. Неизвестные участки\n")
    if data["unknown_areas"]:
        for ex in data["unknown_areas"][:10]:
            L.append(f"- {ex['status']} @ offset `{ex['stream_offset']}`, "
                     f"длина `{ex['length']}`")
        L.append("")
    else:
        L.append("_Неизвестные участки отсутствуют._\n")

    # 7. Область применимости
    L.append("## 7. Область применимости\n")
    L.append(f"Модель применима к TCP-потокам, соответствующим критериям "
             f"корпуса `{corpus['name']}`. Перенос на другие протоколы и "
             f"порты требует переобучения и перепроверки.\n")

    # 8. Открытые вопросы
    L.append("## 8. Открытые вопросы\n")
    L.append(f"- Полнота покрытия: {len(data['unknown_areas'])} участков "
             f"остались неизвестными")
    L.append(f"- Контрпримеры: {len(data['counterexamples'])} сообщений "
             f"нарушили правила")
    L.append(f"- Проверенные примеры: {len(data['verified_examples'])} "
             f"успешно разобраны\n")

    # 9. Гипотезы (отдельно от правил)
    L.append("## 9. Гипотезы (отдельно от правил)\n")
    if data["hypotheses"]:
        for h in data["hypotheses"]:
            L.append(f"- [{h['status']}] {h['formulation']}")
        L.append("")
    else:
        L.append("_Гипотезы не зафиксированы._\n")

    # 10. Checksum offloading
    L.append("## 10. Предупреждение о checksum offloading\n")
    L.append("Checksum-поля IP/TCP могут быть некорректны в захватах, "
             "сделанных на интерфейсе отправки (checksum offloading). "
             "Все выводы о checksum следует проверять на захватах с "
             "интерфейса приёма.\n")

    # Сводка
    L.append("## Сводка результатов\n")
    L.append("| Статус | Количество |")
    L.append("|---|---|")
    for k in ("ok", "violation", "ambiguous", "incomplete",
              "not_applicable", "unknown_frame"):
        L.append(f"| `{k}` | {data['status_counts'].get(k, 0)} |")
    L.append("")

    return "\n".join(L)


# ---------------------------------------------------------------------------
# Генерация HTML из Markdown
# ---------------------------------------------------------------------------

def _render_html(md_text: str, data: dict[str, Any]) -> str:
    """Конвертирует Markdown → HTML. markdown, если доступен; иначе <pre>."""
    try:
        import markdown  # type: ignore
        body = markdown.markdown(md_text, extensions=["tables", "fenced_code"])
        return _wrap_html(body, data)
    except ImportError:
        # Без markdown — оборачиваем в <pre>
        import html as _html
        body = f"<pre>{_html.escape(md_text)}</pre>"
        return _wrap_html(body, data)


def _wrap_html(body: str, data: dict[str, Any]) -> str:
    title = f"Отчёт #{data['run']['id']} — {data['interpretation']['name']}"
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 900px;
        margin: 2em auto; padding: 0 1em; line-height: 1.6; color: #222; }}
h1, h2 {{ border-bottom: 1px solid #ddd; padding-bottom: 0.3em; }}
code {{ background: #f4f4f4; padding: 0.15em 0.35em; border-radius: 3px; }}
pre {{ background: #f6f8fa; padding: 1em; border-radius: 5px; overflow-x: auto; }}
table {{ border-collapse: collapse; margin: 1em 0; }}
table th, table td {{ border: 1px solid #ddd; padding: 0.4em 0.8em; }}
table th {{ background: #f0f0f0; text-align: left; }}
blockquote {{ border-left: 4px solid #ddd; padding-left: 1em; color: #555; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

def generate_report(
    project_dir: Path,
    run_id: Optional[int] = None,
    formats: tuple[str, ...] = ("md", "html", "json"),
    out_dir: Optional[Path] = None,
    progress: ProgressFn = _noop_progress,
) -> dict[str, Optional[Path]]:
    """Генерирует отчёт по прогону верификации.

    Args:
        project_dir: корень проекта taptuna.
        run_id: id прогона; None → последний завершённый.
        formats: какие файлы создавать ('md', 'html', 'json').
        out_dir: куда писать; по умолчанию <project_dir>/reports/.
        progress: колбэк прогресса.

    Returns:
        {"md_path": Path|None, "html_path": Path|None, "machine_model_path": Path|None}
    """
    project_dir = Path(project_dir)
    if out_dir is None:
        out_dir = project_dir / "reports"
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    progress("gathering data", 0.1)
    data = _gather_report_data(project_dir, run_id)

    progress("building machine model", 0.3)
    model = build_machine_model(data)

    stamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    base = f"report_run{data['run']['id']}_{stamp}"

    result: dict[str, Optional[Path]] = {
        "md_path": None,
        "html_path": None,
        "machine_model_path": None,
    }

    md_text: Optional[str] = None
    if "md" in formats or "html" in formats:
        progress("rendering markdown", 0.5)
        md_text = _render_markdown(data, model)

    if "md" in formats and md_text is not None:
        p = out_dir / f"{base}.md"
        p.write_text(md_text, encoding="utf-8")
        result["md_path"] = p
        progress(f"md written: {p.name}", 0.7)

    if "html" in formats and md_text is not None:
        progress("rendering html", 0.8)
        html_text = _render_html(md_text, data)
        p = out_dir / f"{base}.html"
        p.write_text(html_text, encoding="utf-8")
        result["html_path"] = p
        progress(f"html written: {p.name}", 0.9)

    if "json" in formats:
        p = out_dir / f"{base}.machine_model.json"
        p.write_text(json.dumps(model, indent=2, ensure_ascii=False), encoding="utf-8")
        result["machine_model_path"] = p
        progress(f"machine_model written: {p.name}", 1.0)

    return result


def list_reports(project_dir: Path) -> list[dict[str, Any]]:
    """Список сгенерированных отчётов в <project_dir>/reports/."""
    out_dir = Path(project_dir) / "reports"
    if not out_dir.exists():
        return []
    out = []
    for p in sorted(out_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file():
            out.append({
                "name": p.name,
                "path": str(p),
                "size": p.stat().st_size,
                "mtime": p.stat().st_mtime,
            })
    return out