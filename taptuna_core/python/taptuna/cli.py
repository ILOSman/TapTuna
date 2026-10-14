"""CLI для taptuna (ТЗ §11.3).

Все команды работают без GUI. Использование:

    taptuna init --project ./myproj
    taptuna ingest --project ./myproj --input capture.pcap
    taptuna serve --project ./myproj --port 5000
    taptuna interp-add --project ./myproj --file interp.yaml
    taptuna interp-apply --project ./myproj --session 1 --direction a_to_b --name http@1
    taptuna corpus-add --project ./myproj --name corpus1 --file criteria.yaml
    taptuna corpus-list --project ./myproj
    taptuna verify --project ./myproj --corpus corpus1 --interpretation http@1
    taptuna runs --project ./myproj
    taptuna results --project ./myproj --run 1 --status violation
    taptuna report --project ./myproj --run 1 --format md,html
    taptuna action-add --project ./myproj --name actions --file actions.csv
    taptuna action-list --project ./myproj
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

import yaml  # type: ignore


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

def _fail(msg: str, code: int = 1) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return code


def _project_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--project", required=True, type=Path,
                   help="путь к каталогу проекта")


def _progress_printer(prefix: str = "") -> Any:
    """Простой прогресс: печатает на stderr каждые 10% или при смене сообщения."""
    last: dict[str, Any] = {"frac": -1.0, "msg": ""}

    def _p(msg: str, frac: float) -> None:
        bucket = int(frac * 10)
        if bucket != last["frac"] or msg != last["msg"]:
            bar = "█" * bucket + "░" * (10 - bucket)
            print(f"\r{prefix}[{bar}] {int(frac * 100):3d}% {msg}",
                  file=sys.stderr, end="", flush=True)
            last["frac"] = bucket
            last["msg"] = msg
            if frac >= 1.0:
                print(file=sys.stderr)

    return _p


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    from .manifest import create_manifest
    from .store import init_db
    from .errors import ProjectAlreadyExistsError

    project = Path(args.project).resolve()
    project.mkdir(parents=True, exist_ok=True)
    try:
        create_manifest(project)
    except ProjectAlreadyExistsError:
        print(f"project already initialized: {project}")
    else:
        print(f"manifest created: {project / 'manifest.json'}")
    init_db(project)
    print(f"database ready:   {project / 'project.sqlite'}")
    return 0


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------

def cmd_ingest(args: argparse.Namespace) -> int:
    from .ingest import ingest_capture

    project = Path(args.project).resolve()
    input_path = Path(args.input).resolve()
    if not input_path.is_file():
        return _fail(f"input file not found: {input_path}")

    try:
        result = ingest_capture(
            project_dir=project,
            input_path=input_path,
            no_copy=args.no_copy,
            progress=_progress_printer(),
        )
    except Exception as e:
        return _fail(str(e))

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"capture_id:  {result['capture_id']}")
        print(f"sha256:      {result['sha256']}")
        print(f"packets:     {result['packets']}")
        print(f"sessions:    {result['sessions']}")
        print(f"pcap_path:   {result['pcap_path']}")
    return 0


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------

def cmd_serve(args: argparse.Namespace) -> int:
    from .app import create_app

    project = Path(args.project).resolve()
    if not (project / "manifest.json").exists():
        return _fail(f"project not initialized: {project} (run `taptuna init`)")

    app = create_app(project)
    print(f"taptuna server on http://{args.host}:{args.port} (project: {project})")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


# ---------------------------------------------------------------------------
# interp-add
# ---------------------------------------------------------------------------

def cmd_interp_add(args: argparse.Namespace) -> int:
    import hashlib
    from .store import open_db

    project = Path(args.project).resolve()
    spec_path = Path(args.file).resolve()
    if not spec_path.is_file():
        return _fail(f"spec file not found: {spec_path}")

    raw = spec_path.read_text(encoding="utf-8")
    if spec_path.suffix in (".yaml", ".yml"):
        spec = yaml.safe_load(raw)
    elif spec_path.suffix == ".json":
        spec = json.loads(raw)
    else:
        return _fail(f"unsupported spec format: {spec_path.suffix}")

    name = args.name or spec.get("name")
    kind = args.kind or spec.get("kind", "declarative")
    if not name:
        return _fail("name is required (use --name or add 'name:' to spec)")
    if kind not in ("declarative", "script"):
        return _fail(f"kind must be declarative or script, got {kind}")

    source_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    conn = open_db(project)
    try:
        cur = conn.cursor()
        cur.execute("SELECT MAX(version) FROM interpretations WHERE name = ?", (name,))
        version = (cur.fetchone()[0] or 0) + 1

        cur.execute(
            """INSERT INTO interpretations
               (name, version, kind, source_yaml, source_hash,
                framing_json, fields_json, constraints_json, semantics_json)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                name, version, kind, raw, source_hash,
                json.dumps(spec.get("framing") or {}),
                json.dumps(spec.get("fields") or {}),
                json.dumps(spec.get("constraints") or []),
                json.dumps(spec.get("semantics") or {}),
            ),
        )
        conn.commit()
        print(f"interpretation added: {name}@v{version} (id={cur.lastrowid})")
    finally:
        conn.close()
    return 0


# ---------------------------------------------------------------------------
# interp-apply
# ---------------------------------------------------------------------------

def cmd_interp_apply(args: argparse.Namespace) -> int:
    from .store import open_db
    from .verification import _load_stream
    from .interpreters import DeclarativeInterpreter, ScriptInterpreter

    project = Path(args.project).resolve()
    conn = open_db(project)
    try:
        cur = conn.cursor()

        # Находим интерпретацию
        if args.id:
            cur.execute("SELECT * FROM interpretations WHERE id = ?", (args.id,))
            row = cur.fetchone()
        elif args.name:
            if "@" in args.name:
                name, ver = args.name.split("@", 1)
                cur.execute(
                    "SELECT * FROM interpretations WHERE name = ? AND version = ?",
                    (name, int(ver.lstrip("v"))),
                )
            else:
                cur.execute(
                    """SELECT * FROM interpretations WHERE name = ?
                       ORDER BY version DESC LIMIT 1""",
                    (args.name,),
                )
            row = cur.fetchone()
        else:
            return _fail("either --id or --name is required")
        if row is None:
            return _fail("interpretation not found")
        interp = dict(row)

        # Направление
        cur.execute(
            "SELECT * FROM directions WHERE session_id = ? AND direction = ?",
            (args.session, args.direction),
        )
        drow = cur.fetchone()
        if drow is None:
            return _fail(f"direction not found: session={args.session}, direction={args.direction}")
        drow = dict(drow)

        # Stream
        stream = _load_stream(project, drow)
        if not stream:
            print("stream is empty")
            return 0

        # Спецификация
        spec = {
            "framing": json.loads(interp["framing_json"] or "{}"),
            "fields": json.loads(interp["fields_json"] or "{}"),
            "constraints": json.loads(interp["constraints_json"] or "[]"),
            "semantics": json.loads(interp["semantics_json"] or "{}"),
        }
        if interp["kind"] == "script":
            spec["code"] = interp["source_yaml"]

        interp_obj = (
            DeclarativeInterpreter(spec, interp["name"], interp["version"])
            if interp["kind"] == "declarative"
            else ScriptInterpreter(spec, interp["name"], interp["version"])
        )

        msgs = interp_obj.interpret(stream, drow["id"])
    finally:
        conn.close()

    out_data = {
        "interpretation": f"{interp['name']}@v{interp['version']}",
        "session_id": args.session,
        "direction": args.direction,
        "messages": [m.to_dict() for m in msgs],
    }

    if args.out:
        out_path = Path(args.out)
        out_path.write_text(json.dumps(out_data, indent=2, ensure_ascii=False),
                            encoding="utf-8")
        print(f"written: {out_path}")
    else:
        print(json.dumps(out_data, indent=2, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# corpus-add / corpus-list
# ---------------------------------------------------------------------------

def cmd_corpus_add(args: argparse.Namespace) -> int:
    from .store import open_db

    project = Path(args.project).resolve()
    crit_path = Path(args.file).resolve()
    if not crit_path.is_file():
        return _fail(f"criteria file not found: {crit_path}")

    raw = crit_path.read_text(encoding="utf-8")
    if crit_path.suffix in (".yaml", ".yml"):
        criteria = yaml.safe_load(raw)
    elif crit_path.suffix == ".json":
        criteria = json.loads(raw)
    else:
        return _fail(f"unsupported criteria format: {crit_path.suffix}")

    conn = open_db(project)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO corpora (name, criteria_json) VALUES (?,?)",
            (args.name, json.dumps(criteria, ensure_ascii=False)),
        )
        conn.commit()
        print(f"corpus added: {args.name} (id={cur.lastrowid})")
    finally:
        conn.close()
    return 0


def cmd_corpus_list(args: argparse.Namespace) -> int:
    from .store import open_db

    project = Path(args.project).resolve()
    conn = open_db(project)
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, name, created_at FROM corpora ORDER BY id")
        rows = cur.fetchall()
        if not rows:
            print("no corpora")
            return 0
        for r in rows:
            print(f"  #{r['id']:3d}  {r['name']:30s}  {r['created_at']}")
    finally:
        conn.close()
    return 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def cmd_verify(args: argparse.Namespace) -> int:
    from .store import open_db
    from .verification import verify_corpus

    project = Path(args.project).resolve()
    conn = open_db(project)
    try:
        cur = conn.cursor()

        # Корпус
        cur.execute("SELECT id FROM corpora WHERE name = ?", (args.corpus,))
        row = cur.fetchone()
        if row is None:
            return _fail(f"corpus not found: {args.corpus}")
        corpus_id = row[0]

        # Интерпретация
        if args.interpretation_id:
            interpretation_id = args.interpretation_id
        else:
            if "@" in args.interpretation:
                name, ver = args.interpretation.split("@", 1)
                cur.execute(
                    "SELECT id FROM interpretations WHERE name = ? AND version = ?",
                    (name, int(ver.lstrip("v"))),
                )
            else:
                cur.execute(
                    """SELECT id FROM interpretations WHERE name = ?
                       ORDER BY version DESC LIMIT 1""",
                    (args.interpretation,),
                )
            row = cur.fetchone()
            if row is None:
                return _fail(f"interpretation not found: {args.interpretation}")
            interpretation_id = row[0]
    finally:
        conn.close()

    try:
        result = verify_corpus(
            project_dir=project,
            corpus_id=corpus_id,
            interpretation_id=interpretation_id,
            seed=args.seed,
            progress=_progress_printer(),
        )
    except Exception as e:
        return _fail(str(e))

    if args.out:
        Path(args.out).write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"written: {args.out}")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["verdict"] != "violation" else 2


# ---------------------------------------------------------------------------
# runs / results
# ---------------------------------------------------------------------------

def cmd_runs(args: argparse.Namespace) -> int:
    from .store import open_db

    project = Path(args.project).resolve()
    conn = open_db(project)
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT vr.id, vr.corpus_id, vr.interpretation_id, vr.status,
                      vr.seed, vr.started_at, vr.finished_at, vr.summary_json,
                      c.name AS corpus_name, i.name AS interp_name, i.version AS interp_version
               FROM verification_runs vr
               LEFT JOIN corpora c ON c.id = vr.corpus_id
               LEFT JOIN interpretations i ON i.id = vr.interpretation_id
               ORDER BY vr.id DESC"""
        )
        rows = cur.fetchall()
        if not rows:
            print("no verification runs")
            return 0
        for r in rows:
            summary = json.loads(r["summary_json"]) if r["summary_json"] else {}
            verdict = summary.get("verdict", "?")
            print(f"  run #{r['id']:3d}  {r['status']:10s}  verdict={verdict:14s}  "
                  f"corpus={r['corpus_name']}  interp={r['interp_name']}@v{r['interp_version']}")
    finally:
        conn.close()
    return 0


def cmd_results(args: argparse.Namespace) -> int:
    from .store import open_db
    from .verification import get_results

    project = Path(args.project).resolve()
    conn = open_db(project)
    try:
        rows = get_results(
            conn,
            run_id=args.run,
            status=args.status,
            offset=args.offset,
            limit=args.limit,
        )
    finally:
        conn.close()

    if args.out:
        Path(args.out).write_text(
            json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"written: {args.out} ({len(rows)} results)")
    else:
        print(f"results for run #{args.run}: {len(rows)}")
        for r in rows:
            print(f"  [{r['status']:14s}] msg #{r['message_index']:4d} "
                  f"@ {r['stream_offset']:8d}  {r['message_name']}")
    return 0


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def cmd_report(args: argparse.Namespace) -> int:
    from .reports import generate_report

    project = Path(args.project).resolve()
    formats = tuple(f.strip() for f in args.format.split(","))
    out_dir = Path(args.out).resolve() if args.out else None

    try:
        result = generate_report(
            project_dir=project,
            run_id=args.run,
            formats=formats,
            out_dir=out_dir,
            progress=_progress_printer(),
        )
    except Exception as e:
        return _fail(str(e))

    for k, v in result.items():
        if v is not None:
            print(f"{k}: {v}")
    return 0


# ---------------------------------------------------------------------------
# action-add / action-list
# ---------------------------------------------------------------------------

def cmd_action_add(args: argparse.Namespace) -> int:
    from .action_log import import_action_log

    project = Path(args.project).resolve()
    path = Path(args.file).resolve()
    if not path.is_file():
        return _fail(f"action log file not found: {path}")

    try:
        result = import_action_log(
            project_dir=project,
            path=path,
            name=args.name,
            no_copy=args.no_copy,
        )
    except Exception as e:
        return _fail(str(e))

    print(f"action_log_id: {result['action_log_id']}")
    print(f"name:          {result['name']}")
    print(f"entries:       {result['entries']}")
    print(f"sha256:        {result['sha256']}")
    return 0


def cmd_action_list(args: argparse.Namespace) -> int:
    from .store import open_db
    from .action_log import get_action_logs

    project = Path(args.project).resolve()
    conn = open_db(project)
    try:
        rows = get_action_logs(conn)
        if not rows:
            print("no action logs")
            return 0
        for r in rows:
            print(f"  #{r['id']:3d}  {r['name']:30s}  rows={r['row_count']:5d}  "
                  f"imported_at={r['imported_at']}")
    finally:
        conn.close()
    return 0


# ---------------------------------------------------------------------------
# Парсер
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="taptuna",
        description="TapTuna — Protocol Laboratory",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p = sub.add_parser("init", help="инициализировать проект")
    _project_arg(p)
    p.set_defaults(func=cmd_init)

    # ingest
    p = sub.add_parser("ingest", help="импортировать PCAP/PCAPNG")
    _project_arg(p)
    p.add_argument("--input", required=True, help="путь к PCAP/PCAPNG")
    p.add_argument("--no-copy", action="store_true",
                   help="не копировать файл в проект (ref-режим)")
    p.add_argument("--json", action="store_true", help="вывод в JSON")
    p.set_defaults(func=cmd_ingest)

    # serve
    p = sub.add_parser("serve", help="запустить веб-сервер")
    _project_arg(p)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.set_defaults(func=cmd_serve)

    # interp-add
    p = sub.add_parser("interp-add", help="добавить интерпретацию")
    _project_arg(p)
    p.add_argument("--file", required=True, help="YAML/JSON со спекой")
    p.add_argument("--name", help="имя интерпретации (иначе из спеки)")
    p.add_argument("--kind", choices=["declarative", "script"])
    p.set_defaults(func=cmd_interp_add)

    # interp-apply
    p = sub.add_parser("interp-apply", help="применить интерпретацию к сессии")
    _project_arg(p)
    p.add_argument("--session", type=int, required=True)
    p.add_argument("--direction", choices=["a_to_b", "b_to_a"], required=True)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--name", help="имя интерпретации (можно name@vN)")
    g.add_argument("--id", type=int, help="id интерпретации")
    p.add_argument("--out", help="файл для сохранения результата")
    p.set_defaults(func=cmd_interp_apply)

    # corpus-add
    p = sub.add_parser("corpus-add", help="добавить корпус")
    _project_arg(p)
    p.add_argument("--name", required=True)
    p.add_argument("--file", required=True, help="YAML/JSON с критериями")
    p.set_defaults(func=cmd_corpus_add)

    # corpus-list
    p = sub.add_parser("corpus-list", help="список корпусов")
    _project_arg(p)
    p.set_defaults(func=cmd_corpus_list)

    # verify
    p = sub.add_parser("verify", help="прогнать верификацию корпуса")
    _project_arg(p)
    p.add_argument("--corpus", required=True, help="имя корпуса")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--interpretation", help="имя (можно name@vN)")
    g.add_argument("--interpretation-id", type=int)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--out", help="файл для результата (JSON)")
    p.set_defaults(func=cmd_verify)

    # runs
    p = sub.add_parser("runs", help="список прогонов верификации")
    _project_arg(p)
    p.set_defaults(func=cmd_runs)

    # results
    p = sub.add_parser("results", help="результаты прогона")
    _project_arg(p)
    p.add_argument("--run", type=int, required=True)
    p.add_argument("--status", help="фильтр по статусу")
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--out", help="файл для результата (JSON)")
    p.set_defaults(func=cmd_results)

    # report
    p = sub.add_parser("report", help="сгенерировать отчёт")
    _project_arg(p)
    p.add_argument("--run", type=int, help="id прогона (иначе последний)")
    p.add_argument("--format", default="md,html,json",
                   help="через запятую: md,html,json")
    p.add_argument("--out", help="каталог для отчёта")
    p.set_defaults(func=cmd_report)

    # action-add
    p = sub.add_parser("action-add", help="импортировать журнал действий")
    _project_arg(p)
    p.add_argument("--name", help="имя журнала (иначе stem файла)")
    p.add_argument("--file", required=True, help="CSV или YAML")
    p.add_argument("--no-copy", action="store_true")
    p.set_defaults(func=cmd_action_add)

    # action-list
    p = sub.add_parser("action-list", help="список журналов действий")
    _project_arg(p)
    p.set_defaults(func=cmd_action_list)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())