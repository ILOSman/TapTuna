"""Генерирует готовый демонстрационный проект (§13 п.4 ТЗ).

Создаёт:
    examples/demo_project/
    ├── manifest.json
    ├── project.sqlite
    ├── captures/<sha>.pcap
    ├── action_log/<sha>.entries.json
    └── reports/report_run1_*.{md,html,machine_model.json}

Запуск:
    python examples/generate_demo.py
    python examples/generate_demo.py --out /custom/path
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path,
                    default=Path(__file__).parent / "demo_project")
    ap.add_argument("--force", action="store_true",
                    help="удалить существующий проект")
    args = ap.parse_args()

    project = args.out.resolve()

    if project.exists():
        if not args.force:
            print(f"error: {project} exists. Use --force to overwrite.")
            return 1
        shutil.rmtree(project)

    project.mkdir(parents=True)

    # Импортируем taptuna — предполагается editable install
    try:
        from taptuna.manifest import create_manifest
        from taptuna.store import init_db
        from taptuna.ingest import ingest_capture
        from taptuna.action_log import import_action_log
        from taptuna.verification import verify_corpus
        from taptuna.reports import generate_report
    except ImportError as e:
        print(f"error: taptuna not installed: {e}", file=sys.stderr)
        print("Run: pip install -e taptuna_core", file=sys.stderr)
        return 1

    # 1. Инициализация
    print("[1/7] init")
    create_manifest(project)
    init_db(project)

    # 2. Генерируем эталонный PCAP через taptuna.examples
    print("[2/7] generate pcap")
    from taptuna.examples.generate import build_session
    from scapy.all import wrpcap

    pcap_src = project / "demo.pcap"
    pkts = build_session()
    wrpcap(str(pcap_src), pkts)

    print("[3/7] ingest")
    ingest_result = ingest_capture(
        project_dir=project,
        input_path=pcap_src,
        no_copy=False,
        progress=lambda msg, frac: None,
    )
    pcap_src.unlink()
    print(f"      capture_id={ingest_result['capture_id']} "
          f"sessions={ingest_result['sessions']} packets={ingest_result['packets']}")

    # 4. Интерпретация
    print("[4/7] add interpretation")
    import hashlib
    from taptuna.store import open_db

    conn = open_db(project)
    cur = conn.cursor()

    framing = json.dumps({"kind": "fixed", "size": 13, "max_message": 1024})
    fields = json.dumps({
        "name": "message",
        "fields": [{"name": "raw", "type": "bytes", "offset": 0, "size": 13}],
    })
    source_yaml = (
        "name: demo_fixed13\n"
        "kind: declarative\n"
        "framing: {kind: fixed, size: 13, max_message: 1024}\n"
        "fields:\n"
        "  name: message\n"
        "  fields:\n"
        "    - {name: raw, type: bytes, offset: 0, size: 13}\n"
        "constraints: []\n"
        "semantics: {}\n"
    )
    source_hash = hashlib.sha256(source_yaml.encode("utf-8")).hexdigest()

    cur.execute(
        """INSERT INTO interpretations
           (name, version, kind, source_yaml, source_hash,
            framing_json, fields_json, constraints_json, semantics_json)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        ("demo_fixed13", 1, "declarative", source_yaml, source_hash,
         framing, fields, "[]", "{}"),
    )
    interp_id = cur.lastrowid

    # 5. Корпус
    print("[5/7] add corpus")
    criteria = json.dumps({"any_ports": [8080]})
    cur.execute(
        "INSERT INTO corpora (name, criteria_json) VALUES (?,?)",
        ("demo_corpus", criteria),
    )
    corpus_id = cur.lastrowid
    conn.commit()
    conn.close()

    # 6. Журнал действий (согласованный с временем сессии)
    print("[6/7] add action log")
    conn = open_db(project)
    cur = conn.cursor()
    cur.execute("SELECT MIN(start_time) AS t0 FROM sessions")
    t0 = cur.fetchone()["t0"]
    conn.close()

    entries = [
        {"ts": t0 - 1.0, "action": "connect",
         "params": {"host": "10.0.0.2", "port": 8080},
         "result": {"ok": True}},
        {"ts": t0 + 0.1, "action": "send_data",
         "params": {"bytes": 13},
         "result": {"ok": True}},
        {"ts": t0 + 1.0, "action": "close",
         "params": {}, "result": {"ok": True}},
    ]
    al_yaml = project / "_actions.yaml"
    al_yaml.write_text(json.dumps({"entries": entries}, indent=2),
                       encoding="utf-8")
    import_action_log(
        project_dir=project,
        path=al_yaml,
        name="demo_actions",
        no_copy=False,
    )
    al_yaml.unlink()

    # 7. Verify + отчёт
    print("[7/7] verify + report")
    vresult = verify_corpus(
        project_dir=project,
        corpus_id=corpus_id,
        interpretation_id=interp_id,
        seed=0,
    )
    print(f"      verdict={vresult['verdict']} messages={vresult['messages']} "
          f"run_hash={vresult['run_hash'][:16]}…")

    generate_report(
        project_dir=project,
        run_id=vresult["run_id"],
        formats=("md", "html", "json"),
    )

    print()
    print(f"project: {project}")
    print(f"open:    taptuna serve --project {project}")
    print(f"         http://127.0.0.1:5000")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())