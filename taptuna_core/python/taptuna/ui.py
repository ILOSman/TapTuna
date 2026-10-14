"""UI-маршруты: HTML-страницы на Jinja2 (§16)."""
from __future__ import annotations

from pathlib import Path

from flask import Blueprint, abort, current_app, render_template, send_from_directory
import json
from pathlib import Path

bp = Blueprint("ui", __name__)



def _project() -> Path:
    return Path(current_app.config["PROJECT_DIR"])


def _db():
    from .store import open_db
    return open_db(_project())

@bp.route("/")
def index():
    p = _project()
    initialized = (p / "manifest.json").exists()
    captures = []
    if initialized:
        try:
            conn = _db()
            try:
                cur = conn.cursor()
                cur.execute("""SELECT id, sha256, filename, packet_count,
                                      tshark_version, ingested_at
                               FROM captures ORDER BY id DESC""")
                captures = [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()
        except Exception:
            captures = []
    return render_template("index.html", project_name=p.name,
                           initialized=initialized, captures=captures)


@bp.route("/sessions")
def sessions():
    p = _project()
    sessions_list = []
    captures = []
    try:
        conn = _db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, filename FROM captures ORDER BY id")
            captures = [dict(r) for r in cur.fetchall()]
            cur.execute("""
                SELECT s.id, s.capture_id, s.stream_index,
                       s.ip_src, s.ip_dst, s.port_src, s.port_dst,
                       s.roles_established, s.first_frame, s.last_frame,
                       s.start_time, s.end_time,
                       s.packets_a2b, s.packets_b2a,
                       s.bytes_a2b, s.bytes_b2a,
                       c.filename AS capture_name
                FROM sessions s
                JOIN captures c ON c.id = s.capture_id
                ORDER BY s.id
            """)
            sessions_list = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception:
        pass
    return render_template("sessions.html", project_name=p.name,
                           sessions=sessions_list, captures=captures)


@bp.route("/sessions/<int:session_id>")
def session_detail(session_id: int):
    p = _project()
    try:
        conn = _db()
        try:
            cur = conn.cursor()
            cur.execute("""SELECT s.*, c.filename AS capture_name, c.sha256 AS capture_sha256
                           FROM sessions s
                           JOIN captures c ON c.id = s.capture_id
                           WHERE s.id = ?""", (session_id,))
            row = cur.fetchone()
            if row is None:
                abort(404)
            session = dict(row)
            cur.execute("""SELECT id, direction, stream_start_abs_seq,
                                  reassembled_bytes, overlap_policy,
                                  gaps_json, ambiguities_json
                           FROM directions WHERE session_id = ?
                           ORDER BY direction""", (session_id,))
            directions = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except FileNotFoundError:
        abort(404)
    return render_template("session.html", project_name=p.name,
                           session=session, directions=directions)


@bp.route("/research")
def research():
    p = _project()
    sessions_list = []
    try:
        conn = _db()
        try:
            cur = conn.cursor()
            cur.execute("""SELECT id, ip_src, ip_dst, port_src, port_dst,
                                  stream_index, packets_a2b, packets_b2a,
                                  bytes_a2b, bytes_b2a
                           FROM sessions ORDER BY id""")
            sessions_list = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception:
        pass
    return render_template("research.html", project_name=p.name,
                           sessions=sessions_list)


@bp.route("/interpretations")
def interpretations():
    p = _project()
    interps = []
    sessions_list = []
    try:
        conn = _db()
        try:
            cur = conn.cursor()
            cur.execute("""SELECT id, name, version, kind, source_hash, created_at
                           FROM interpretations
                           ORDER BY name, version DESC""")
            interps = [dict(r) for r in cur.fetchall()]
            cur.execute("""SELECT id, ip_src, ip_dst, port_src, port_dst,
                                  stream_index FROM sessions ORDER BY id""")
            sessions_list = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception:
        pass
    return render_template("interpretations.html", project_name=p.name,
                           interpretations=interps, sessions=sessions_list)


@bp.route("/verification")
def verification():
    p = _project()
    corpora = []
    interps = []
    runs = []
    try:
        conn = _db()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, name, criteria_json, created_at FROM corpora ORDER BY id"
            )
            corpora = [dict(r) for r in cur.fetchall()]

            cur.execute(
                """SELECT id, name, version, kind FROM interpretations
                   ORDER BY name, version DESC"""
            )
            interps = [dict(r) for r in cur.fetchall()]

            cur.execute(
                """SELECT vr.id, vr.status, vr.seed, vr.started_at,
                          vr.finished_at, vr.summary_json,
                          c.name AS corpus_name,
                          i.name AS interp_name, i.version AS interp_version
                   FROM verification_runs vr
                   LEFT JOIN corpora c ON c.id = vr.corpus_id
                   LEFT JOIN interpretations i ON i.id = vr.interpretation_id
                   ORDER BY vr.id DESC LIMIT 50"""
            )
            runs_raw = [dict(r) for r in cur.fetchall()]
            runs = []
            for r in runs_raw:
                summary = {}
                if r.get("summary_json"):
                    try:
                        summary = json.loads(r["summary_json"])
                    except Exception:
                        summary = {}
                r["verdict"] = summary.get("verdict")
                r["run_hash"] = summary.get("run_hash")
                runs.append(r)
        finally:
            conn.close()
    except Exception:
        pass

    return render_template(
        "verification.html",
        project_name=p.name,
        corpora=corpora,
        interpretations=interps,
        runs=runs,
    )


@bp.route("/action-log")
def action_log():
    p = _project()
    logs = []
    entries = {}
    try:
        conn = _db()
        try:
            cur = conn.cursor()
            cur.execute(
                """SELECT id, name, source_path, sha256, row_count,
                          columns_json, imported_at
                   FROM action_log ORDER BY id DESC"""
            )
            logs = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception:
        pass

    # Загружаем первые N записей каждого журнала
    from .action_log import get_action_entries
    for lg in logs:
        try:
            all_entries = get_action_entries(p, lg["id"])
            entries[lg["id"]] = all_entries[:200]
        except Exception:
            entries[lg["id"]] = []

    return render_template("action_log.html", project_name=p.name,
                           logs=logs, entries=entries)


@bp.route("/project")
def project():
    p = _project()
    from .manifest import load_manifest

    manifest = {}
    stats = {"captures": 0, "sessions": 0, "packets": 0,
             "interpretations": 0, "corpora": 0, "runs": 0,
             "observations": 0, "hypotheses": 0, "action_logs": 0}
    stale_count = 0

    try:
        if (p / "manifest.json").exists():
            manifest = load_manifest(p)
        conn = _db()
        try:
            cur = conn.cursor()
            for tbl, key in [
                ("captures", "captures"),
                ("sessions", "sessions"),
                ("packets", "packets"),
                ("interpretations", "interpretations"),
                ("corpora", "corpora"),
                ("verification_runs", "runs"),
                ("observations", "observations"),
                ("hypotheses", "hypotheses"),
                ("action_log", "action_logs"),
            ]:
                cur.execute(f"SELECT COUNT(*) FROM {tbl}")
                stats[key] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM verification_results WHERE stale = 1")
            stale_count = cur.fetchone()[0]
        finally:
            conn.close()
    except Exception:
        pass

    return render_template("project.html", project_name=p.name,
                           manifest=manifest, project_path=str(p),
                           stats=stats, stale_count=stale_count)


@bp.route("/report")
def report():
    p = _project()
    from .reports import list_reports
    reports = list_reports(p)

    runs = []
    try:
        conn = _db()
        try:
            cur = conn.cursor()
            cur.execute("""SELECT vr.id, vr.status, vr.finished_at, vr.summary_json,
                                  c.name AS corpus_name,
                                  i.name AS interp_name, i.version AS interp_version
                           FROM verification_runs vr
                           LEFT JOIN corpora c ON c.id = vr.corpus_id
                           LEFT JOIN interpretations i ON i.id = vr.interpretation_id
                           WHERE vr.status = 'completed'
                           ORDER BY vr.id DESC LIMIT 50""")
            raw = [dict(r) for r in cur.fetchall()]
            for r in raw:
                summary = {}
                if r.get("summary_json"):
                    try:
                        summary = json.loads(r["summary_json"])
                    except Exception:
                        pass
                r["verdict"] = summary.get("verdict")
                runs.append(r)
        finally:
            conn.close()
    except Exception:
        pass

    return render_template("report.html", project_name=p.name,
                           reports=reports, runs=runs)

@bp.route("/reports/<path:name>")
def serve_report(name: str):
    """Отдаёт сгенерированный отчёт из <project>/reports/."""
    p = _project()
    reports_dir = p / "reports"
    return send_from_directory(reports_dir, name, as_attachment=False)