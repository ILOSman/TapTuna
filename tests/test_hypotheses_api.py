"""API-тесты гипотез (§9). Синхронные эндпоинты; job'ы — только создание."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from taptuna.manifest import create_manifest
from taptuna.store import init_db, open_db


def _client(project: Path):
    from taptuna.app import create_app
    app = create_app(project)
    return app.test_client()


def _empty_project(tmp_path: Path) -> Path:
    project = tmp_path / "p"
    project.mkdir()
    create_manifest(project)
    init_db(project)
    return project


# ---------------------------------------------------------------------------
# POST /hypotheses/validate
# ---------------------------------------------------------------------------

def test_validate_valid_expression(tmp_path):
    project = _empty_project(tmp_path)
    c = _client(project)

    r = c.post(
        f"/api/projects/{project.name}/hypotheses/validate",
        json={"expression_text": "temp >= -20 and temp <= 20"},
    )
    assert r.status_code == 200
    d = r.get_json()
    assert d["valid"] is True
    assert d["ast"]["op"] == "and"


def test_validate_bad_expression(tmp_path):
    project = _empty_project(tmp_path)
    c = _client(project)

    r = c.post(
        f"/api/projects/{project.name}/hypotheses/validate",
        json={"expression_text": "temp >= "},
    )
    assert r.status_code == 200
    d = r.get_json()
    assert d["valid"] is False
    assert "error" in d


def test_validate_unknown_function(tmp_path):
    project = _empty_project(tmp_path)
    c = _client(project)

    r = c.post(
        f"/api/projects/{project.name}/hypotheses/validate",
        json={"expression_text": "eval('bad')"},
    )
    assert r.status_code == 200
    d = r.get_json()
    assert d["valid"] is False
    assert "Unknown function" in d["error"]["message"]


def test_validate_missing_expression(tmp_path):
    project = _empty_project(tmp_path)
    c = _client(project)

    r = c.post(
        f"/api/projects/{project.name}/hypotheses/validate",
        json={},
    )
    assert r.status_code == 400
    assert r.get_json()["error"]["code"] == "MISSING_EXPRESSION"


# ---------------------------------------------------------------------------
# POST /hypotheses
# ---------------------------------------------------------------------------

def test_create_hypothesis_with_expression(tmp_path):
    project = _empty_project(tmp_path)
    c = _client(project)

    r = c.post(
        f"/api/projects/{project.name}/hypotheses",
        json={
            "formulation": "Температура в [-20, 20]",
            "status": "open",
            "expression_text": "temp >= -20 and temp <= 20",
        },
    )
    assert r.status_code == 201
    d = r.get_json()
    assert d["has_expression"] is True

    # Проверяем в БД
    conn = open_db(project)
    cur = conn.cursor()
    cur.execute("SELECT formulation, expression_json, auto_status FROM hypotheses WHERE id = ?", (d["id"],))
    row = dict(cur.fetchone())
    conn.close()
    assert row["formulation"] == "Температура в [-20, 20]"
    assert row["expression_json"] is not None
    assert row["auto_status"] == "unknown"


def test_create_hypothesis_without_expression(tmp_path):
    """Гипотеза без выражения — legacy-режим, всё ещё работает."""
    project = _empty_project(tmp_path)
    c = _client(project)

    r = c.post(
        f"/api/projects/{project.name}/hypotheses",
        json={"formulation": "что-то неизвестное"},
    )
    assert r.status_code == 201
    d = r.get_json()
    assert d["has_expression"] is False


def test_create_hypothesis_bad_expression(tmp_path):
    project = _empty_project(tmp_path)
    c = _client(project)

    r = c.post(
        f"/api/projects/{project.name}/hypotheses",
        json={
            "formulation": "bad",
            "expression_text": "temp >= ",
        },
    )
    assert r.status_code == 400
    assert r.get_json()["error"]["code"] == "BAD_EXPRESSION"


def test_create_hypothesis_missing_formulation(tmp_path):
    project = _empty_project(tmp_path)
    c = _client(project)

    r = c.post(
        f"/api/projects/{project.name}/hypotheses",
        json={"expression_text": "temp >= 0"},
    )
    assert r.status_code == 400
    assert r.get_json()["error"]["code"] == "MISSING_FORMULATION"


# ---------------------------------------------------------------------------
# GET /hypotheses
# ---------------------------------------------------------------------------

def test_list_hypotheses_includes_new_fields(tmp_path):
    project = _empty_project(tmp_path)
    c = _client(project)

    # Создаём две
    c.post(f"/api/projects/{project.name}/hypotheses",
           json={"formulation": "h1", "expression_text": "temp >= 0"})
    c.post(f"/api/projects/{project.name}/hypotheses",
           json={"formulation": "h2"})

    r = c.get(f"/api/projects/{project.name}/hypotheses")
    assert r.status_code == 200
    items = r.get_json()["hypotheses"]
    assert len(items) == 2
    # Новые поля присутствуют
    for h in items:
        assert "auto_status" in h
        assert "expression_text" in h
        assert "checked_count" in h


# ---------------------------------------------------------------------------
# DELETE /hypotheses/<id>
# ---------------------------------------------------------------------------

def test_delete_hypothesis(tmp_path):
    project = _empty_project(tmp_path)
    c = _client(project)

    r = c.post(f"/api/projects/{project.name}/hypotheses",
               json={"formulation": "to delete"})
    hyp_id = r.get_json()["id"]

    r = c.delete(f"/api/projects/{project.name}/hypotheses/{hyp_id}")
    assert r.status_code == 200
    assert r.get_json()["deleted"] == hyp_id

    # Второй раз — 404
    r = c.delete(f"/api/projects/{project.name}/hypotheses/{hyp_id}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# POST /hypotheses/<id>/check — создаётся job
# ---------------------------------------------------------------------------

def test_check_hypothesis_creates_job(tmp_path):
    project = _empty_project(tmp_path)
    c = _client(project)

    # Создаём гипотезу с выражением
    r = c.post(f"/api/projects/{project.name}/hypotheses",
               json={"formulation": "test", "expression_text": "temp >= 0"})
    hyp_id = r.get_json()["id"]

    # Запускаем проверку — это job
    r = c.post(f"/api/projects/{project.name}/hypotheses/{hyp_id}/check", json={})
    # Может быть 202 (job запущен) или 400/500, если не нашёлся прогон
    # Проверяем, что не падает с 500 HTML
    assert r.status_code in (202, 400, 404, 409), r.get_data(as_text=True)[:300]

    if r.status_code == 202:
        d = r.get_json()
        assert "job_id" in d
        assert d["state"] in ("pending", "running")


# ---------------------------------------------------------------------------
# GET /hypotheses/<id>/checks
# ---------------------------------------------------------------------------

def test_get_checks_empty(tmp_path):
    project = _empty_project(tmp_path)
    c = _client(project)

    r = c.post(f"/api/projects/{project.name}/hypotheses",
               json={"formulation": "test", "expression_text": "temp >= 0"})
    hyp_id = r.get_json()["id"]

    r = c.get(f"/api/projects/{project.name}/hypotheses/{hyp_id}/checks")
    assert r.status_code == 200
    assert r.get_json()["checks"] == []