"""Flask application factory.

Приложение может работать в двух режимах:
1. С активным проектом: create_app(project_dir) — как раньше.
2. Без проекта (GUI-режим): create_app() или create_app(None).
   UI показывает /welcome, а /api/projects/* позволяет создать/открыть/
   импортировать проект. Активный проект переключается без перезапуска
   через POST /api/projects/open.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask

from .routes import bp as api_bp, register_error_handlers
from .ui import bp as ui_bp


def create_app(project_dir: Path | None = None) -> Flask:
    """Создаёт и конфигурирует Flask-приложение.

    Args:
        project_dir: путь к активному проекту либо None.
                     None → GUI-режим: /welcome и /api/projects/*.

    Активный проект хранится в app.config["PROJECT_DIR"] и может быть
    переключён без перезапуска процесса (см. routes.api_open_project).
    """
    app = Flask(__name__)

    app.config["PROJECT_DIR"] = (
        Path(project_dir).resolve() if project_dir else None
    )
    app.config["JSON_AS_ASCII"] = False
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024

    # API
    app.register_blueprint(api_bp, url_prefix="/api")
    register_error_handlers(app)

    # UI (без префикса)
    app.register_blueprint(ui_bp)

    return app