"""Flask application factory."""

from __future__ import annotations

from pathlib import Path

from flask import Flask

from .routes import bp as api_bp, register_error_handlers
from .ui import bp as ui_bp


def create_app(project_dir: Path) -> Flask:
    """Создаёт и конфигурирует Flask-приложение для проекта."""
    app = Flask(__name__)
    app.config["PROJECT_DIR"] = Path(project_dir)
    app.config["JSON_AS_ASCII"] = False
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024
    # API
    app.register_blueprint(api_bp, url_prefix="/api")
    register_error_handlers(app)

    # UI (без префикса)
    app.register_blueprint(ui_bp)

    return app
