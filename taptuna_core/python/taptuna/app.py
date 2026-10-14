"""Flask application factory."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify

from .errors import ProtocolLabError
from .routes import bp as api_bp, register_error_handlers


def create_app(project_dir: Path) -> Flask:
    """Создаёт и конфигурирует Flask-приложение для проекта.

    Важно: не создаёт manifest.json и project.sqlite. Для инициализации
    проекта используйте `POST /api/projects` или `taptuna init`.
    """
    app = Flask(__name__)
    app.config["PROJECT_DIR"] = Path(project_dir)

    app.register_blueprint(api_bp, url_prefix="/api")

    # Единый источник error handlers — routes.py
    register_error_handlers(app)

    @app.errorhandler(ProtocolLabError)
    def handle_taptuna_error(e: ProtocolLabError):
        return jsonify(e.to_dict()), e.http_status

    return app