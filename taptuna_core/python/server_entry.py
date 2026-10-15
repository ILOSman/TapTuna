"""Точка входа для PyInstaller: запускает Flask без открытия браузера.

Аргументы:
    --port N        порт (по умолчанию 5000)
    --host HOST     хост (по умолчанию 127.0.0.1)
    --no-project    GUI-режим, без активного проекта

Этот файл попадает в PyInstaller-бандл как entry point.
"""
import argparse
import logging
import os
import sys
from pathlib import Path


def _setup_logging() -> None:
    """Логи в stderr + ~/TapTuna/logs/server.log (с ротацией в .1)."""
    home = Path(os.environ.get("TAPTUNA_HOME",
                               str(Path.home() / "TapTuna")))
    log_dir = home / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "server.log"

    # Простая ротация: если > 5 МБ — переименовываем в .1 (перезапись)
    try:
        if log_file.exists() and log_file.stat().st_size > 5 * 1024 * 1024:
            backup = log_file.with_name("server.log.1")
            if backup.exists():
                backup.unlink()
            log_file.rename(backup)
    except OSError:
        pass

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    try:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    except OSError:
        pass  # если диск занят/нет прав — работаем только со stderr

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )


def main() -> int:
    _setup_logging()

    # Когда PyInstaller распаковывает onefile, sys._MEIPASS содержит
    # временную папку с данными. TAPTUNA_HOME — где хранить проекты.
    if "TAPTUNA_HOME" not in os.environ:
        os.environ["TAPTUNA_HOME"] = str(Path.home() / "TapTuna")

    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-project", action="store_true",
                    help="GUI-режим без активного проекта (по умолчанию)")
    ap.add_argument("--project", default=None,
                    help="путь к проекту (опционально)")
    args = ap.parse_args()

    from taptuna.app import create_app

    project = Path(args.project) if args.project else None
    app = create_app(project)

    # Проверка tshark при старте — если нет, всё равно стартуем,
    # но логируем предупреждение. UI покажет ошибку при ingest.
    from taptuna.tshark_check import get_tshark_path
    if get_tshark_path() is None:
        logging.warning("tshark не найден в PATH — ingest не будет работать. "
                        "Установите: sudo apt install tshark")

    # Отключаем reloader и debug (иначе PyInstaller запустит второй процесс)
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())