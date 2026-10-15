# PyInstaller spec для taptuna-server.
# Собирает один бинарь, который умеет и GUI-режим, и CLI-режим.
#
# Сборка:
#   pyinstaller server.spec
#
# Результат: dist/taptuna-server (один файл, ~30 МБ)

import sys
from pathlib import Path

# Корни, из которых тянем исходники
HERE = Path(SPECPATH).resolve()
PYTHON_SRC = HERE / "python"

block_cipher = None

# Что включаем в бандл как data-файлы (не-Питон)
datas = [
    # Шаблоны Jinja
    (str(PYTHON_SRC / "taptuna" / "templates"), "taptuna/templates"),
    # Статика (CSS, JS)
    (str(PYTHON_SRC / "taptuna" / "static"), "taptuna/static"),
]

# Скрытые импорты, которые PyInstaller не видит из-за динамических импортов
hiddenimports = [
    "taptuna.app",
    "taptuna.routes",
    "taptuna.ui",
    "taptuna.verification",
    "taptuna.hypotheses",
    "taptuna.reports",
    "taptuna.interpreters",
    "taptuna.interpreters.declarative",
    "taptuna.interpreters.script_sandbox",
    "taptuna.native",
    "taptuna.native.fallback",
    "taptuna.native.reassembly",
    "taptuna.projects",
    "taptuna.action_log",
    "taptuna.manifest",
    "taptuna.store",
    # Flask тянет много всего динамически
    "flask",
    "jinja2",
    "werkzeug",
    "markupsafe",
    "itsdangerous",
    "click",
    "blinker",
    # YAML/JSON
    "yaml",
    "json",
    # Стандартная библиотека, которую PyInstaller иногда теряет
    "sqlite3",
    "hashlib",
    "multiprocessing",
    "multiprocessing.spawn",
    "queue",
    "random",
    "secrets",
]

# Native .so — путь зависит от того, где maturin положил файл.
# Обычно: taptuna_core/target/release/lib_native.so
# Или в site-packages/taptuna/_native.cpython-*.so — тут сложнее,
# PyInstaller не увидит его через python-source. Мы предполагаем,
# что `maturin develop` уже установил wheel в venv.
# PyInstaller сам подхватит .so, если он импортируется через
# `from taptuna import _native`.

a = Analysis(
    [str(PYTHON_SRC / "server_entry.py")],
    pathex=[str(PYTHON_SRC)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Раздувают бандл, не нужны
        "tkinter", "matplotlib", "numpy", "pandas", "IPython",
        "pytest", "setuptools", "pip", "wheel",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="taptuna-server",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,             # UPX часто ломает .so, не включаем
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # console=False: без терминала при запуске
                            # из .AppImage. Логи всё равно идут в stderr,
                            # Electron их перехватит.
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)