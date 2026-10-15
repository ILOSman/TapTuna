"""Менеджер проектов: реестр, создание, открытие, экспорт/импорт.

Проекты хранятся по путям, записанным в реестре:
    <config_dir>/projects.json

По умолчанию config_dir = ~/TapTuna (см. DEFAULT_ROOT).
Реестр — это JSON:
    {"projects": [{"id": "...", "name": "...", "path": "...",
                   "created_at": "...", "last_opened": "..."}]}

Экспорт проекта — zip с расширением .taptuna.zip, содержит:
    manifest.json, project.sqlite, captures/, blobs/,
    action_log/, reports/

Импорт: распаковка zip в выбранную папку + регистрация.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from .errors import ProtocolLabError, ValidationError
from .manifest import create_manifest, load_manifest
from .store import init_db, open_db


# ---------------------------------------------------------------------------
# Пути
# ---------------------------------------------------------------------------

DEFAULT_ROOT = Path.home() / "TapTuna"
PROJECTS_SUBDIR = "projects"
REGISTRY_FILE = "projects.json"

_SLUG_RE = re.compile(r"[^a-zA-Z0-9_\-\.]+")


def _slugify(name: str, fallback: str = "project") -> str:
    """Приводит имя к безопасному имени папки: sensor-1 → sensor_1."""
    s = _SLUG_RE.sub("_", name.strip())
    s = s.strip("._-")
    if not s:
        s = fallback
    return s[:64]


# ---------------------------------------------------------------------------
# Реестр
# ---------------------------------------------------------------------------

def _config_dir() -> Path:
    """Каталог конфигурации: TAPTUNA_HOME или ~/TapTuna."""
    env = os.environ.get("TAPTUNA_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return DEFAULT_ROOT


def _registry_path() -> Path:
    return _config_dir() / REGISTRY_FILE


def _load_registry() -> dict:
    p = _registry_path()
    if not p.exists():
        return {"projects": [], "active_id": None}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"projects": [], "active_id": None}


def _save_registry(reg: dict) -> None:
    p = _registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)


def _project_id(path: Path) -> str:
    """Стабильный id: sha1 от нормализованного пути, 12 hex-символов."""
    import hashlib
    h = hashlib.sha1(str(path.resolve()).encode("utf-8")).hexdigest()
    return h[:12]


# ---------------------------------------------------------------------------
# Модель
# ---------------------------------------------------------------------------

@dataclass
class ProjectInfo:
    id: str
    name: str
    path: str
    created_at: str
    last_opened: str
    size_bytes: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def _build_info(path: Path) -> ProjectInfo:
    path = path.resolve()
    pid = _project_id(path)
    st = path.stat() if path.exists() else None
    return ProjectInfo(
        id=pid,
        name=path.name,
        path=str(path),
        created_at=(
            time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(st.st_ctime))
            if st else ""
        ),
        last_opened=time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        size_bytes=_dir_size(path) if path.exists() else 0,
    )


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            pass
    return total


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def list_projects() -> list[dict]:
    """Все известные проекты с актуальным размером.

    `name` берётся из реестра (display-имя), а не из имени папки —
    их можно переопределить через rename_display без переименования
    папки на диске.
    """
    reg = _load_registry()
    out: list[dict] = []
    changed = False
    for entry in reg.get("projects", []):
        path = Path(entry["path"])
        if not path.exists():
            changed = True
            continue
        info = _build_info(path)
        info.created_at = entry.get("created_at") or info.created_at
        info.last_opened = entry.get("last_opened") or info.last_opened
        # display-имя из реестра имеет приоритет над именем папки
        if entry.get("name"):
            info.name = entry["name"]
        out.append(info.to_dict())
    if changed:
        _save_registry({"projects": out, "active_id": reg.get("active_id")})
    return out


def find_by_path(path: Path) -> Optional[dict]:
    """Находит запись реестра по пути проекта. None если не в реестре."""
    target = Path(path).resolve()
    for p in list_projects():
        try:
            if Path(p["path"]).resolve() == target:
                return p
        except OSError:
            continue
    return None


def set_active(project_id: str) -> dict:
    reg = _load_registry()
    for p in reg.get("projects", []):
        if p.get("id") == project_id:
            if not Path(p["path"]).exists():
                raise ValidationError(
                    code="PROJECT_PATH_MISSING",
                    message=f"Project directory not found: {p['path']}",
                    details={"path": p["path"]},
                )
            p["last_opened"] = time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime())
            reg["active_id"] = project_id
            _save_registry(reg)
            return p
    raise ValidationError(
        code="PROJECT_NOT_FOUND",
        message=f"Project id={project_id} not found",
        details={"id": project_id},
    )


def _display_name_taken(name: str, exclude_id: Optional[str] = None) -> bool:
    for p in list_projects():
        if p.get("name") == name and p.get("id") != exclude_id:
            return True
    return False


def make_unique_display_name(base: str, exclude_id: Optional[str] = None) -> str:
    """sensor1 → sensor1; если занято → sensor1_2, sensor1_3, ..."""
    slug = _slugify(base, fallback="project")
    if not _display_name_taken(slug, exclude_id):
        return slug
    i = 2
    while True:
        candidate = f"{slug}_{i}"
        if not _display_name_taken(candidate, exclude_id):
            return candidate
        i += 1


def rename_display(project_id: str, new_name: str) -> dict:
    """Меняет отображаемое имя проекта в реестре. Папку НЕ переименовывает.

    Если new_name занято другим проектом — добавит _N.
    Возвращает обновлённую запись.
    """
    reg = _load_registry()
    entry = next(
        (p for p in reg.get("projects", []) if p.get("id") == project_id),
        None,
    )
    if entry is None:
        raise ValidationError(
            code="PROJECT_NOT_FOUND",
            message=f"Project id={project_id} not found",
            details={"id": project_id},
        )
    entry["name"] = make_unique_display_name(new_name, exclude_id=project_id)
    _save_registry(reg)
    return entry


def create_project(name: str, parent: Optional[Path] = None) -> dict:
    """Создаёт новый проект на диске и регистрирует его.

    Args:
        name: имя проекта. Станет именем папки (slug-нормализация).
        parent: где создать. По умолчанию <config_dir>/projects/.
    """
    slug = _slugify(name)
    if not slug:
        raise ValidationError(
            code="BAD_NAME",
            message="Project name must contain letters/digits",
            details={"name": name},
        )
    base = Path(parent).expanduser().resolve() if parent else (
        _config_dir() / PROJECTS_SUBDIR)
    base.mkdir(parents=True, exist_ok=True)

    target = base / slug
    if target.exists():
        # Автоуникализация: sensor → sensor_2, sensor_3, ...
        i = 2
        while (base / f"{slug}_{i}").exists():
            i += 1
        target = base / f"{slug}_{i}"

    target.mkdir(parents=True)
    create_manifest(target)
    init_db(target)

    info = _build_info(target)
    _register(info)
    return info.to_dict()


def open_project_path(path: Path) -> dict:
    """Открывает существующий проект по пути (без импорта)."""
    path = Path(path).expanduser().resolve()
    if not (path / "manifest.json").exists():
        raise ValidationError(
            code="NOT_A_PROJECT",
            message=f"Not a taptuna project: {path} (manifest.json missing)",
            details={"path": str(path)},
        )
    info = _build_info(path)
    _register(info)
    return info.to_dict()


def forget_project(project_id: str) -> bool:
    """Убирает проект из реестра (файлы не удаляются)."""
    reg = _load_registry()
    before = len(reg.get("projects", []))
    reg["projects"] = [p for p in reg["projects"] if p.get("id") != project_id]
    if reg.get("active_id") == project_id:
        reg["active_id"] = None
    _save_registry(reg)
    return len(reg["projects"]) < before


def _register(info: ProjectInfo) -> None:
    reg = _load_registry()
    existing = next(
        (p for p in reg.get("projects", []) if p.get("id") == info.id),
        None,
    )
    info_dict = info.to_dict()
    # Сохраняем display-имя, если оно уже было переопределено
    # через rename_display. Иначе имя = имя папки.
    if existing and existing.get("name"):
        info_dict["name"] = existing["name"]
    reg["projects"] = [p for p in reg.get("projects", [])
                       if p.get("id") != info.id]
    reg["projects"].append(info_dict)
    reg["active_id"] = info.id
    _save_registry(reg)


# ---------------------------------------------------------------------------
# Экспорт / импорт
# ---------------------------------------------------------------------------

EXPORT_EXT = ".taptuna.zip"


def export_zip(project_id: str, target: Path) -> Path:
    """Упаковывает проект в zip.

    target — путь к .taptuna.zip (или папка — тогда имя по проекту).
    """
    reg = _load_registry()
    entry = next((p for p in reg.get("projects", []) if p.get("id") == project_id), None)
    if entry is None:
        raise ValidationError(
            code="PROJECT_NOT_FOUND",
            message=f"Project id={project_id} not found",
            details={"id": project_id},
        )
    src = Path(entry["path"]).resolve()
    if not src.exists():
        raise ValidationError(
            code="PROJECT_PATH_MISSING",
            message=f"Project directory gone: {src}",
            details={"path": str(src)},
        )

    target = Path(target).expanduser()
    if target.is_dir():
        target = target / f"{entry['name']}{EXPORT_EXT}"
    target = target.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    # Пишем через временный файл, чтобы не оставить битый zip при ошибке
    tmp = target.with_suffix(target.suffix + ".part")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in src.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(src)
            zf.write(p, arcname=str(rel))
    tmp.replace(target)
    return target


def import_zip(
    source: Path,
    parent: Optional[Path] = None,
    preferred_name: Optional[str] = None,
) -> dict:
    """Распаковывает .taptuna.zip и регистрирует проект.

    Args:
        source: путь к .taptuna.zip (может быть временным файлом).
        parent: где создать проект. По умолчанию <config>/projects/.
        preferred_name: имя проекта. Если задано — используется оно
            (важно для multipart-загрузки, где файл на диске сервера
            имеет временное имя вроде upload.zip).
    """
    source = Path(source).expanduser().resolve()
    if not source.is_file():
        raise ValidationError(
            code="ZIP_NOT_FOUND",
            message=f"Zip not found: {source}",
            details={"path": str(source)},
        )

    # Имя папки: preferred_name → оригинальное имя zip без .taptuna.zip
    stem = preferred_name if preferred_name else source.name
    for suf in (EXPORT_EXT, ".zip"):
        if stem.endswith(suf):
            stem = stem[: -len(suf)]
            break
    slug = _slugify(stem, "imported")

    base = Path(parent).expanduser().resolve() if parent else (
        _config_dir() / PROJECTS_SUBDIR)
    base.mkdir(parents=True, exist_ok=True)

    target = base / slug
    if target.exists():
        i = 2
        while (base / f"{slug}_{i}").exists():
            i += 1
        target = base / f"{slug}_{i}"

    # Распаковка в tmp, затем перемещение — чтобы не оставить частичный проект
    tmpdir = Path(tempfile.mkdtemp(prefix="taptuna_import_", dir=str(base)))
    try:
        with zipfile.ZipFile(source, "r") as zf:
            # Защита от zip-slip: все пути внутри tmpdir
            for member in zf.namelist():
                target_path = (tmpdir / member).resolve()
                if not str(target_path).startswith(str(tmpdir)):
                    raise ValidationError(
                        code="BAD_ZIP",
                        message=f"Unsafe path in zip: {member}",
                        details={"member": member},
                    )
            zf.extractall(tmpdir)

        if not (tmpdir / "manifest.json").exists():
            raise ValidationError(
                code="BAD_ZIP",
                message="Zip does not contain manifest.json — not a taptuna project",
                details={"source": str(source)},
            )
        tmpdir.rename(target)
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise

    info = _build_info(target)
    _register(info)
    return info.to_dict()


# ---------------------------------------------------------------------------
# Проверка целостности
# ---------------------------------------------------------------------------

def project_integrity(project_dir: Path) -> dict:
    """Используется UI для проверки, что проект не битый."""
    project_dir = Path(project_dir).resolve()
    out = {
        "path": str(project_dir),
        "has_manifest": (project_dir / "manifest.json").exists(),
        "has_db": (project_dir / "project.sqlite").exists(),
        "captures_total": 0,
        "captures_missing": 0,
        "blobs_total": 0,
        "blobs_missing": 0,
        "missing_list": [],
    }
    if not out["has_db"]:
        return out

    conn = open_db(project_dir)
    try:
        cur = conn.cursor()
        cur.execute("SELECT sha256, filename FROM captures")
        for row in cur.fetchall():
            out["captures_total"] += 1
            if not (project_dir / "captures" / f"{row['sha256']}.pcap").exists():
                out["captures_missing"] += 1
                out["missing_list"].append(f"capture: {row['filename']}")
        cur.execute("""SELECT DISTINCT payload_sha256 FROM packets
                       WHERE payload_sha256 IS NOT NULL
                         AND payload_inline IS NULL""")
        for row in cur.fetchall():
            out["blobs_total"] += 1
            if not (project_dir / "blobs" / f"{row['payload_sha256']}.bin").exists():
                out["blobs_missing"] += 1
                out["missing_list"].append(f"blob: {row['payload_sha256'][:16]}…")
    finally:
        conn.close()
    return out


# ---------------------------------------------------------------------------
# Именование по PCAP
# ---------------------------------------------------------------------------

def suggest_project_name(pcap_path: Path) -> str:
    """Предлагает имя проекта по имени PCAP: sensor1.pcap → sensor1."""
    stem = Path(pcap_path).stem
    return _slugify(stem, fallback="project")


def suggest_interpretation_name(project_name: str, kind: str = "main") -> str:
    """sensor1 + fixed → sensor1_fixed."""
    return f"{_slugify(project_name, 'project')}_{_slugify(kind, 'main')}"


def suggest_corpus_name(project_name: str, suffix: str = "all") -> str:
    return f"{_slugify(project_name, 'project')}_{_slugify(suffix, 'all')}"