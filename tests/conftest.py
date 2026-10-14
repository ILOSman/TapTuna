"""Общие фикстуры для тестов (§20.2–§20.3)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from taptuna.manifest import create_manifest
from taptuna.store import init_db


@pytest.fixture
def empty_project(tmp_path: Path) -> Path:
    """Пустой проект: manifest.json + project.sqlite."""
    project = tmp_path / "project"
    project.mkdir()
    create_manifest(project)
    init_db(project)
    return project


@pytest.fixture
def sample_segments() -> list[dict]:
    """Три сегмента с payload'ом, покрывающие базовый reassembly."""
    return [
        {"abs_seq": 1000, "len": 5, "frame_number": 1, "data": b"Hello"},
        {"abs_seq": 1005, "len": 5, "frame_number": 2, "data": b"World"},
        {"abs_seq": 1010, "len": 3, "frame_number": 3, "data": b"!!!"},
    ]