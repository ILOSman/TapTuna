# Changelog

## v0.1.0 — первая публичная версия

### Возможности

- **Ingest:** один вызов tshark на PCAP, TSV → сессии, sha256 источника.
- **Reassembly:** RFC 9293, ±2³¹, seed из SYN, dedup повторных передач,
  gaps без zero-fill, ambiguities с политикой.
- **Framing:** 4 стратегии (length_prefix, delimiter, fixed, regex).
- **Extract:** 13 типов полей, offset/size через safe-eval.
- **Safe-eval:** whitelist AST, арифметика, сравнения, побитовые, constraints.
- **Script sandbox:** отдельный процесс, whitelist импортов, RLIMIT_CPU/AS/FSIZE,
  wall-clock timeout, respawn.
- **Верификация:** корпус, 5 статусов, вердикт, `run_hash` для cross-check.
- **Отчёты:** Markdown → HTML + `machine_model.json`.
- **Действия:** импорт CSV/YAML, связь с сессиями по времени.
- **CLI:** 13 команд (`init`, `ingest`, `serve`, `interp-add`, `interp-apply`,
  `corpus-add`, `corpus-list`, `verify`, `runs`, `results`, `report`,
  `action-add`, `action-list`).
- **REST API:** 36 эндпоинтов + SSE для долгих операций.
- **UI:** 9 экранов на localhost, виртуальный hex-viewer, framing-tool,
  side-by-side сравнение, overlay журнала действий.
- **Проект:** SQLite (14 таблиц), relative paths, переносимость.
- **Fallback:** чистая Python-реализация при `TAPTUNA_NATIVE=0`.

### UI-детали
- Клик по байту в hex-viewer → popup с frame_number, seq, flags.
- Переход из результатов verify к байтам источника (`?offset=N&direction=X`).
- Framing-tool с 4 стратегиями, экспорт JSON.
- Панель «Применить интерпретацию» прямо на `/research`.
- Гипотезы и наблюдения с привязкой к offset.
- Side-by-side сравнение двух сессий с синхронизацией скролла.
- Overlay журнала действий на сессии по временному окну.
- Группировка сессий по capture (optgroup + фильтр).

### Производительность

- Reassembly 100 МиБ: **46.8 ms** (2.08 GiB/s).
- Пиковая память 100 МиБ: **290.7 MiB** (×2.9 от входа).
- Требование §12.7 (≤ 90 с на 100 МиБ): выполнено с запасом ×1923.
- Framing 100k сообщений: **47.4 MiB** пиковой памяти Python (было 116.3 MiB
  до оптимизации PyO3 → PyBytes).

### Платформы

- Linux x86_64 (glibc, musl).
- Linux aarch64 (glibc, musl).
- macOS arm64.
- Windows x86_64.
- Python 3.11, 3.12, 3.13, 3.14 (abi3-py311).

### Известные ограничения

- Только TCP/IPv4 поверх Ethernet. IPv6, IP-фрагментация, non-Ethernet L2 —
  диагностируются как неподдерживаемые.
- Один интерфейс, одна точка захвата.
- Checksum-поля могут быть некорректны при локальном захвате (offloading).

### Зависимости

- Rust: pyo3 0.22, thiserror, sha2, regex, once_cell.
- Python: flask, markdown, jinja2, pyyaml.
- Внешние: tshark 4.0+.