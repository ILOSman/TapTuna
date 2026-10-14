# TapTuna — Лаборатория протоколов

Инструмент для исследования недокументированного бинарного обмена поверх TCP/IPv4:
от PCAP до проверяемой интерпретации, пригодной для передачи другому инженеру.

## Что умеет

- Открывает PCAP/PCAPNG, восстанавливает направленные TCP-потоки по RFC 9293.
- Явно обозначает пропуски, перекрытия и неоднозначности; не подменяет неизвестное нулями.
- Позволяет исследовать границы сообщений (4 стратегии фрейминга) и поля (13 типов).
- Декларативные интерпретации + песочница для script-интерпретаций.
- Верификация на корпусе: 5 статусов, `violation > ambiguous > incomplete > ok`.
- Отчёты: Markdown (source of truth) → HTML + `machine_model.json`.
- Локальный веб-интерфейс на `127.0.0.1:5000` (9 экранов, SSE для долгих операций).
- Воспроизводимость: `manifest.json` + относительные пути + `stale` для устаревших результатов.

## Требования

- Linux x86-64 (основная платформа) или macOS/Windows.
- Python 3.11+ (проверено на 3.14).
- Rust toolchain (для сборки нативного ядра).
- TShark 4.0+ в `PATH` или `TAPTUNA_TSHARK=/путь/к/tshark`.
- 4 vCPU, 8 GiB RAM — профиль измерения (§10 ТЗ).

## Установка

```bash
# 1. Python-зависимости и editable install
python -m venv .venv
source .venv/bin/activate
pip install -e taptuna_core
pip install -e .           # корневой пакет (CLI)

# 2. Проверка нативного ядра
python -c "from taptuna.native import native_status; print(native_status())"
# Ожидаемо: {'has_native': True, ...}

# 3. Проверка tshark
python -c "from taptuna.tshark_check import get_tshark_path; print(get_tshark_path())"
```

### Если Rust не установлен

`taptuna.native` автоматически перейдёт на чистую Python-реализацию
(`HAS_NATIVE=False`). Функциональность сохраняется, скорость падает.
Принудительный fallback: `TAPTUNA_NATIVE=0`.

## Быстрый старт

```bash
# 1. Создать проект
taptuna init --project ./myproj

# 2. Импортировать запись
taptuna ingest --project ./myproj --input capture.pcap

# 3. Добавить интерпретацию
taptuna interp-add --project ./myproj --file interp.yaml

# 4. Добавить корпус
taptuna corpus-add --project ./myproj --name corpus1 --file corpus.yaml

# 5. Прогнать верификацию
taptuna verify --project ./myproj --corpus corpus1 --interpretation interp_name

# 6. Отчёт
taptuna report --project ./myproj --run 1 --format md,html,json

# 7. UI
taptuna serve --project ./myproj --port 5000
# Открыть http://127.0.0.1:5000
```

## CLI — 13 команд (§11.3)

```
taptuna init           — инициализировать проект
taptuna ingest         — импортировать PCAP/PCAPNG
taptuna serve          — запустить веб-сервер
taptuna interp-add     — добавить интерпретацию
taptuna interp-apply   — применить интерпретацию к сессии
taptuna corpus-add     — добавить корпус
taptuna corpus-list    — список корпусов
taptuna verify         — прогнать верификацию
taptuna runs           — список прогонов
taptuna results        — результаты прогона
taptuna report         — сгенерировать отчёт
taptuna action-add     — импортировать журнал действий
taptuna action-list    — список журналов
```

## Пример: минимальная интерпретация

```yaml
# interp.yaml — fixed-size 13-байтовые сообщения
name: example_fixed
kind: declarative
framing:
  kind: fixed
  size: 13
  max_message: 1024
fields:
  name: message
  fields:
    - name: raw
      type: bytes
      offset: 0
      size: 13
constraints: []
semantics: {}
```

```yaml
# corpus.yaml — все сессии на порту 8080
any_ports: [8080]
min_packets: 1
```

## Примеры данных

```bash
# Сгенерировать эталонный PCAP + specs
python -m taptuna.examples.generate

# Прогнать полный E2E-сценарий
make test-examples
```

## Тесты

```bash
make test              # Rust + Python
make test-python       # pytest tests/
make test-examples     # E2E на эталонном PCAP
make bench             # cargo bench --no-run
```

## Структура проекта

```
Taptuna_my/
├── taptuna_core/                # Rust-ядро + Python-пакет
│   ├── src/                     # Rust: wire, seq, reassembly, framing, extract, safe_eval
│   ├── python/taptuna/          # Python: CLI, API, UI, движки, отчёты
│   ├── Cargo.toml
│   └── pyproject.toml
├── tests/                       # pytest: ingest, sandbox, cross-validation, portability
├── docs/                        # ARCHITECTURE.md, DoD.md, REUSE.md
├── examples/                    # эталонные PCAP (генерируются)
├── Makefile
└── README.md
```

## Документация

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — подход, слои, форматы, зависимости, ограничения.
- [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) — методология исследования: framing → гипотезы → интерпретация → верификация.
- [`docs/DEMO.md`](docs/DEMO.md) — пошаговый сценарий демонстрации (15–20 мин).
- [`docs/DoD.md`](docs/DoD.md) — результаты проверки требований и измерения ресурсов.
- [`docs/REUSE.md`](docs/REUSE.md) — как применить сохранённую интерпретацию к новой записи.
- [`docs/COMPARISON.md`](docs/COMPARISON.md) — обоснование стека (Rust + PyO3 + Flask + SQLite).
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — частые проблемы.
- [`examples/README.md`](examples/README.md) — готовый демонстрационный проект.

## Быстрая проверка

```bash
make demo              # сгенерировать готовый проект
make test              # Rust + Python тесты
make test-examples     # E2E на эталонном PCAP
```

## Ограничения

- Только TCP/IPv4 поверх Ethernet. IPv6, IP-фрагментация и другие L2 — диагностируются как неподдерживаемые.
- Один интерфейс, одна точка захвата. Multi-interface и распределённый захват — вне сценария.
- Расшифровка TLS, разбор сжатых данных, восстановление полного автомата состояний — не входят.