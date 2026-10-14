# Архитектура TapTuna

Документ описывает выбранный подход, слои, форматы, зависимости и ограничения.

## 1. Подход

Задача — дать инженеру **воспроизводимый** способ исследовать недокументированный
обмен. Ключевые принципы:

1. **Источник неизменен.** PCAP копируется в `captures/<sha256>.pcap`, sha256 хранится
   в манифесте. Повторный импорт того же файла — явное предупреждение.
2. **Происхождение прослеживается.** Каждый байт потока имеет `frame_number` в
   `byte_map`. Любой результат ссылается на `session_id`, `direction_id`,
   `stream_offset` — от них можно вернуться к пакету.
3. **Изменение интерпретации не меняет байты.** Интерпретации версионируются
   (`interpretations.name, version`). Результаты старой версии помечаются `stale`
   при чтении, но не удаляются.
4. **Неизвестное не подменяется.** Пропуски в потоке — `gaps`; перекрытия с
   разными данными — `ambiguities`. Zero-fill запрещён.
5. **Неопределённость видна.** 5 статусов сообщений: `ok`, `violation`,
   `ambiguous`, `incomplete`, `not_applicable`. Вердикт прогона —
   самый «тяжёлый» из встреченных.
6. **Правило отделено от гипотезы.** Результат движка — правило, применённое к
   байтам. Гипотеза — предположение о смысле. Живут в разных таблицах
   (`verification_results` vs `hypotheses`).

## 2. Слои

```
┌──────────────────────────────────────────────────────────────┐
│ UI (Jinja2 + JS)          /sessions, /research, /verify, ... │
├──────────────────────────────────────────────────────────────┤
│ REST API + SSE            Flask + jobs + EventSource          │
├──────────────────────────────────────────────────────────────┤
│ Движки                    declarative, script (sandbox)       │
├──────────────────────────────────────────────────────────────┤
│ Верификация               corpus, statuses, run_hash          │
├──────────────────────────────────────────────────────────────┤
│ Отчёты                    MD → HTML, machine_model.json       │
├──────────────────────────────────────────────────────────────┤
│ Хранилище                 SQLite (14 таблиц) + blobs/         │
├──────────────────────────────────────────────────────────────┤
│ Ingest                    один вызов tshark, TSV → сессии     │
├──────────────────────────────────────────────────────────────┤
│ Reassembly (Rust/PyO3)    wire → seq → reassembly             │
└──────────────────────────────────────────────────────────────┘
```

## 3. Rust-ядро (`taptuna_core`)

Собрано как Python-расширение через PyO3 (abi3-py3.11). Шесть модулей:

| Модуль | Назначение |
|---|---|
| `wire` | Ethernet + IPv4 + TCP, VLAN, отказ на фрагментах |
| `seq` | RFC 9293, ±2³¹, seed из SYN |
| `reassembly` | Склейка, dedup, gaps, ambiguities, byte_map |
| `framing` | 4 стратегии: length_prefix, delimiter, fixed, regex |
| `extract` | 13 типов полей, offset/size через safe-eval |
| `safe_eval` | whitelist AST: арифметика, сравнения, побитовые |

**Почему Rust:** reassembly на 100 МиБ должен укладываться в 90 с.
Rust даёт 174 MiB/s на 100 МиБ (0.58 с) — в 156 раз быстрее лимита.
Python-fallback байт-идентичен, используется при `TAPTUNA_NATIVE=0`.

## 4. Python-пакет (`taptuna`)

| Модуль | Назначение |
|---|---|
| `manifest` | `manifest.json`: версии, политики, pip_freeze |
| `store` | SQLite: 14 таблиц, мигратор, CAS |
| `ingest` | Один вызов `tshark -r`, TSV → сессии |
| `native` | Обёртка над `_native` + fallback |
| `interpreters/` | `declarative`, `script_sandbox` |
| `verification` | Корпус, классификация, `run_hash` |
| `reports` | MD/HTML + `machine_model.json` |
| `action_log` | Импорт CSV/YAML, связь с сессиями |
| `jobs` | Фоновые задачи + SSE |
| `routes`, `ui`, `app` | Flask |
| `cli` | 13 команд |

## 5. Формат проекта

```
myproj/
├── manifest.json          # schema_version, политики, pip_freeze
├── project.sqlite         # 14 таблиц, PRAGMA user_version
├── captures/
│   └── <sha256>.pcap
├── blobs/
│   └── <sha256>.bin       # payload > 4 КиБ (CAS)
├── action_log/
│   └── <sha256>.entries.json
└── reports/
    └── report_run1_<ts>.{md,html,machine_model.json}
```

**Переносимость:** пути внутри `project.sqlite` относительные (`captures/<sha>.pcap`,
`blobs/<sha>.bin`). Перенос каталога не ломает проект.

## 6. Формат интерпретации

Декларативная (YAML):

```yaml
name: my_protocol
kind: declarative
framing:
  kind: length_prefix
  prefix_bytes: 2
  big_endian: true
  length_includes_prefix: false
  max_message: 65536
fields:
  name: message
  fields:
    - {name: magic, type: u16be, offset: auto, size: 2}
    - {name: length, type: u16be, offset: auto, size: 2}
    - {name: payload, type: bytes, offset: auto, size: {from_field: length}}
constraints:
  - {op: lt, a: {op: field, name: length}, b: {op: const, value: 65536}}
semantics:
  fields:
    magic: {meaning: "идентификатор протокола"}
```

Script (Python в sandbox):

```yaml
name: my_script
kind: script
code: |
  def interpret(payload, index, stream_offset):
      magic = payload[0:2]
      return {"status": "ok", "fields": {"magic": magic.hex()}}
```

## 7. Зависимости

**Rust:** `pyo3 0.22` (abi3-py3.11), `thiserror`, `sha2`, `regex`, `once_cell`.
**Python:** `flask`, `markdown`, `jinja2`, `pyyaml`.
**Тесты:** `pytest`, `scapy`.
**Внешние:** `tshark` 4.0+.

## 8. Ограничения

- **Только TCP/IPv4 + Ethernet.** IPv6, IP-фрагментация, ARP-only, non-Ethernet —
  диагностируются, не анализируются.
- **Один интерфейс, одна точка захвата.** Merge нескольких PCAP — не поддерживается
  в обязательном сценарии.
- **Checksum offloading.** Checksum-поля IP/TCP могут быть некорректны в локальных
  захватах. Политика `checksum: verify` (default) не блокирует анализ, но результат
  помечается в отчёте.
- **Таймауты sandbox.** Script-интерпретации ограничены CPU (10 с), память (512 MiB),
  wall-clock (5 с на сообщение). Превышение → `unknown_frame`.
- **Защитные пределы.**
  - `max_stream_bytes` — верхний предел объёма потока.
  - `max_output_bytes` — лимит вывода tshark (10 GiB по умолчанию).
  - `MAX_CONTENT_LENGTH` — лимит загрузки через UI (2 GiB).

## 9. Что не входит

Захват трафика, расшифровка TLS, разбор сжатых данных, восстановление полного
автомата состояний — вне обязательного сценария