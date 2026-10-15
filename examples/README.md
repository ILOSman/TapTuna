# Примеры TapTuna

Три независимых набора примеров:

1. **`interpretations/`** — готовые YAML-интерпретации, работают на любом PCAP.
2. **`demo_project/`** — синтетический проект для демонстрации (генерируется).
3. **`taptuna_core/python/taptuna/examples/`** — минимальный эталонный PCAP
   для автотестов.

---

## 1. Готовые интерпретации

Папка [`interpretations/`](interpretations/) содержит 5 YAML-файлов, каждый
демонстрирует свой механизм. Подробное описание — в
[`interpretations/README.md`](interpretations/README.md).

| Файл | Что показывает |
|---|---|
| `01_fixed_magic.yaml` | Простой fixed-framing, 13 байт |
| `02_length_prefix.yaml` | Размер из поля: `size: {from_field: len}` |
| `03_delimiter.yaml` | Разделитель CRLF, текстовый протокол |
| `04_expression.yaml` | Вычисляемые поля (`temp = temp_raw // 10`) + constraints |
| `05_corpus.yaml` | Критерии корпуса для verify |

**Как использовать** — через GUI:

1. Открыть `/interpretations` → вкладка **YAML**.
2. Вставить содержимое файла.
3. Указать имя и нажать **«Добавить»**.

Или через CLI:

```bash
taptuna interp-add --project ./myproj --file interpretations/04_expression.yaml
taptuna corpus-add --project ./myproj --name c1 --file interpretations/05_corpus.yaml
```

---

## 2. Демонстрационный проект

Синтетический проект с PCAP, интерпретацией, корпусом и журналом действий.
Используется для сценария демонстрации из [`docs/DEMO.md`](../docs/DEMO.md).

### Генерация

```bash
python examples/generate_demo.py --force
```

Создаёт `examples/demo_project/` со структурой:

```
demo_project/
├── manifest.json
├── project.sqlite
├── captures/<sha>.pcap         TCP-сессия: SYN, SYN-ACK, 13 байт, FIN
├── action_log/<sha>.entries.json
└── reports/                    отчёты (если запускался report)
```

### Что внутри

| Компонент | Что показывает |
|---|---|
| PCAP | 4 пакета: 1 capture, 1 session, 2 directions |
| `demo_fixed13@v1` | Fixed-size framing, 13 байт |
| `demo_corpus` | Критерии: порт 8080, ≥1 пакет |
| `demo_actions` | 3 действия, согласованных по времени |
| Verify run #1 | verdict=ok, 1 сообщение |
| Отчёты | `report_run1_*.{md,html,machine_model.json}` |

### Запуск

**Через GUI (Electron):**

```bash
# Если приложение уже установлено, на /welcome появится demo_project
# после первого запуска generate_demo.py — либо импортировать его:

./TapTuna-0.1.1-x86_64.AppImage
# → /welcome → «Путь на сервере» → /full/path/to/examples/demo_project
```

**Через CLI:**

```bash
taptuna serve --project examples/demo_project
# открыть http://127.0.0.1:5000
```

### Обход демонстрации

1. **Сессии** — обзор, клик по #1 → hex-viewer.
2. **Исследование** — framing tool: `fixed size=13`, `delimiter delim=2c20`,
   `length_prefix`.
3. **Интерпретации** — `demo_fixed13@v1` уже добавлена.
4. **Проверка** — run #1 завершён, verdict=ok.
5. **Журнал** — `demo_actions`, кнопка «Записи».
6. **Отчёт** — сгенерирован, открыть HTML.
7. **Проект** — сводка по 14 таблицам.

---

## 3. Эталонный PCAP для тестов

Минимальный TCP-сеанс (4 пакета, 13 байт данных) для E2E-тестов.

```bash
cd taptuna_core/python/taptuna/examples
python generate.py
```

Создаёт:

- `input/test.pcap` — SYN, SYN-ACK, ACK+payload, FIN
- `expected/test.json` — эталонная сводка

Используется в `make test-examples`. Проверяет полный цикл:
`init → ingest → interp-add → corpus-add → verify → report`.

---

## Что расширить под свой случай

### Свой PCAP

Через GUI: `/welcome` → «Путь на сервере» → указать `.pcap` → **«Импортировать»**.

Через CLI:

```bash
taptuna ingest --project ./myproj --input your.pcap
```

### Свой журнал действий

Через GUI: `/action-log` → указать путь к CSV/YAML → **«Импортировать»**.

Через CLI:

```bash
taptuna action-add --project ./myproj --file actions.csv
```

### Своя интерпретация

Через GUI: `/interpretations` → форма или YAML.

Через CLI:

```bash
taptuna interp-add --project ./myproj --file spec.yaml
```

### Свой корпус

Через GUI: `/verification` → форма создания.

Через CLI:

```bash
taptuna corpus-add --project ./myproj --name c1 --file corpus.yaml
```

---

## Форматы

- **Спецификации интерпретаций** — [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) §6
- **Методология исследования** — [`docs/METHODOLOGY.md`](../docs/METHODOLOGY.md)
- **Формат журнала действий** — CSV или YAML, см. `taptuna/action_log.py`
- **Критерии корпуса** — `{"any_ports": [...], "min_packets": N, ...}`,
  см. `CorpusCriteria` в `taptuna/verification.py`

---

## Ссылки

- [README проекта](../README.md) — обзор
- [docs/DEMO.md](../docs/DEMO.md) — сценарий демонстрации (15–20 мин)
- [docs/INSTALL.md](../docs/INSTALL.md) — установка
- [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) — техническое описание
- [docs/REUSE.md](../docs/REUSE.md) — повторное применение интерпретаций