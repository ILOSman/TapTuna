Как применить сохранённую интерпретацию к новой записи **без повторения
ручной исследовательской работы**.

## Сценарий

Есть проект `research/` с интерпретацией `my_protocol@v3` и корпусом
`corpus_v1`. Появилась новая запись `new.pcap`. Нужно проверить, что
интерпретация применима, и получить результат.

## Способ 1: CLI (быстро, для 1 записи)

```bash
# 1. Копируем проект (или работаем в существующем)
cp -r research/ research_extended/
cd research_extended/

# 2. Импортируем новую запись
taptuna ingest --project . --input new.pcap

# 3. Применяем сохранённую интерпретацию к новым сессиям
taptuna verify --project . --corpus corpus_v1 --interpretation my_protocol@v3

# 4. Результат
taptuna runs --project .
taptuna results --project . --run <id>
taptuna report  --project . --run <id> --format md,html,json
```

Результат сохраняется в `reports/report_run<N>_*.{md,html,machine_model.json}`.

## Способ 2: Python (для автоматизации)

```python
from pathlib import Path
from taptuna.ingest import ingest_capture
from taptuna.verification import verify_corpus
from taptuna.reports import generate_report

project = Path("research_extended")

# 1. Ingest
ingest_capture(project, Path("new.pcap"))

# 2. Verify (нужны corpus_id и interpretation_id — берём из БД или
#    по имени через select_sessions)
from taptuna.store import open_db
conn = open_db(project)
cur = conn.cursor()
cur.execute("SELECT id FROM corpora WHERE name='corpus_v1'")
corpus_id = cur.fetchone()[0]
cur.execute("SELECT id FROM interpretations WHERE name='my_protocol' ORDER BY version DESC LIMIT 1")
interp_id = cur.fetchone()[0]
conn.close()

result = verify_corpus(
    project_dir=project,
    corpus_id=corpus_id,
    interpretation_id=interp_id,
    seed=0,
)
print(f"verdict: {result['verdict']}, messages: {result['messages']}, run_hash: {result['run_hash']}")

# 3. Report
paths = generate_report(project, run_id=result["run_id"])
print(paths)
```

## Способ 3: `machine_model.json` (для внешних инструментов)

`machine_model.json` — воспроизводимая модель, не зависящая от TapTuna:

```json
{
  "format_version": 1,
  "interpretation": {"name": "my_protocol", "version": 3, "kind": "declarative"},
  "framing": {"kind": "length_prefix", "prefix_bytes": 2, ...},
  "fields": {"name": "message", "fields": [...]},
  "constraints": [...],
  "semantics": {...},
  "provenance": {"app_version": "0.1.0", "tshark_version": "4.7.4", ...}
}
```

Любой внешний код может прочитать `framing` и `fields` и применить их к
байтам. Например, для Python:

```python
import json
from taptuna.interpreters.declarative import DeclarativeInterpreter

model = json.load(open("machine_model.json"))
interp = DeclarativeInterpreter(model, name=model["interpretation"]["name"])

# Применяем к потоку, полученному любым способом
stream = b"..."
messages = interp.interpret(stream, direction_id=1)
for m in messages:
    print(m.status.value, m.fields)
```

## Воспроизводимость

При одинаковых:
- исходных PCAP (sha256),
- версии интерпретации (`name@version`),
- seed,
- политиках (`overlap`, `checksum`),

прогон `verify` даёт **идентичный `run_hash`**. Это проверяется в
`tests/test_cross_validation.py::test_verify_deterministic_hash`.

Если `run_hash` различается — проверьте:

1. Изменился ли PCAP (sha256 в `captures`).
2. Изменилась ли версия интерпретации.
3. Изменился ли seed.
4. Изменились ли политики в `manifest.json`.

## Что делать с устаревшими результатами

Старые `verification_runs` не удаляются. Если интерпретация получила новую
версию (`v3` → `v4`), результаты `v3` помечаются `stale` при чтении:

```bash
taptuna runs --project .    # увидите все прогоны
```

В UI: `/verification` — колонка `stale`.

Чтобы актуализировать:

```bash
taptuna verify --project . --corpus corpus_v1 --interpretation my_protocol@v4
```

## Ограничения области применения

Интерпретация `my_protocol@v3` применима к TCP-потокам, попадающим в критерии
`corpus_v1`. Перенос на другие порты/протоколы требует:

1. Нового корпуса с расширенными критериями.
2. Проверки, что framing не ломается на новых данных.
3. Возможно — новой версии интерпретации.

Отчёт (`reports/report_run<N>_*.md`, §7) явно перечисляет:
- **проверенные примеры** (`status: ok`),
- **контрпримеры** (`violation`, `ambiguous`),
- **неизвестные участки** (`incomplete`, `unknown_frame`),
- **область применимости**.