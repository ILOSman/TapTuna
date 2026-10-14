# Troubleshooting

## Нативный модуль

### `HAS_NATIVE: False`

```bash
python -c "from taptuna.native import native_status; print(native_status())"
```

Возможные причины:

- **Rust не установлен.** Установите через `rustup`.
- **`_native.so` не собран.** `cd taptuna_core && maturin develop --release`.
- **Пакет установлен из wheel без .so.** Проверьте `python -c "import taptuna._native as n; print(n.__file__)"`.

Принудительный fallback: `TAPTUNA_NATIVE=0 python ...`.

### `ModuleNotFoundError: No module named 'taptuna._native'`

Проверьте путь импорта:

```bash
python -c "import taptuna; print(taptuna.__file__)"
```

Если путь указывает в `site-packages`, а не в `taptuna_core/python/taptuna/` —
вы в venv с wheel-установкой, а не в editable. Переключитесь:

```bash
deactivate
cd /path/to/Taptuna_my
source .venv/bin/activate
pip install -e taptuna_core
```

## tshark

### `TSHARK_NOT_FOUND`

```bash
which tshark || export TAPTUNA_TSHARK=/usr/bin/tshark
tshark -v
```

### `tshark exited with code 1: Some fields aren't valid`

Проверьте версию tshark. Поле `tcp.flags.reset` (не `tcp.flags.rst`).

## Ingest

### `The file "test.pcap" doesn't exist`

Путь относительный — от текущего каталога. Используйте абсолютный или
запускайте из корня проекта.

### `UNIQUE constraint failed: sessions.capture_id, sessions.stream_index`

Повторный импорт того же sha256. Актуальные версии перезаписывают сессии
автоматически. Если ошибка осталась — обновите код.

### `TSHARK_OUTPUT_TOO_LARGE`

Вывод tshark превысил `max_output_bytes`. Увеличьте в `manifest.json`
поле `policies.max_output_bytes`.

## Sandbox

### `worker exited cleanly without results`

Гонка `multiprocessing.Queue`: результат положен, но процесс завершился
раньше, чем feeder-поток сбросил данные в pipe. Актуальные версии содержат
`_flush_queue()` в конце worker'а. Обновите код.

### `killed externally (SIGKILL) — likely OOM or timeout`

Проверьте `RLIMIT_AS` (по умолчанию 512 MiB). Скрипт превысил лимит.

### `timeout (wall clock)`

Wall-clock timeout на сообщение (по умолчанию 5 с). Уменьшите сложность
скрипта или увеличьте `timeout_per_message` в конструкторе.

### `cpu limit exceeded (SIGXCPU)`

`RLIMIT_CPU` (по умолчанию 10 с). Бесконечный цикл в скрипте.

## Windows

### `OSError: [WinError 193] %1 is not a valid Win32 application`

Попытка запустить `.sh` на Windows. Обновите тесты: актуальные версии
используют `.bat` для `os.name == "nt"`.

### `RLIMIT_CPU not supported`

`resource` — POSIX-only. На Windows sandbox работает через wall-clock
timeout. Тесты учитывают это (`sys.platform == "win32"`).

## Тесты

### `pytest` использует системный Python, не venv

```bash
which pytest     # /usr/bin/pytest — плохо
python -m pytest # OK
```

Или установите pytest в venv: `python -m pip install pytest`.

### `ModuleNotFoundError: No module named 'taptuna'`

Запуск pytest вне venv или вне корня проекта. Проверьте:

```bash
echo $VIRTUAL_ENV
pwd   # должен быть /path/to/Taptuna_my
python -c "import taptuna; print(taptuna.__file__)"
```

## Проект

### `Project already exists`

`taptuna init` на существующем проекте. Используйте `taptuna serve --project <dir>`,
не пересоздавайте.

### `Manifest not found`

Проект не инициализирован. `taptuna init --project <dir>`.

### `Database not found`

То же. Проверьте `ls <project>/manifest.json <project>/project.sqlite`.

## Долгие операции

### SSE не показывает прогресс

Проверьте DevTools → Network → запрос `/api/jobs/<id>/events`.
Должен быть `200`, тип `text/event-stream`. Если соединение сбрасывается —
проверьте прокси или firewall.

### Job висит в `running`

Job'ы не переживают перезапуск процесса. Если процесс упал — job потерян.
Перезапустите сервер.

## Отчёты

### HTML без стилей

Установите `markdown`: `pip install markdown`. Без него отчёт
рендерится как `<pre>`.

### `No filter named 'fromjson'`

Старый Jinja2. Обновите шаблон `verification.html` — используйте
предвычисленный `verdict` из `ui.py`.

## Оптимизация

### Reassembly медленный

Проверьте, что используете нативный модуль:

```bash
python -c "from taptuna.native import HAS_NATIVE; print(HAS_NATIVE)"
```

Fallback медленнее в 10–20 раз. `maturin develop --release` пересоберёт.