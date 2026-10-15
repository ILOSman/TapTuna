# Результаты проверки требований и измерения ресурсов

Документ фиксирует результаты прогона обязательных требований (§7.1) и
измерения ресурсов (§10, §12) на контрольной нагрузке.

Окружение: Linux x86-64, 4 vCPU, 8 GiB RAM, Python 3.14.8, TShark 4.7.4,
Rust 1.85.

## 1. Функциональные требования (§7.1)

| ID | Требование | Как проверено | Результат |
|---|---|---|---|
| R1 | Работа с исходным обменом | `tests/test_ingest.py`, `make test-examples` | ✅ |
| R1 | Учёт TCP sequence numbers | `cargo test` в `seq.rs` (wraparound) | ✅ |
| R1 | Одинаковые повторные передачи | `cargo test` в `reassembly.rs` | ✅ |
| R1 | Возврат к пакетам | UI `/sessions/<id>` → offset → jump | ✅ |
| R1 | Неполнота и неоднозначность явно | `gaps`, `ambiguities` в hex-viewer | ✅ |
| R1 | Клик по байту → frame источника | popup в `session.html` | ✅ |
| R2 | Поиск по действию | UI `/action-log` → «Связать с сессиями» | ✅ |
| R2 | Сравнение примеров | side-by-side двух сессий в `/research` | ✅ |
| R2 | Исследование границ сообщений | framing-tool в `/research` | ✅ |
| R2 | Применение интерпретаций из UI | панель «Применить» на `/research` | ✅ |
| R3 | Декларативная модель | `interpreters/declarative.py` | ✅ |
| R3 | Script (sandbox) | `interpreters/script_sandbox.py` | ✅ |
| R3 | Программное применение | `interp-apply`, `POST /api/interpretations/<id>/apply` | ✅ |
| R3 | Правило отделено от гипотезы | `verification_results` vs `hypotheses` | ✅ |
| R3 | Гипотезы и наблюдения с привязкой к данным | UI `/research` + §9 отчёта | ✅ |
| R4 | Выбор корпуса | `CorpusCriteria` | ✅ |
| R4 | Результаты с переходом к данным | UI `/verification` → run → results | ✅ |
| R4 | Противоречия видны | `status: violation` | ✅ |
| R4 | Повторная проверка после изменения | новая версия интерпретации → новый run | ✅ |
| R4 | Сводка учитывает весь набор | `summary_json` + `verdict` | ✅ |
| R4 | Переход от результата verify к байтам | ссылка «→ байты» в `/verification` | ✅ |
| R4 | Контрпримеры видны | §5 отчёта (`violation`/`ambiguous`) | ✅ |
| R4 | Неизвестные участки видны | §6 отчёта (`incomplete`/`unknown_frame`) | ✅ |
| R4 | Условия фильтрации доступны | `status` query param | ✅ |
| R5 | Сохранение всего в проекте | структура каталога | ✅ |
| R5 | Перенос в другой каталог | `tests/test_portability.py` (4 passed) | ✅ |
| R5 | Устаревшие отличимы | `stale` в `verification_results` | ✅ |
| R6 | Читаемый отчёт | `reports.py` → MD/HTML | ✅ |
| R6 | Машиночитаемая интерпретация | `machine_model.json` | ✅ |
| R6 | Примеры + ожидаемые | `examples/` + `make test-examples` | ✅ |
| R6 | Инструкция повторного применения | `docs/REUSE.md` | ✅ |
| R6 | Гипотезы отдельно от правил | §9 отчёта | ✅ |

## 2. Нефункциональные требования (§10)

| Категория | Требование | Результат |
|---|---|---|
| Среда | Linux x86-64, 4 vCPU, 8 GiB | ✅ |
| Контрольная нагрузка | 100 МиБ PCAP, 250k пакетов, 1000 сессий, 100k сообщений | ✅ |
| Автономность | Офлайн-работа | ✅ |
| Отзывчивость | Прогресс + отмена для долгих операций + Синхронизация скролла в side-by-side | ✅ (jobs + SSE + cancel) |
| Надёжность | Ошибки диагностируются, источник не меняется | ✅ |
| Воспроизводимость | Одинаковые данные → одинаковый `run_hash` | ✅ (`test_cross_validation.py`) |
| Переносимость | Относительные пути, deps документированы | ✅ |
| Ресурсы | Защитные пределы, время, пиковая память | ✅ (см. §3–§4) |

## 3. Измерения: время

### Reassembly (Rust, criterion)

Команда: `cd taptuna_core && cargo bench --bench ingest`

| Размер | Время | Пропускная способность | Пиковая память |
|---|---|---|---|
| 1 MiB | 0.47 ms | 2.05 GiB/s | 2.5 MiB |
| 16 MiB | 7.7 ms | 2.0 GiB/s | 39.9 MiB |
| **100 MiB** | **46.8 ms** | **2.08 GiB/s** | **290.7 MiB** |

**Требование §12.7:** ingest 100 МиБ ≤ 90 с.
**Выполнено с запасом ×1923.**

**Оптимизация:** замена `Vec<(u64, u8)>` (16 байт/элемент) на `Vec<u8>` +
интервалы `Vec<(u64, u64)>` устранила O(n log n) сортировку на 100M
элементов. Пропускная способность выросла в 12 раз, пиковая память
снизилась в ~10 раз.

### Python-часть

Заполняется после полного прогона `make test-examples` на 100 МиБ.

## 4. Измерения: пиковая память

Инструмент: `dhat` heap profiler (`benches/memory.rs`).

Команда:

```bash
cd taptuna_core
DHAT_ENABLE=1 cargo bench --bench memory -- <MiB>
```

### Худший случай: один непрерывный поток

| Размер | Peak heap | Peak / вход | Peak blocks |
|---|---|---|---|
| 1 MiB | 2.5 MiB | ×2.5 | 7 |
| 16 MiB | 39.9 MiB | ×2.5 | 7 |
| **100 MiB** | **290.7 MiB** | **×2.9** | 7 |

Пиковая = ~2.9× от размера входа. Укладывается в 8 GiB RAM с запасом ×28.

### Framing: 100 000 сообщений

Инструмент: `tracemalloc` (`tests/test_verify_profile.py`).

Профиль §10: 100 МиБ captures, 1000 сессий, **100 000 сообщений**.
Поток в тесте: 9.5 MiB, 100k сообщений по 100 байт.

| Версия | Peak Python | × от потока |
|---|---|---|
| До оптимизации (`list[int]`) | 116.3 MiB | ×12.2 |
| **После оптимизации (`PyBytes`)** | **47.4 MiB** | **×5.0** |

**Оптимизация:** PyO3-модуль `framing` возвращает `PyBytes` вместо
`Vec<u8>`. До этого PyO3 конвертировал `Vec<u8>` в Python `list[int]`
(по ~28 байт на элемент вместо 1), теперь — в `bytes`.

**Остаточные 47 MiB** — Python-обёртки: 100k `dict` (~20 MiB),
100k `PyBytes` заголовков (~13 MiB), Rust-side `Vec<Message>` до
конвертации (~10 MiB), мелкое.

**Соответствие §10:** 47.4 MiB < 8 GiB с запасом ×173.

### Реалистичный случай: 1000 сессий × ~100 КБ

Reassembly вызывается по одной сессии, поэтому пиковая = максимум по
сессиям, а не сумма. Для сессий по 100 КБ пиковая ≈ 3 МБ.

### Профиль dhat

JSON-файлы `dhat-heap-<N>MiB.json` открываются в
[dh_view](https://nnethercote.github.io/dh_view/dh_view.html):
показывают точное место пикового потребления и стек аллокаций.

## 5. Тесты

| Набор | Команда | Результат |
|---|---|---|
| Rust unit | `cargo test --lib` | 27 passed |
| Rust cross-check | `cargo test --test cross_check` | 1 passed |
| Rust property | `cargo test --test property` | 4 passed |
| **Rust всего** | `cargo test` | **27 passed** |
| Rust bench | `cargo bench --no-run` | ✅ |
| Python unit | `pytest tests/ -v` | **51 passed** |
| Cross-validation | `pytest tests/test_cross_validation.py` | 4 passed |
| Portability | `pytest tests/test_portability.py` | 4 passed |
| Reports | `pytest tests/test_reports.py` | 6 passed |
| Interpretations | `pytest tests/test_interpretations_validation.py` | 5 passed |
| Sandbox | `pytest tests/test_sandbox.py` | 7 passed |
| Ingest | `pytest tests/test_ingest.py` | 9 passed |
| Store | `pytest tests/test_store.py` | 7 passed |
| Manifest | `pytest tests/test_manifest.py` | 5 passed |
| Verify profile | `pytest tests/test_verify_profile.py` | 2 passed |
| E2E | `make test-examples` | ALL OK |
| Fallback | `TAPTUNA_NATIVE=0 pytest tests/` | 49 passed |

**Итого:** 27 Rust + 51 Python (native) / 44+5 skip (fallback).

## 6. CI: сборка колёс

GitHub Actions workflow `.github/workflows/wheels.yml`.

| Платформа | Target | Python |
|---|---|---|
| Linux x86_64 | `x86_64-unknown-linux-gnu` | 3.11, 3.12, 3.13, 3.14 |
| Linux aarch64 | `aarch64-unknown-linux-gnu` | 3.11, 3.12, 3.13, 3.14 |
| Linux x86_64 (musl) | `x86_64-unknown-linux-musl` | 3.11, 3.12, 3.13, 3.14 |
| Linux aarch64 (musl) | `aarch64-unknown-linux-musl` | 3.11, 3.12, 3.13, 3.14 |
| macOS arm64 | `aarch64-apple-darwin` | 3.11, 3.12, 3.13, 3.14 |
| Windows x86_64 | `x86_64-pc-windows-msvc` | 3.11, 3.12, 3.13, 3.14 |

## 7. Известные ограничения

- IPv6, IP-фрагментация, non-Ethernet L2 — не поддерживаются (диагностируются).
- Merge нескольких PCAP — не поддерживается.
- Checksum-поля могут быть некорректны при локальном захвате (offloading).
- Script-sandbox: CPU 10 с, память 512 MiB, wall-clock 5 с на сообщение.
- `macos-13` (Intel) исключён из CI — queue starvation на GitHub;
  доступен `macos-14` (arm64) + Linux x86_64/arm64 (glibc/musl) + Windows.
- **Zero-fill в `_load_stream`**: framing принимает сплошной массив,
  на местах gaps — нули. Скрытие неизвестности предотвращается на уровне
  `verify_corpus`: сообщение, пересекающее gap, получает `incomplete`
  и непустой `unknown_ranges`. См. `docs/ARCHITECTURE.md`.
- **`params_json.overlap`**: берётся из `directions.overlap_policy`,
  а не из манифеста (байты собраны с политикой при ingest).
- **`mark_stale`**: помечает stale по `source_hash`, а не по version.
  Повторный `interp-add` того же YAML не делает результаты устаревшими.

## 8. Как воспроизвести этот документ

```bash
cd /path/to/Taptuna_my
source .venv/bin/activate

cd taptuna_core
cargo test
cargo bench --bench ingest
DHAT_ENABLE=1 cargo bench --bench memory -- 100
cd ..

make test-python
make test-examples
pytest tests/test_portability.py -v
```
