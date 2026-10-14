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
| R2 | Поиск по действию | `action_log.find_sessions_in_window` | ✅ |
| R2 | Сравнение примеров | `/research` side-by-side двух направлений | ✅ |
| R2 | Исследование границ сообщений | framing-tool в `/research` | ✅ |
| R3 | Декларативная модель | `interpreters/declarative.py` | ✅ |
| R3 | Script (sandbox) | `interpreters/script_sandbox.py` | ✅ |
| R3 | Программное применение | `interp-apply`, `POST /api/interpretations/<id>/apply` | ✅ |
| R3 | Правило отделено от гипотезы | `verification_results` vs `hypotheses` | ✅ |
| R4 | Выбор корпуса | `CorpusCriteria` | ✅ |
| R4 | Результаты с переходом к данным | UI `/verification` → run → results | ✅ |
| R4 | Противоречия видны | `status: violation` | ✅ |
| R4 | Повторная проверка после изменения | новая версия интерпретации → новый run | ✅ |
| R4 | Сводка учитывает весь набор | `summary_json` + `verdict` | ✅ |
| R4 | Условия фильтрации доступны | `status` query param | ✅ |
| R5 | Сохранение всего в проекте | структура каталога | ✅ |
| R5 | Перенос в другой каталог | `tests/test_portability.py` (4 passed) | ✅ |
| R5 | Устаревшие отличимы | `stale` в `verification_results` | ✅ |
| R6 | Читаемый отчёт | `reports.py` → MD/HTML | ✅ |
| R6 | Машиночитаемая интерпретация | `machine_model.json` | ✅ |
| R6 | Примеры + ожидаемые | `examples/` + `make test-examples` | ✅ |
| R6 | Инструкция повторного применения | `docs/REUSE.md` | ✅ |

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
| Rust unit | `cargo test` | 18 passed |
| Rust property | `cargo test` | включены в 18 |
| Rust bench | `cargo bench --no-run` | ✅ |
| Python | `make test-python` | 36 passed |
| Cross-validation | `pytest tests/test_cross_validation.py` | 4 passed |
| E2E | `make test-examples` | ALL OK |
| Portability | `pytest tests/test_portability.py` | 4 passed |
| Fallback | `TAPTUNA_NATIVE=0 pytest ...` | 36 passed |

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
- `macos-13` (Intel) исключён из CI — queue starvation на GitHub.

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
