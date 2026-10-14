# Примеры

## Готовый демонстрационный проект

```bash
python examples/generate_demo.py --force
taptuna serve --project examples/demo_project
```

Открыть `http://127.0.0.1:5000/`.

**Что внутри:**

| Компонент | Что показывает |
|---|---|
| `captures/<sha>.pcap` | TCP-сессия: SYN, SYN-ACK, 13 байт данных, FIN |
| `project.sqlite` | 1 capture, 1 session, 2 directions, 4 packets |
| Интерпретация `demo_fixed13@v1` | Fixed-size framing 13 байт |
| Корпус `demo_corpus` | Сессии на порту 8080 |
| Журнал `demo_actions` | 3 действия, согласованных по времени |
| Прогон verify #1 | verdict=ok, 1 сообщение |
| Отчёты | `reports/report_run1_*.{md,html,machine_model.json}` |

**Что делать:**

1. **Сессии** — обзор, клик по #1.
2. **Исследование** — framing-tool: попробуйте `fixed size=13`,
   `delimiter delim=2c20`, `length_prefix`.
3. **Интерпретации** — `demo_fixed13@v1` уже добавлена.
4. **Проверка** — run #1 завершён, verdict=ok.
5. **Журнал** — `demo_actions`, кнопка «Записи».
6. **Отчёт** — сгенерирован. Откройте HTML.
7. **Проект** — сводка по 14 таблицам.

## Эталонный PCAP для тестов

```bash
python -m taptuna.examples.generate
```

Создаёт `input/test.pcap` и `expected/test.json`. Используется в
`make test-examples`.

## Что можно расширить

- **Свой PCAP.** `taptuna ingest --project <dir> --input your.pcap`.
- **Свой журнал.** `taptuna action-add --project <dir> --file actions.csv`.
- **Своя интерпретация.** `taptuna interp-add --project <dir> --file spec.yaml`.

Форматы описаны в `docs/ARCHITECTURE.md` §6 и `docs/METHODOLOGY.md` §5.