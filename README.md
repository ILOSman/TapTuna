# TapTuna — Protocol Laboratory

Инструмент для исследования недокументированного бинарного обмена
поверх TCP/IPv4. Восстанавливает поток из PCAP, помогает сформулировать
интерпретацию протокола, проверить её на корпусе и передать результаты
другому инженеру.

## Возможности

- **Импорт PCAP/PCAPNG** через `tshark` — один проход на файл.
- **Восстановление TCP-потока** по RFC 9293 (Rust + PyO3): порядок,
  повторные передачи, перекрытия, gaps с явной диагностикой.
- **Возврат к источнику**: любой байт потока ссылается на конкретный
  кадр в PCAP.
- **Декларативные интерпретации**: framing (4 стратегии) + 20 типов
  полей + constraints + semantics.
- **Верификация корпуса**: 5 статусов (`ok` / `violation` / `ambiguous`
  / `incomplete` / `not_applicable`), контрпримеры, `run_hash` для
  воспроизводимости.
- **Гипотезы как выражения**: `magic == 0x48`, `-20 <= temp <= 20`,
  автопроверка на всех сообщениях, контрпримеры со ссылкой на байты.
- **Отчёты**: Markdown + HTML + `machine_model.json` (самодостаточная
  интерпретация для повторного применения).
- **Экспорт/импорт проектов** одним `.taptuna.zip`.
- **Настольное приложение**: один файл `.AppImage`, запуск двойным кликом.

## Установка

Требования: **Linux x86-64**, `tshark` (Wireshark CLI).

### Готовый AppImage

```bash
# 1. Установить tshark
sudo apt install tshark            # Ubuntu / Debian
sudo dnf install wireshark-cli     # Fedora
sudo pacman -S wireshark-cli       # Arch

# 2. Скачать и запустить
wget https://github.com/ILOSman/taptuna/releases/download/v0.1.1/TapTuna-0.1.0-x86_64.AppImage
chmod +x TapTuna-0.1.0-x86_64.AppImage
./TapTuna-0.1.0-x86_64.AppImage
```

Подробнее — см. [`docs/INSTALL.md`](docs/INSTALL.md).

### Из исходников

```bash
# Требования: Python 3.11+, Rust 1.75+, Node.js 18+
git clone https://github.com/ILOSman/taptuna.git
cd taptuna

# Python-окружение
python3 -m venv .venv
source .venv/bin/activate
pip install maturin

# Сборка Rust-ядра
maturin develop --release -m taptuna_core/Cargo.toml

# Python-зависимости
pip install flask jinja2 pyyaml markdown

# Проверка
python -m taptuna.cli init --project /tmp/test
python -m taptuna.cli serve --project /tmp/test

# Electron-приложение (опционально)
cd electron
npm install
npm run build:appimage
```

## Быстрый старт

Через GUI:

1. Запустить приложение.
2. `/welcome` → создать проект (или перетащить `.pcap` в окно).
3. Импортировать PCAP.
4. Исследовать сессии, создать интерпретацию, запустить verify.
5. Сгенерировать отчёт.

Через CLI:

```bash
taptuna init --project ./myproj
taptuna ingest --project ./myproj --input capture.pcap
taptuna interp-add --project ./myproj --file interp.yaml
taptuna corpus-add --project ./myproj --name c1 --file corpus.yaml
taptuna verify --project ./myproj --corpus c1 --interpretation my_interp
taptuna report --project ./myproj --format md,html,json
taptuna serve --project ./myproj
```

## Документация

| Документ | Что внутри |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Подход, слои, форматы, зависимости |
| [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) | Методология исследования протокола |
| [`docs/INSTALL.md`](docs/INSTALL.md) | Подробная установка и решение проблем |
| [`docs/REUSE.md`](docs/REUSE.md) | Повторное применение интерпретации |
| [`docs/DEMO.md`](docs/DEMO.md) | Сценарий демонстрации (15–20 минут) |
| [`docs/DoD.md`](docs/DoD.md) | Проверка требований, измерения |
| [`examples/interpretations/`](examples/interpretations/) | Примеры интерпретаций |

## Структура проекта

```
taptuna_core/          Rust-ядро (PyO3): wire, seq, reassembly,
                       framing, extract, safe_eval
  python/taptuna/      Python-пакет
    app.py             Flask application factory
    routes.py          REST API + SSE
    ui.py              HTML-страницы
    projects.py        Реестр проектов
    ingest.py          Импорт PCAP через tshark
    verification.py    Корпус → интерпретация → статусы
    hypotheses.py      Гипотезы как safe-eval выражения
    reports.py         Отчёты MD/HTML + machine_model.json
    interpreters/      Декларативные и script-интерпретации
    native/            Python-fallback reassembly
    templates/         Jinja2-шаблоны
    static/            CSS, JS
electron/              Настольное приложение (main.js, preload.js)
examples/              Демонстрационный проект и примеры
docs/                  Документация
tests/                 Python-тесты
```

## Ограничения

- Только **TCP/IPv4 поверх Ethernet**. Wi-Fi (802.11), IPv6,
  IP-фрагментация, UDP-only, ARP, ICMP — диагностируются, но не
  анализируются.
- **Одна точка захвата**, один интерфейс.
- Checksum-поля IP/TCP могут быть некорректны в локальных захватах
  (checksum offloading). Политика анализа задаётся явно.
- Не покрыто: TLS-расшифровка, разбор сжатых данных, восстановление
  полного автомата состояний.

## Лицензия

[MIT](LICENSE)