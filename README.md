
# TapTuna — Protocol Laboratory

Инструмент для исследования недокументированного бинарного обмена поверх
TCP/IPv4. Восстанавливает поток из PCAP, помогает сформулировать
интерпретацию протокола, проверить её на корпусе и передать результаты
другому инженеру.

## Что умеет

- **Импорт PCAP/PCAPNG** через `tshark` — один проход на файл.
- **Восстановление TCP-потока** по RFC 9293 (Rust + PyO3): порядок, повторные
  передачи, перекрытия, gaps с явной диагностикой.
- **Возврат к источнику**: любой байт потока ссылается на конкретный кадр
  в PCAP.
- **Декларативные интерпретации**: framing (4 стратегии) + поля (20 типов) +
  constraints + semantics.
- **Верификация корпуса**: 5 статусов (`ok` / `violation` / `ambiguous` /
  `incomplete` / `not_applicable`), контрпримеры, `run_hash` для
  воспроизводимости.
- **Гипотезы как выражения**: `magic == 0x48`, `-20 <= temp <= 20`,
  автопроверка на всех сообщениях, контрпримеры со ссылкой на байты.
- **Отчёты**: Markdown + HTML + `machine_model.json` (самодостаточная
  интерпретация для повторного применения).
- **Экспорт/импорт проектов** одним `.taptuna.zip`.
- **Electron-приложение**: один файл `.AppImage`, запуск двойным кликом.

## Установка

Требования: **Linux x86-64**, `tshark` (Wireshark CLI).

```bash
# 1. Установить tshark
sudo apt install tshark       # Ubuntu / Debian
sudo dnf install wireshark-cli # Fedora

# 2. Запустить TapTuna
chmod +x TapTuna-0.1.0.AppImage
./TapTuna-0.1.0.AppImage
```

Открывается окно приложения. Проекты хранятся в `~/TapTuna/projects/`.

### Сборка из исходников

```bash
# 1. Python 3.11+ и Rust 1.75+
sudo apt install python3-venv rustc cargo

# 2. Клонировать и установить
git clone https://github.com/ILOSman/taptuna.git
cd taptuna
python3 -m venv .venv
source .venv/bin/activate
pip install maturin
maturin develop --release -m taptuna_core/Cargo.toml
pip install flask jinja2 pyyaml markdown

# 3. Проверить
python -m taptuna.cli init --project /tmp/test
python -m taptuna.cli serve --project /tmp/test

# 4. Сборка AppImage
cd electron
npm install
npm run build:appimage
```

## Быстрый старт

```bash
# Импорт PCAP
# В GUI: /welcome → создать проект → загрузить .pcap

# Или через CLI:
taptuna init --project ./myproj
taptuna ingest --project ./myproj --input capture.pcap
taptuna serve --project ./myproj
```

## Документация

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — подход, слои, форматы.
- [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) — методология исследования.
- [`docs/REUSE.md`](docs/REUSE.md) — как применять интерпретацию повторно.
- [`docs/DEMO.md`](docs/DEMO.md) — сценарий демонстрации (15–20 минут).
- [`docs/DoD.md`](docs/DoD.md) — результаты проверки требований, измерения.

## Лицензия

MIT