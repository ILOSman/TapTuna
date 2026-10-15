# Установка TapTuna

## Способ 1: готовый AppImage (рекомендуется)

### Требования

- Linux x86-64 (Ubuntu 22.04+, Fedora 38+, Arch, openSUSE)
- `tshark` — Wireshark CLI, для импорта PCAP

### Шаги

#### 1. Установить tshark

```bash
# Ubuntu / Debian / Mint
sudo apt update && sudo apt install -y tshark

# Fedora / RHEL / CentOS
sudo dnf install -y wireshark-cli

# Arch / Manjaro
sudo pacman -S wireshark-cli

# openSUSE
sudo zypper install wireshark
```

При установке Ubuntu спросит: «Should non-superusers be able to capture
packets?» — можно ответить **No**, для анализа сохранённых PCAP это
не требуется.

Проверка:

```bash
tshark -v | head -1
# TShark (Wireshark) 4.x.x
```

#### 2. Скачать AppImage

```bash
cd ~/Downloads
wget https://github.com/ILOSman/taptuna/releases/download/v0.1.0/TapTuna-0.1.0-x86_64.AppImage
chmod +x TapTuna-0.1.0-x86_64.AppImage
```

#### 3. Запустить

```bash
./TapTuna-0.1.0-x86_64.AppImage
```

Откроется окно приложения со списком проектов.

#### 4. (Опционально) ярлык в меню приложений

```bash
mkdir -p ~/.local/bin ~/.local/share/applications

mv ~/Downloads/TapTuna-0.1.0-x86_64.AppImage ~/.local/bin/taptuna
chmod +x ~/.local/bin/taptuna

cat > ~/.local/share/applications/taptuna.desktop <<EOF
[Desktop Entry]
Type=Application
Name=TapTuna
Comment=Protocol Laboratory
Exec=$HOME/.local/bin/taptuna
Terminal=false
Categories=Development;Network;
EOF

update-desktop-database ~/.local/share/applications 2>/dev/null || true
```

Теперь `TapTuna` появится в меню приложений.

### Где хранятся данные

| Что | Путь |
|---|---|
| Проекты | `~/TapTuna/projects/` |
| Реестр проектов | `~/TapTuna/projects.json` |
| Логи сервера | `~/TapTuna/logs/server.log` |

**Удаление приложения:** удалить AppImage и `rm -rf ~/TapTuna`.

## Способ 2: из исходников

### Требования

- Python 3.11 или новее
- Rust 1.75+ (`rustup` рекомендуется)
- Node.js 18+ (только для Electron-приложения)
- `tshark`

### Шаги

```bash
# Клонировать
git clone https://github.com/ILOSman/taptuna.git
cd taptuna

# Python-окружение
python3 -m venv .venv
source .venv/bin/activate

# Установить maturin и собрать Rust-ядро
pip install maturin
cd taptuna_core
maturin develop --release
cd ..

# Python-зависимости
pip install flask jinja2 pyyaml markdown

# Проверка
python -m taptuna.cli init --project /tmp/test
python -m taptuna.cli serve --project /tmp/test --port 5001
# открыть http://127.0.0.1:5001
```

### Сборка Electron-приложения

```bash
# 1. Собрать PyInstaller-бинарь сервера
cd taptuna_core
pyinstaller --clean server.spec
cp dist/taptuna-server ../electron/bin/
chmod +x ../electron/bin/taptuna-server

# 2. Собрать AppImage
cd ../electron
npm install
npm run build:appimage

# 3. Готовый файл
ls -la dist/*.AppImage
```

## Решение проблем

### Окно пустое / белый экран

Смотрите лог Electron:

```bash
tail -50 ~/TapTuna/logs/electron-server.log
tail -50 ~/TapTuna/logs/server.log
```

### «tshark не найден»

Приложение покажет экран `/setup-tshark` с командой установки.
После установки нажмите **«Проверить снова»**.

Проверить, что tshark виден системе:

```bash
which tshark
tshark -v | head -1
```

Если установлен, но не виден — перезапустите сессию терминала
(или перелогиньтесь), чтобы обновился `$PATH`.

### Импорт PCAP: 0 сессий

PCAP не содержит TCP/IPv4. TapTuna работает **только с TCP через
Ethernet**. Wi-Fi (802.11), UDP-only, ARP, ICMP, IPv6 — не подходят.

Проверить формат:

```bash
tshark -r your.pcap -c 5 -T fields -e frame.protocols
# Должно быть: eth:ethertype:ip:tcp
# НЕ подходит: wlan, eth:ethertype:ip:udp, eth:ethertype:ipv6
```

Если видите `wlan` — это Wi-Fi дамп, снятый не на проводном
интерфейсе. Нужен PCAP с Ethernet.

### FUSE error при запуске AppImage

Ubuntu 24.04+ не имеет `libfuse2` по умолчанию:

```bash
sudo apt install libfuse2t64
```

Или запустить без FUSE:

```bash
./TapTuna-0.1.0-x86_64.AppImage --appimage-extract-and-run
```

### Большие PCAP: превышение лимита

По умолчанию `max_output_bytes = 2 ГиБ` — лимит вывода tshark.
Для очень больших PCAP (> 1 ГиБ) может понадобиться увеличить
в `~/TapTuna/projects/<имя>/manifest.json`:

```json
"policies": {
  "max_output_bytes": 4294967296
}
```

Затем повторить ingest.

## Что дальше

- [README](../README.md) — обзор возможностей
- [DEMO.md](DEMO.md) — сценарий демонстрации
- [ARCHITECTURE.md](ARCHITECTURE.md) — техническое описание