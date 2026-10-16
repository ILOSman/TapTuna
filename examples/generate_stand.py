"""Генерирует 4 PCAP-файла, по одному под каждую интерпретацию
из examples/interpretations/. Каждый PCAP — отдельный протокол,
чтобы интерпретации демонстрировались изолированно.

Запуск:
    python examples/generate_stand.py --out /tmp/taptuna_stand
"""
from __future__ import annotations
import argparse
import json
import struct
import time
from pathlib import Path


def _eth_ip_tcp(payload: bytes, sport: int, dport: int,
                src: str = "10.0.0.1", dst: str = "10.0.0.2",
                seq: int = 1000) -> bytes:
    """Собирает Ethernet + IPv4 + TCP + payload вручную."""
    # Ethernet
    eth = (b"\x00\x11\x22\x33\x44\x55"   # dst mac
           b"\x66\x77\x88\x99\xaa\xbb"   # src mac
           b"\x08\x00")                   # IPv4

    # TCP
    tcp = struct.pack(">HHIIHHHH",
                      sport, dport, seq, 0,
                      (5 << 12) | 0x18,     # data offset 5 + PSH+ACK
                      65535, 0, 0)
    tcp += payload

    # IPv4
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s",
                     0x45, 0, total, 0x1234, 0x4000, 64, 6, 0,
                     bytes(map(int, src.split("."))),
                     bytes(map(int, dst.split("."))))
    return eth + ip + tcp


def _write_pcap(path: Path, frames: list[bytes]) -> None:
    """Пишет минимальный PCAP (без синхронизации по времени)."""
    with path.open("wb") as f:
        # PCAP global header
        f.write(struct.pack("<IHHiIII",
                            0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            ts = time.time() + i * 0.001
            f.write(struct.pack("<IIII",
                                int(ts), int((ts % 1) * 1e6),
                                len(frame), len(frame)))
            f.write(frame)


# ---------------------------------------------------------------------------

def make_fixed(out: Path) -> None:
    """5 сообщений по 13 байт. Порт 8080."""
    payload = b"Hello, World!" * 5    # 65 байт = 5 × 13
    frame = _eth_ip_tcp(payload, 12345, 8080)
    _write_pcap(out / "01_fixed.pcap", [frame])


def make_length_prefix(out: Path) -> None:
    """3 сообщения: 2 байта длины BE + payload."""
    msgs = [b"first", b"second-longer", b"third"]
    payload = b""
    for m in msgs:
        payload += struct.pack(">H", len(m)) + m
    frame = _eth_ip_tcp(payload, 12345, 8080)
    _write_pcap(out / "02_length_prefix.pcap", [frame])


def make_delimiter(out: Path) -> None:
    """4 строки, разделитель CRLF."""
    payload = b"GET / HTTP/1.1\r\nHost: test\r\n\r\nBODY"
    frame = _eth_ip_tcp(payload, 12345, 8080)
    _write_pcap(out / "03_delimiter.pcap", [frame])


def make_expression(out: Path) -> None:
    """5 сообщений по 6 байт: temp_raw(u16be), humidity_raw(u16be), magic(u16be).

    Значения подобраны для чистой демонстрации:
    - temp_raw кратен 10 → нет потери при floordiv
    - 4 сообщения в диапазоне [-40, 85] → constraint проходит (ok)
    - 1 сообщение = 100 °C → violation в verify
    - 4 сообщения с magic = 0x48 → гипотеза magic == 0x48 даст supported
    - 1 сообщение с magic = 0x49 → та же гипотеза даст refuted
    """
    msgs = []
    # (temp_c, humidity_pct, magic)
    data = [
        (21.0, 55.0, 0x0048),
        (22.0, 56.0, 0x0048),
        (5.0,  40.0, 0x0048),    # было -5.0 → стало +5.0 (u16be без знака)
        (30.0, 70.0, 0x0048),
        (100.0, 50.0, 0x0049),   # выходит за верхнюю границу, magic другой
    ]
    for temp_c, hum_pct, magic in data:
        temp_raw = int(temp_c * 10)
        hum_raw = int(hum_pct * 10)
        # u16be: unsigned big-endian → ">H"
        msgs.append(struct.pack(">HHH", temp_raw, hum_raw, magic))
    payload = b"".join(msgs)
    frame = _eth_ip_tcp(payload, 12345, 8080)
    _write_pcap(out / "04_expression.pcap", [frame])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path,
                    default=Path("/tmp/taptuna_stand"))
    args = ap.parse_args()

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    make_fixed(out)
    make_length_prefix(out)
    make_delimiter(out)
    make_expression(out)

    print(f"Сгенерировано в {out}:")
    for p in sorted(out.glob("*.pcap")):
        size = p.stat().st_size
        print(f"  {p.name:30s}  {size} байт")

    print()
    print("Интерпретации (examples/interpretations/):")
    print("  01_fixed_magic.yaml       → 01_fixed.pcap")
    print("  02_length_prefix.yaml     → 02_length_prefix.pcap")
    print("  03_delimiter.yaml         → 03_delimiter.pcap")
    print("  04_expression.yaml        → 04_expression.pcap")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())