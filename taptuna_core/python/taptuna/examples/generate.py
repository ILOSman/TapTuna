"""Генерирует тестовые PCAP-файлы для E2E-тестов (ТЗ §20.4).

Создаёт:
- input/test.pcap — TCP-сессия с 4 пакетами и payload'ом "Hello, World!"
- expected/test.json — эталонная сводка

Запуск:
    python -m taptuna.examples.generate
    python -m taptuna.examples.generate --out /custom/path
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap


def build_session() -> list:
    """TCP-сессия: SYN, SYN-ACK, ACK+payload, FIN."""
    mac_a = "02:00:00:00:00:01"
    mac_b = "02:00:00:00:00:02"
    return [
        Ether(src=mac_a, dst=mac_b) /
        IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=12345, dport=8080, seq=1000, flags="S"),

        Ether(src=mac_b, dst=mac_a) /
        IP(src="10.0.0.2", dst="10.0.0.1") /
        TCP(sport=8080, dport=12345, seq=5000, ack=1001, flags="SA"),

        Ether(src=mac_a, dst=mac_b) /
        IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=12345, dport=8080, seq=1001, ack=5001, flags="PA") /
        Raw(b"Hello, World!"),

        Ether(src=mac_a, dst=mac_b) /
        IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=12345, dport=8080, seq=1014, ack=5001, flags="FA"),
    ]


def build_interp_yaml() -> str:
    """Минимальная декларативная интерпретация: fixed size 13, одно поле."""
    return """\
name: test_fixed
kind: declarative
framing:
  kind: fixed
  size: 13
  max_message: 1024
fields:
  name: message
  fields:
    - name: raw
      type: bytes
      offset: 0
      size: 13
constraints: []
semantics: {}
"""


def build_corpus_yaml() -> str:
    """Корпус: сессии с портом 8080 и хотя бы одним пакетом."""
    return """\
any_ports: [8080]
min_packets: 1
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path(__file__).parent)
    args = ap.parse_args()

    input_dir = args.out / "input"
    expected_dir = args.out / "expected"
    input_dir.mkdir(parents=True, exist_ok=True)
    expected_dir.mkdir(parents=True, exist_ok=True)

    pcap_path = input_dir / "test.pcap"
    pkts = build_session()
    wrpcap(str(pcap_path), pkts)

    expected = {
        "description": "TCP session: SYN, SYN-ACK, data, FIN",
        "pcap": "input/test.pcap",
        "packets": len(pkts),
        "sessions": 1,
        "expected_streams": {
            "a_to_b": {
                "reassembled_bytes": 13,
                "data": "Hello, World!",
                "gaps": 0,
                "ambiguities": 0,
            },
            "b_to_a": {
                "reassembled_bytes": 0,
                "data": "",
                "gaps": 0,
                "ambiguities": 0,
            },
        },
        "roles_established": True,
        "verification": {
            "verdict": "ok",
            "messages": 1,
        },
    }
    (expected_dir / "test.json").write_text(
        json.dumps(expected, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Specs — чтобы run.sh не писал их heredoc'ами
    (args.out / "interp.yaml").write_text(build_interp_yaml(), encoding="utf-8")
    (args.out / "corpus.yaml").write_text(build_corpus_yaml(), encoding="utf-8")

    print(f"generated: {pcap_path}")
    print(f"generated: {expected_dir / 'test.json'}")
    print(f"generated: {args.out / 'interp.yaml'}")
    print(f"generated: {args.out / 'corpus.yaml'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())