.PHONY: help install test test-rust test-python test-examples bench demo clean

help:
	@echo "make targets:"
	@echo "  install       — editable install taptuna-core + зависимости"
	@echo "  test          — все тесты (rust + python)"
	@echo "  test-rust     — cargo test в taptuna_core"
	@echo "  test-python   — pytest в tests/"
	@echo "  test-examples — E2E на эталонном PCAP"
	@echo "  bench         — cargo bench --no-run"
	@echo "  clean         — удалить артефакты"

install:
	pip install -e taptuna_core
	pip install pytest markdown jinja2 pyyaml flask scapy

test: test-rust test-python

test-rust:
	cd taptuna_core && cargo test

test-python:
	pytest tests/ -v

test-examples:
	bash taptuna_core/python/taptuna/examples/run.sh

bench:
	cd taptuna_core && cargo bench --no-run
	@echo "run 'cd taptuna_core && cargo bench' for full benchmarks"

demo:
	python examples/generate_demo.py --force
	@echo ""
	@echo "Готово. Открыть проект:"
	@echo "  taptuna serve --project examples/demo_project"
	@echo "  http://127.0.0.1:5000"

clean:
	rm -rf /tmp/taptuna_example /tmp/taptuna_api_test /tmp/taptuna_cli_test
	rm -rf examples/demo_project
	cd taptuna_core && cargo clean
	rm -rf .pytest_cache tests/__pycache__