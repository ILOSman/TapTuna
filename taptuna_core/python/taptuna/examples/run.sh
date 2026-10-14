#!/usr/bin/env bash
# E2E-прогон на эталонном PCAP (ТЗ §20.4).
#   - генерирует test.pcap и эталоны
#   - прогоняет полный цикл CLI
#   - сверяет ключевые поля с expected/test.json
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROJECT=/tmp/taptuna_example
INPUT="$HERE/input/test.pcap"
EXPECTED="$HERE/expected/test.json"

echo "== cleaning =="
rm -rf "$PROJECT"

echo "== generating fixtures =="
python -m taptuna.examples.generate --out "$HERE"

echo "== init =="
python -m taptuna.cli init --project "$PROJECT"

echo "== ingest =="
python -m taptuna.cli ingest --project "$PROJECT" --input "$INPUT" --json > /tmp/ingest.json
python -c "import json; d=json.load(open('/tmp/ingest.json')); print(f\"packets={d['packets']} sessions={d['sessions']}\")"

echo "== interp-add =="
python -m taptuna.cli interp-add --project "$PROJECT" --file "$HERE/interp.yaml"

echo "== corpus-add =="
python -m taptuna.cli corpus-add --project "$PROJECT" --name test_corpus --file "$HERE/corpus.yaml"

echo "== corpus-list =="
python -m taptuna.cli corpus-list --project "$PROJECT"

echo "== verify =="
python -m taptuna.cli verify --project "$PROJECT" \
    --corpus test_corpus --interpretation test_fixed --out /tmp/verify.json
python -c "import json; d=json.load(open('/tmp/verify.json')); print(f\"verdict={d['verdict']} messages={d['messages']}\")"

echo "== runs =="
python -m taptuna.cli runs --project "$PROJECT"

echo "== results =="
python -m taptuna.cli results --project "$PROJECT" --run 1

echo "== report =="
python -m taptuna.cli report --project "$PROJECT" --run 1 --format md,html,json

echo "== assertions =="
python - "$EXPECTED" /tmp/ingest.json /tmp/verify.json <<'PY'
import json, sys
expected = json.load(open(sys.argv[1]))
ingest = json.load(open(sys.argv[2]))
verify = json.load(open(sys.argv[3]))

assert ingest["packets"] == expected["packets"], \
    f"packets: {ingest['packets']} != {expected['packets']}"
assert ingest["sessions"] == expected["sessions"], \
    f"sessions: {ingest['sessions']} != {expected['sessions']}"
assert verify["verdict"] == expected["verification"]["verdict"], \
    f"verdict: {verify['verdict']} != {expected['verification']['verdict']}"
assert verify["messages"] == expected["verification"]["messages"], \
    f"messages: {verify['messages']} != {expected['verification']['messages']}"

print(f"E2E OK: packets={ingest['packets']} sessions={ingest['sessions']} "
      f"verdict={verify['verdict']} messages={verify['messages']}")
PY

echo "== report files =="
ls -la "$PROJECT/reports/"

echo "ALL OK"