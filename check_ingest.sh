#!/usr/bin/env bash
set -euo pipefail

# 1. tshark
test -n "$(python -c 'from taptuna.tshark_check import get_tshark_path; print(get_tshark_path() or "")')"

# 2. parse_line
python - <<'PY'
from taptuna.ingest import _parse_line
r = _parse_line("0\t1\t1.0\t10.0.0.1\t10.0.0.2\t1234\t80\t1000\t0\t5\t1\t0\t0\t0\t48656c6c6f")
assert r and r.payload == b"Hello" and r.syn
print("parse_line OK")
PY

# 3. run_tshark
python - <<'PY'
from pathlib import Path
from taptuna.ingest import run_tshark
rows = run_tshark(Path("test.pcap"))
assert rows, "no rows"
print(f"run_tshark OK ({len(rows)} rows)")
PY

# 4. group
python - <<'PY'
from pathlib import Path
from taptuna.ingest import run_tshark, group_by_stream
s = group_by_stream(run_tshark(Path("test.pcap")))
assert len(s) == 1, s
print("group_by_stream OK")
PY

echo "ALL OK"
