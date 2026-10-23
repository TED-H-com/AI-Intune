#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == --dry-run ]]; then
  echo 'Read-only integrity_check and exact per-table counts on two stopped SQLite snapshots.'
  exit 0
fi
[[ $# == 2 && -f $1 && -f $2 ]] || { echo 'Usage: compare-rowcounts.sh OLD.sqlite NEW.sqlite' >&2; exit 2; }
# Python SQLite handles arbitrary identifiers, including embedded quotes/newlines.
python3 - "$1" "$2" <<'PY'
import pathlib, sqlite3, sys

def counts(path):
    db = sqlite3.connect(pathlib.Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise RuntimeError('integrity_check failed')
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_schema WHERE type='table'")]
        return {t: db.execute('SELECT count(*) FROM "' + t.replace('"', '""') + '"').fetchone()[0] for t in tables}
    finally:
        db.close()
try:
    old, new = map(counts, sys.argv[1:])
    for table in sorted(old.keys() | new.keys()):
        print(f'{table!r}: old={old.get(table, "missing")} new={new.get(table, "missing")}')
    if old != new:
        raise RuntimeError('table/row-count mismatch')
    print(f'Integrity OK; {len(old)} tables matched')
except (sqlite3.Error, RuntimeError) as exc:
    sys.exit(str(exc))
PY
