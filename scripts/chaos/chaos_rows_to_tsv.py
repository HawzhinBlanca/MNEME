#!/usr/bin/env python3
"""Convert ``CHAOS_ROW|{json}`` log lines into the soak matrix TSV.

This replaces the fragile ``sed`` column extraction in ``soak.sh``: rows whose
``actual`` field carries escaped quotes (e.g. ``disk_full``'s
``IoFailed{ kind: "..." }``) shifted columns under ``echo -e``/``sed``. Parsing
the JSON authoritatively makes the TSV match the ``CHAOS_ROW`` ground truth.

Usage::

    grep '^CHAOS_ROW|' soak.log | python3 chaos_rows_to_tsv.py <run> <unsafe_log>

Writes one TSV row per input line to stdout (column order matches the soak
header), appends genuine unsafe events to ``<unsafe_log>``, and reports any JSON
parse failure on stderr (which the caller surfaces rather than miscounting it as
an unsafe event).
"""
import json
import sys

COLUMNS = [
    "fault",
    "injection_point",
    "expected",
    "actual",
    "verify_result",
    "incomplete",
    "open_result",
    "unsafe_state",
    "unsafe_reason",
]


def cell(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")


def main() -> int:
    run = sys.argv[1] if len(sys.argv) > 1 else "?"
    unsafe_log = sys.argv[2] if len(sys.argv) > 2 else None
    unsafe_fh = open(unsafe_log, "a", encoding="utf-8") if unsafe_log else None
    try:
        for raw in sys.stdin:
            line = raw.rstrip("\n")
            if not line.startswith("CHAOS_ROW|"):
                continue
            payload = line.split("|", 1)[1]
            try:
                row = json.loads(payload)
            except json.JSONDecodeError as exc:
                print(f"run={run} JSON_PARSE_ERROR: {exc}", file=sys.stderr)
                continue
            iter_v = row.get("iter", "")
            fields = [str(run), cell(iter_v)] + [cell(row.get(c, "")) for c in COLUMNS]
            sys.stdout.write("\t".join(fields) + "\n")
            if row.get("unsafe_state") is True and unsafe_fh is not None:
                unsafe_fh.write(
                    f"run={run} iter={iter_v} "
                    f"fault={row.get('fault', '')} reason={row.get('unsafe_reason', '')}\n"
                )
    finally:
        if unsafe_fh is not None:
            unsafe_fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
