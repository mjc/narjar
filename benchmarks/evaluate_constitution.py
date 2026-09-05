#!/usr/bin/env python3
"""Small dependency-free evaluator for the frozen NARJ-75 decision gates."""
import json
import sys
from pathlib import Path


CONSTITUTION = json.loads(Path(__file__).with_name("constitution.json").read_text())


def classify(savings_percent):
    thresholds = CONSTITUTION["primary_savings_gate_percent"]
    if savings_percent < thresholds["reject_below"]:
        return "reject"
    if savings_percent >= thresholds["strong_at_or_above"]:
        return "strong"
    return "conditional"


def missing_fields(record, required):
    empty = (None, "", [], {})
    return sorted(
        field
        for field in required
        if field not in record or record[field] in empty
    )


def validate_provenance(record):
    return missing_fields(record, CONSTITUTION["provenance_required_fields"])


def validate_metrics(record):
    return missing_fields(record, CONSTITUTION["metric_required_fields"])


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: evaluate_constitution.py RECORD.json")
    record = json.load(open(sys.argv[1]))
    missing = validate_provenance(record) + validate_metrics(record)
    if missing:
        raise SystemExit("missing required fields: " + ", ".join(missing))
    print(classify(float(record["savings_percent"])))


if __name__ == "__main__":
    main()
