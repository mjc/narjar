#!/usr/bin/env python3
"""Small dependency-free evaluator for the frozen NARJ-75 decision gates."""
import json
import sys
from pathlib import Path


CONSTITUTION = json.loads(Path(__file__).with_name("constitution.json").read_text())


def classify(savings_percent):
    if savings_percent < 25:
        return "reject"
    if savings_percent >= 50:
        return "strong"
    return "conditional"


def validate_provenance(record):
    required = set(CONSTITUTION["provenance_required_fields"])
    return sorted(required - record.keys())


def validate_metrics(record):
    required = set(CONSTITUTION["metric_required_fields"])
    return sorted(required - record.keys())


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
