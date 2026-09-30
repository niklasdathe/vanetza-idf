#!/usr/bin/env python3
"""Check an ETSI TTCN-3 campaign against the repository's pinned baseline.

The raw runner intentionally returns non-zero for every non-PASS verdict. This
checker is the CI policy layer: known upstream defects and deliberate adapter
scope gaps stay visible and executable without hiding new regressions.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def normalize_expected(value):
    if isinstance(value, str):
        return value, None, None
    if not isinstance(value, dict) or not isinstance(value.get("verdict"), str):
        raise ValueError(f"invalid expected outcome: {value!r}")
    return value["verdict"], value.get("classification"), value.get("reason")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument(
        "--expectations",
        type=Path,
        default=Path(__file__).with_name("expected-outcomes.json"),
    )
    args = parser.parse_args()

    all_expected = json.loads(args.expectations.read_text())
    if args.campaign not in all_expected:
        parser.error(f"campaign {args.campaign!r} is missing from {args.expectations}")
    expected = all_expected[args.campaign]
    result = json.loads(args.result.read_text())

    errors: list[str] = []
    if result.get("status") != "completed":
        errors.append(f"runner status is {result.get('status')!r}, expected 'completed'")
    if not result.get("campaign_complete"):
        errors.append("runner did not observe exactly one verdict for every selected testcase")
    for field in ("missing_cases", "unexpected_cases", "duplicate_cases"):
        if result.get(field):
            errors.append(f"{field}: {result[field]}")

    verdict_items = result.get("verdicts")
    if not isinstance(verdict_items, list):
        errors.append("result.verdicts is not an array")
        verdict_items = []

    observed = {}
    for item in verdict_items:
        if not isinstance(item, dict) or "testcase" not in item or "verdict" not in item:
            errors.append(f"malformed verdict item: {item!r}")
            continue
        name = item["testcase"]
        if name in observed:
            errors.append(f"duplicate testcase in result: {name}")
        observed[name] = str(item["verdict"]).lower()

    expected_names = set(expected)
    observed_names = set(observed)
    if expected_names != observed_names:
        missing = sorted(expected_names - observed_names)
        extra = sorted(observed_names - expected_names)
        if missing:
            errors.append(f"baseline testcases missing from run: {missing}")
        if extra:
            errors.append(f"unbaselined testcases appeared in run: {extra}")

    rows = []
    for testcase, expected_value in expected.items():
        wanted, classification, reason = normalize_expected(expected_value)
        wanted = wanted.lower()
        actual = observed.get(testcase, "missing")
        ok = actual == wanted
        if not ok:
            errors.append(f"{testcase}: got {actual!r}, expected {wanted!r}")
        rows.append((testcase, actual, wanted, classification or "", reason or "", ok))

    summary_lines = [
        f"### ETSI TTCN-3: `{args.campaign}`",
        "",
        "| Testcase | Actual | Baseline | Classification |",
        "|---|---:|---:|---|",
    ]
    for testcase, actual, wanted, classification, _, ok in rows:
        marker = "" if ok else " **CHANGED**"
        summary_lines.append(
            f"| `{testcase}` | `{actual}`{marker} | `{wanted}` | {classification} |"
        )
    summary_lines.append("")
    if errors:
        summary_lines.append("**Result: regression / campaign mismatch.**")
        summary_lines.extend(f"- {error}" for error in errors)
    else:
        non_pass = sum(1 for _, actual, _, _, _, _ in rows if actual != "pass")
        summary_lines.append(
            f"**Result: baseline matched.** {len(rows) - non_pass}/{len(rows)} PASS; "
            f"{non_pass} explicitly baselined non-PASS verdict(s)."
        )

    summary = "\n".join(summary_lines) + "\n"
    print(summary)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(summary + "\n")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
