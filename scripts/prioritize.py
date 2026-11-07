#!/usr/bin/env python3
"""Assign P0-P3/Review to every finding using docs/rubric.md, then apply manual overrides."""

import csv
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FINDINGS = ROOT / "analysis" / "findings.csv"
OVERRIDES = ROOT / "analysis" / "overrides.csv"
RUNTIME = {"server-runtime", "frontend-runtime"}
SEVERE = {"HIGH", "CRITICAL"}


def rule_priority(r):
    epss = float(r["epss"]) if r["epss"] else 0.0
    runtime = r["component"] in RUNTIME
    direct_server = r["component"] == "server-runtime" and r["dep_type"] == "direct"
    sev = r["severity_max"]

    if r["component"] == "unknown" or "legacy NSWG" in r["review"]:
        return "Review", "not enough evidence (unknown component or legacy duplicate ID)"
    if r["kev"] == "yes" and runtime:
        return "P0", "on CISA KEV and in runtime code"
    if r["kev"] == "yes":
        return "P1", "on CISA KEV (non-runtime component)"
    if runtime and epss >= 0.10:
        return "P1", f"runtime and EPSS {epss:.2f}"
    if sev in SEVERE and direct_server:
        return "P1", f"{sev} in a direct server dependency"
    if runtime and (sev in SEVERE or epss >= 0.01):
        return "P2", f"runtime, {sev}, EPSS {epss:.3f}"
    if sev == "MEDIUM" and direct_server:
        return "P2", "MEDIUM in a direct server dependency"
    if r["component"] == "frontend-dev-or-build" and epss >= 0.10:
        return "Review", f"frontend dev dep with EPSS {epss:.2f}; may be bundled, check manually"
    return "P3", f"{r['component']}, {sev}, EPSS {epss:.3f}"


def load_overrides():
    if not OVERRIDES.exists():
        OVERRIDES.write_text("release,package,version,vuln_id,priority,reason\n")
    return {(o["release"], o["package"], o["version"], o["vuln_id"]): o
            for o in csv.DictReader(OVERRIDES.open())}


def main():
    rows = list(csv.DictReader(FINDINGS.open()))
    columns = list(rows[0].keys())
    for extra in ("priority_reason", "priority_rule"):
        if extra not in columns:
            columns.insert(columns.index("priority") + 1, extra)

    overrides = load_overrides()
    used = 0
    for r in rows:
        prio, why = rule_priority(r)
        r["priority_rule"] = prio
        o = overrides.get((r["release"], r["package"], r["version"], r["vuln_id"]))
        if o:
            r["priority"], r["priority_reason"] = o["priority"], f"OVERRIDE: {o['reason']}"
            used += 1
        else:
            r["priority"], r["priority_reason"] = prio, why

    with FINDINGS.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for r in rows:
            writer.writerow({c: r.get(c, "") for c in columns})

    order = ["P0", "P1", "P2", "P3", "Review"]
    print(f"overrides applied: {used}")
    for release in ("latest", "old"):
        mine = [r for r in rows if r["release"] == release]
        counts = Counter(r["priority"] for r in mine)
        print(f"\n=== {release} ===  " + "  ".join(f"{p}: {counts.get(p, 0)}" for p in order))
        for r in sorted(mine, key=lambda r: order.index(r["priority"])):
            if r["priority"] in ("P0", "P1", "Review"):
                print(f'  {r["priority"]:6}  {r["package"]}@{r["version"]}  {r["vuln_id"]}  ({r["priority_reason"]})')


if __name__ == "__main__":
    main()
