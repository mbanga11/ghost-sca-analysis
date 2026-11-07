#!/usr/bin/env python3
"""Build charts for the README and report from analysis/findings.csv and the SBOMs."""
import csv
import json
import random
import re
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
FINDINGS = ROOT / "analysis" / "findings.csv"
OUT = ROOT / "charts"
OUT.mkdir(exist_ok=True)

RELEASES = [("old", "v5.105.0"), ("latest", "v6.74.0")]
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
PRIOS = ["P0", "P1", "P2", "P3", "Review"]
COLORS = {"old": "#9aa5b1", "latest": "#2f6fdb", "rubric": "#9aa5b1", "final": "#2f6fdb"}

rows = list(csv.DictReader(FINDINGS.open()))


def prio_of(text):
    m = re.search(r"\b(P[0-3]|Review)\b", text or "")
    return m.group(1) if m else None


def npm_count(path):
    data = json.loads(path.read_text())
    comps = data.get("components") or data.get("artifacts") or []
    return len({c.get("purl", "").split("?")[0] for c in comps if c.get("purl", "").startswith("pkg:npm")})


def save(fig, name):
    fig.tight_layout()
    fig.savefig(OUT / name, dpi=160)
    plt.close(fig)
    print(f"wrote charts/{name}")


# 1. SBOM size
sizes = {r: npm_count(ROOT / "sbom" / f"{r}-sbom.json") for r, _ in RELEASES}
fig, ax = plt.subplots(figsize=(5, 4))
bars = ax.bar([t for _, t in RELEASES], [sizes[r] for r, _ in RELEASES], color=[COLORS[r] for r, _ in RELEASES])
ax.bar_label(bars)
ax.set_title("npm packages in SBOM")
ax.spines[["top", "right"]].set_visible(False)
save(fig, "sbom_size.png")

# 2. Findings by severity
sev = {r: Counter(row["severity_max"].upper() for row in rows if row["release"] == r) for r, _ in RELEASES}
fig, ax = plt.subplots(figsize=(7, 4))
w = 0.38
for i, (r, tag) in enumerate(RELEASES):
    xs = [j + (i - 0.5) * w for j in range(len(SEVS))]
    b = ax.bar(xs, [sev[r].get(s, 0) for s in SEVS], w, label=tag, color=COLORS[r])
    ax.bar_label(b)
ax.set_xticks(range(len(SEVS)), [s.title() for s in SEVS])
ax.set_title("Findings by severity (merged Grype + Trivy)")
ax.legend(frameon=False)
ax.spines[["top", "right"]].set_visible(False)
save(fig, "severity_by_release.png")

# 3. Rubric vs final priority
if all(prio_of(row.get("priority_rule")) for row in rows):
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, (r, tag) in zip(axes, RELEASES):
        mine = [row for row in rows if row["release"] == r]
        rub = Counter(prio_of(row["priority_rule"]) for row in mine)
        fin = Counter(row["priority"] for row in mine)
        for i, (label, c) in enumerate([("rubric", rub), ("final", fin)]):
            xs = [j + (i - 0.5) * w for j in range(len(PRIOS))]
            b = ax.bar(xs, [c.get(p, 0) for p in PRIOS], w, label="Rubric" if label == "rubric" else "After deep dives", color=COLORS[label])
            ax.bar_label(b, fontsize=8)
        ax.set_xticks(range(len(PRIOS)), PRIOS)
        ax.set_title(tag)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].legend(frameon=False)
    fig.suptitle("Priority: rubric vs after manual deep dives")
    save(fig, "priority_before_after.png")
    for r, tag in RELEASES:
        mine = [row for row in rows if row["release"] == r]
        before = sum(prio_of(row["priority_rule"]) in ("P0", "P1") for row in mine)
        after = sum(row["priority"] in ("P0", "P1") for row in mine)
        print(f"  {tag}: P0/P1 rubric {before} -> final {after}")
else:
    print("skipped priority_before_after.png: priority_rule column has no P0-P3/Review values")

# 4. EPSS vs severity (old release)
random.seed(1)
old = [row for row in rows if row["release"] == "old" and row["epss"] and row["severity_max"].upper() in SEVS]
fig, ax = plt.subplots(figsize=(7, 4.5))
for kev in (False, True):
    pts = [row for row in old if (row["kev"].lower() == "yes") == kev]
    ax.scatter(
        [SEVS.index(row["severity_max"].upper()) + random.uniform(-0.25, 0.25) for row in pts],
        [max(float(row["epss"]), 1e-5) for row in pts],
        s=40 if kev else 12, alpha=1 if kev else 0.45,
        color="#d64545" if kev else "#2f6fdb", label="On CISA KEV" if kev else "Not on KEV",
        zorder=3 if kev else 2,
    )
ax.set_yscale("log")
ax.set_xticks(range(len(SEVS)), [s.title() for s in SEVS])
ax.set_ylabel("EPSS (log scale)")
ax.set_title("v5.105.0: scanner severity vs exploitation likelihood")
ax.legend(frameon=False)
ax.spines[["top", "right"]].set_visible(False)
save(fig, "epss_vs_severity.png")

print(f"  SBOM npm packages: {sizes}")
print(f"  severity counts: { {r: dict(sev[r]) for r, _ in RELEASES} }")
