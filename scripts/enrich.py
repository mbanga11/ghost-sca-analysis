#!/usr/bin/env python3
"""Add EPSS scores and CISA KEV status to analysis/findings.csv."""

import csv
import json
import time
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FINDINGS = ROOT / "analysis" / "findings.csv"
RAW = ROOT / "analysis" / "enrichment"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={}"


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "ghost-sca-analysis"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def cves_for(row):
    ids = [row["vuln_id"]] + row["aliases"].split()
    return sorted({i for i in ids if i.startswith("CVE-")})


def main():
    RAW.mkdir(parents=True, exist_ok=True)
    rows = list(csv.DictReader(FINDINGS.open()))
    columns = list(rows[0].keys())
    if "epss_percentile" not in columns:
        columns.insert(columns.index("epss") + 1, "epss_percentile")

    all_cves = sorted({c for r in rows for c in cves_for(r)})
    print(f"{len(rows)} findings, {len(all_cves)} unique CVEs")

    # CISA KEV: one download, saved as-is
    kev = fetch_json(KEV_URL)
    (RAW / "kev.json").write_text(json.dumps(kev))
    kev_added = {v["cveID"]: v["dateAdded"] for v in kev["vulnerabilities"]}
    print(f"KEV catalog {kev.get('catalogVersion')}: {len(kev_added)} entries")

    # EPSS: ask in batches so the URL stays short
    epss = {}
    for i in range(0, len(all_cves), 50):
        batch = all_cves[i:i + 50]
        data = fetch_json(EPSS_URL.format(",".join(batch)))
        for item in data.get("data", []):
            epss[item["cve"]] = {
                "epss": float(item["epss"]),
                "percentile": float(item["percentile"]),
                "date": item["date"],
            }
        time.sleep(1)
    (RAW / "epss.json").write_text(json.dumps(epss, indent=1, sort_keys=True))
    print(f"EPSS scores found for {len(epss)} of {len(all_cves)} CVEs")

    for r in rows:
        cves = cves_for(r)
        scored = [epss[c] for c in cves if c in epss]
        if scored:
            best = max(scored, key=lambda s: s["epss"])
            r["epss"] = f'{best["epss"]:.5f}'
            r["epss_percentile"] = f'{best["percentile"]:.3f}'
            r["epss_date"] = best["date"]
        else:
            r["epss"] = r["epss_percentile"] = r["epss_date"] = ""

        hits = [c for c in cves if c in kev_added]
        if not cves:
            r["kev"], r["kev_date"] = "n/a (no CVE)", ""
        elif hits:
            r["kev"], r["kev_date"] = "yes", min(kev_added[c] for c in hits)
        else:
            r["kev"], r["kev_date"] = "no", ""

    with FINDINGS.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for r in rows:
            writer.writerow({c: r.get(c, "") for c in columns})

    print(f"\nenrichment retrieved {date.today().isoformat()}; raw data in analysis/enrichment/")
    for release in ("latest", "old"):
        mine = [r for r in rows if r["release"] == release]
        kev_rows = [r for r in mine if r["kev"] == "yes"]
        high = [r for r in mine if r["epss"] and float(r["epss"]) >= 0.10]
        print(f"\n=== {release} ===")
        print(f"KEV hits: {len(kev_rows)}   EPSS >= 10%: {len(high)}   no EPSS data: {sum(1 for r in mine if not r['epss'])}")
        for r in kev_rows:
            print(f'  KEV  {r["package"]}@{r["version"]}  {r["vuln_id"]}  added {r["kev_date"]}')
        top = sorted((r for r in mine if r["epss"]), key=lambda r: float(r["epss"]), reverse=True)[:10]
        for r in top:
            print(f'  EPSS {float(r["epss"]):.3f}  {r["severity_max"]:8} {r["package"]}@{r["version"]}  {r["vuln_id"]}')


if __name__ == "__main__":
    main()
