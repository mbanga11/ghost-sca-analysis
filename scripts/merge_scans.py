#!/usr/bin/env python3
"""Merge Grype and Trivy results for both Ghost releases into one CSV."""

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASES = {"old": "v5.105.0", "latest": "v6.74.0"}
SEVERITIES = ["UNKNOWN", "NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def sev_rank(sev):
    sev = (sev or "UNKNOWN").upper()
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0


def pick_id(ids):
    # prefer a CVE, then a GHSA, then whatever is left
    for prefix in ("CVE-", "GHSA-"):
        matches = sorted(i for i in ids if i.startswith(prefix))
        if matches:
            return matches[0]
    return sorted(ids)[0]


def read_grype(path):
    data = json.loads(path.read_text())
    for m in data.get("matches", []):
        vuln, art = m["vulnerability"], m["artifact"]
        related = m.get("relatedVulnerabilities", [])
        scores = [
            c.get("metrics", {}).get("baseScore")
            for v in [vuln] + related
            for c in v.get("cvss", [])
            if str(c.get("version", "")).startswith("3")
        ]
        yield {
            "package": art["name"],
            "version": art["version"],
            "purl": art.get("purl", ""),
            "pkg_type": art.get("type", ""),
            "ids": {vuln["id"]} | {r["id"] for r in related},
            "severity": vuln.get("severity", ""),
            "cvss": max((s for s in scores if s), default=None),
            "fixed": ", ".join(vuln.get("fix", {}).get("versions", [])),
            "locations": {loc.get("path", "") for loc in art.get("locations", [])},
        }


def read_trivy(path):
    data = json.loads(path.read_text())
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            scores = [c.get("V3Score") for c in (v.get("CVSS") or {}).values()]
            yield {
                "package": v["PkgName"],
                "version": v["InstalledVersion"],
                "purl": (v.get("PkgIdentifier") or {}).get("PURL", ""),
                "pkg_type": result.get("Type", ""),
                "ids": {v["VulnerabilityID"]} | set(v.get("VendorIDs") or []),
                "severity": v.get("Severity", ""),
                "cvss": max((s for s in scores if s), default=None),
                "fixed": v.get("FixedVersion", ""),
                "locations": set(),
            }


def merge(release):
    # group by package + version, then join findings that share any ID
    groups = {}
    sources = [
        ("grype", read_grype(ROOT / "scans" / f"{release}-grype.json")),
        ("trivy", read_trivy(ROOT / "scans" / f"{release}-trivy.json")),
    ]
    for tool, findings in sources:
        for f in findings:
            bucket = groups.setdefault((f["package"], f["version"]), [])
            rec = next((r for r in bucket if r["ids"] & f["ids"]), None)
            if rec is None:
                rec = {"package": f["package"], "version": f["version"], "purl": "",
                       "pkg_type": "", "ids": set(), "sev": {}, "cvss": None,
                       "fixed": "", "locations": set()}
                bucket.append(rec)
            rec["ids"] |= f["ids"]
            rec["sev"][tool] = (f["severity"] or "").upper()
            if f["cvss"] and (rec["cvss"] is None or f["cvss"] > rec["cvss"]):
                rec["cvss"] = f["cvss"]
            rec["fixed"] = rec["fixed"] or f["fixed"]
            rec["purl"] = rec["purl"] or f["purl"]
            rec["pkg_type"] = rec["pkg_type"] or f["pkg_type"]
            rec["locations"] |= f["locations"]
    return [r for bucket in groups.values() for r in bucket]


def review_reasons(rec):
    reasons = []
    if len(rec["sev"]) == 1:
        reasons.append(f"only {next(iter(rec['sev']))}")
    if len(set(rec["sev"].values())) > 1:
        reasons.append("severity mismatch")
    real_ids = [i for i in rec["ids"] if i.startswith(("CVE-", "GHSA-"))]
    if any(i.startswith("NSWG-") for i in rec["ids"]) and not real_ids:
        reasons.append("legacy NSWG id, likely duplicate")
    if not rec["fixed"]:
        reasons.append("no fix listed")
    return "; ".join(reasons)


COLUMNS = ["release", "tag", "package", "version", "vuln_id", "aliases", "scanners",
           "severity_grype", "severity_trivy", "severity_max", "cvss", "fixed_version",
           "pkg_type", "purl", "lockfile", "component", "dep_type", "epss", "epss_date",
           "kev", "kev_date", "priority", "review", "notes"]


def main():
    rows = []
    for release, tag in RELEASES.items():
        for rec in merge(release):
            sev_g = rec["sev"].get("grype", "")
            sev_t = rec["sev"].get("trivy", "")
            vuln_id = pick_id(rec["ids"])
            rows.append({
                "release": release, "tag": tag,
                "package": rec["package"], "version": rec["version"],
                "vuln_id": vuln_id,
                "aliases": " ".join(sorted(rec["ids"] - {vuln_id})),
                "scanners": "+".join(sorted(rec["sev"])),
                "severity_grype": sev_g, "severity_trivy": sev_t,
                "severity_max": max([sev_g, sev_t], key=sev_rank),
                "cvss": rec["cvss"] if rec["cvss"] is not None else "",
                "fixed_version": rec["fixed"],
                "pkg_type": rec["pkg_type"], "purl": rec["purl"],
                "lockfile": " ".join(sorted(rec["locations"])),
                "review": review_reasons(rec),
            })
        mine = [r for r in rows if r["release"] == release]
        both = sum(1 for r in mine if r["scanners"] == "grype+trivy")
        flagged = sum(1 for r in mine if r["review"])
        print(f"{release} ({tag}): {len(mine)} findings, {both} found by both scanners, "
              f"{len(mine) - both} by one only, {flagged} flagged for review")

    rows.sort(key=lambda r: (r["release"] != "latest", -sev_rank(r["severity_max"]), r["package"]))
    out = ROOT / "analysis" / "findings.csv"
    with out.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        for r in rows:
            writer.writerow({c: r.get(c, "") for c in COLUMNS})
    print(f"wrote {len(rows)} rows to {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
