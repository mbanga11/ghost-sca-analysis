#!/usr/bin/env python3
"""Tag each finding with where it lives in Ghost.

Builds a dependency graph from each release's lockfile and workspace package.json
files (read straight from git, so no checkout is needed), then walks the graph
from each workspace to see what actually pulls each vulnerable package in.
"""

import csv
import fnmatch
import json
import os
import re
import subprocess
from collections import Counter, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = Path.home() / "Projects" / "ghost-source"
FINDINGS = ROOT / "analysis" / "findings.csv"
TAGS = {"old": "v5.105.0", "latest": "v6.74.0"}
SERVERS = {"old": "ghost/core", "latest": "ghost"}
PROD = ("dependencies", "optionalDependencies")
ALL = PROD + ("devDependencies",)


def git(*args):
    return subprocess.run(["git", "-C", str(SRC), *args],
                          capture_output=True, text=True, check=True).stdout


def is_frontend(ws):
    return ws == "ghost/admin" or ws.startswith("apps/")


def split_spec(spec):
    """'@scope/name@^1.0' -> ('@scope/name', '^1.0'), following npm: aliases."""
    name, rng = re.match(r"^(@?[^@]+)@(.*)$", spec).groups()
    if rng.startswith("npm:"):
        name, rng = split_spec(rng[4:])
    return name, rng


def base(node):
    return node.split("(")[0]  # drop pnpm peer-dependency suffixes


# ---------- old release: yarn workspaces + yarn.lock ----------

def load_yarn_workspaces(tag):
    files = git("ls-tree", "-r", "--name-only", tag).splitlines()
    root = json.loads(git("show", f"{tag}:package.json"))
    globs = root.get("workspaces", [])
    globs = globs.get("packages", []) if isinstance(globs, dict) else globs
    print(f"  workspace globs: {globs}")
    workspaces = {".": root}
    for f in files:
        if not f.endswith("/package.json") or "node_modules" in f:
            continue
        d = f[: -len("/package.json")]
        if any(d.count("/") == g.count("/") and fnmatch.fnmatch(d, g) for g in globs):
            workspaces[d] = json.loads(git("show", f"{tag}:{f}"))
    return workspaces


def yarn_graph(tag):
    workspaces = load_yarn_workspaces(tag)
    spec_to_node, deps = {}, {}
    keys = node = section = None
    for line in git("show", f"{tag}:yarn.lock").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not line[0].isspace():
            keys = [k.strip().strip('"') for k in line.rstrip(":").split(", ")]
            node = section = None
        elif not line.startswith("    "):
            text = line.strip()
            section = text[:-1] if text.endswith(":") else None
            if text.startswith("version "):
                node = f'{split_spec(keys[0])[0]}@{text.split(" ", 1)[1].strip(chr(34))}'
                deps.setdefault(node, [])
                for k in keys:
                    spec_to_node[k] = node
        elif section in PROD and node:
            dep, rng = line.strip().split(" ", 1)
            deps[node].append(f'{dep.strip(chr(34))}@{rng.strip(chr(34))}')

    names = {pkg.get("name"): ws for ws, pkg in workspaces.items()}

    def ws_edges(ws, sections):
        out = []
        for sec in sections:
            for name, rng in (workspaces[ws].get(sec) or {}).items():
                if name in names:
                    out.append("ws:" + names[name])
                elif f"{name}@{rng}" in spec_to_node:
                    out.append(spec_to_node[f"{name}@{rng}"])
        return out

    def children(n):
        if n.startswith("ws:"):
            return ws_edges(n[3:], PROD)
        return [spec_to_node[s] for s in deps.get(n, []) if s in spec_to_node]

    return ws_edges, children, list(workspaces)


# ---------- latest release: pnpm importers + snapshots ----------

def pnpm_graph(tag):
    doc = git("show", f"{tag}:pnpm-lock.yaml").split("\n---\n")[-1]  # project document
    ruby = "require 'yaml'; require 'json'; puts JSON.dump(YAML.safe_load(STDIN.read))"
    data = json.loads(subprocess.run(["ruby", "-e", ruby], input=doc,
                                     capture_output=True, text=True, check=True).stdout)
    importers, snapshots = data.get("importers", {}), data.get("snapshots", {})

    def key(name, version):
        if version.startswith("link:") or "runtime:" in version:
            return None
        b = version.split("(")[0]
        if b and not b[0].isdigit() and "@" in b[1:]:  # npm alias: 'real-name@1.2.3'
            return version
        return f"{name}@{version}"

    def ws_edges(ws, sections):
        out = []
        for sec in sections:
            for name, info in (importers.get(ws, {}).get(sec) or {}).items():
                v = str(info["version"] if isinstance(info, dict) else info)
                if v.startswith("link:"):
                    out.append("ws:" + os.path.normpath(os.path.join(ws, v[5:])))
                elif key(name, v):
                    out.append(key(name, v))
        return out

    def children(n):
        if n.startswith("ws:"):
            return ws_edges(n[3:], PROD)
        snap = snapshots.get(n) or {}
        return [k for sec in PROD for name, v in (snap.get(sec) or {}).items()
                if (k := key(name, str(v)))]

    return ws_edges, children, list(importers)


# ---------- walk the graph ----------

def reach(starts, children):
    seen, q = set(), deque(starts)
    while q:
        n = q.popleft()
        if n not in seen:
            seen.add(n)
            q.extend(children(n))
    return {base(n) for n in seen if not n.startswith("ws:")}


def analyze(release, tag):
    print(f"{release} ({tag}):")
    ws_edges, children, ws_list = yarn_graph(tag) if release == "old" else pnpm_graph(tag)
    print(f"  {len(ws_list)} workspaces; server root present: {SERVERS[release] in ws_list}")
    fronts = [ws for ws in ws_list if is_frontend(ws)]
    return {
        "server": reach(ws_edges(SERVERS[release], PROD), children),
        "front_prod": reach([e for ws in fronts for e in ws_edges(ws, PROD)], children),
        "front_all": reach([e for ws in fronts for e in ws_edges(ws, ALL)], children),
        "per_ws": {ws: reach(ws_edges(ws, ALL), children) for ws in ws_list},
        "direct": {base(e) for ws in ws_list for e in ws_edges(ws, ALL) if not e.startswith("ws:")},
    }


def main():
    rows = list(csv.DictReader(FINDINGS.open()))
    columns = list(rows[0].keys())
    if "reached_from" not in columns:
        columns.insert(columns.index("dep_type") + 1, "reached_from")

    for release, tag in TAGS.items():
        g = analyze(release, tag)
        for r in (r for r in rows if r["release"] == release):
            node = f'{r["package"]}@{r["version"]}'
            sources = sorted(ws for ws, s in g["per_ws"].items() if node in s)
            if r["purl"].startswith("pkg:github/"):
                r["component"], r["dep_type"] = "ci-pipeline", "ci"
            else:
                if node in g["server"]:
                    r["component"] = "server-runtime"
                elif node in g["front_prod"]:
                    r["component"] = "frontend-runtime"
                elif node in g["front_all"]:
                    r["component"] = "frontend-dev-or-build"
                elif sources:
                    r["component"] = "dev-tooling"
                else:
                    r["component"] = "unknown"
                r["dep_type"] = "direct" if node in g["direct"] else ("transitive" if sources else "unknown")
            extra = f" (+{len(sources) - 3} more)" if len(sources) > 3 else ""
            r["reached_from"] = " ".join(sources[:3]) + extra

    with FINDINGS.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for r in rows:
            writer.writerow({c: r.get(c, "") for c in columns})

    for release in ("latest", "old"):
        mine = [r for r in rows if r["release"] == release]
        print(f"\n=== {release} ===")
        print("by component:", dict(Counter(r["component"] for r in mine)))
        print("by dep type: ", dict(Counter(r["dep_type"] for r in mine)))
        for r in mine:
            important = release == "latest" or r["kev"] == "yes" or (r["epss"] and float(r["epss"]) >= 0.10)
            if important:
                print(f'  {r["component"]:22} {r["dep_type"]:10} {r["package"]}@{r["version"]}  {r["vuln_id"]}  <- {r["reached_from"]}')
        unknown = sorted({f'{r["package"]}@{r["version"]}' for r in mine if r["component"] == "unknown"})
        if unknown:
            print(f"  unknown ({len(unknown)}):", ", ".join(unknown[:15]))


if __name__ == "__main__":
    main()
