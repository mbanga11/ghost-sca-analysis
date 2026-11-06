# Methodology

## Environment
- Date: 2026-11-03
- Machine: MacBook Air, Apple Silicon (arm64), macOS

## Tool versions
| Tool | Version |
| --- | --- |
| git | 2.50.1 (Apple Git-155) |
| syft | 1.56.0 |
| grype | 0.121.1 (DB schema 6) |
| trivy | 0.76.1 |
| jq | 1.7.1 |
| python | 3.13.5 |

## Progress log
- 2026-11-03: Generated old SBOM (v5.105.0) with Syft. 3,206 components: 3,170 npm, 26 GitHub, 10 with no package URL. Needs regenerating with --source-name/--source-version.
- 2026-11-04: Regenerated old SBOM with --source-name ghost --source-version v5.105.0. 3,198 packages, 3,206 total components.
- Side observation (v5.105.0): 26 GitHub Actions in CI. Only 1 pinned to a commit SHA; several pinned to mutable tags, 3+ pinned to a branch (main). actions/upload-artifact v3 in use. Revisit for a CI/CD supply chain section.
- 2026-11-04: Latest SBOM (v6.74.0) with Syft 1.56.0 returned only 136 packages vs ~2,775 lockfile entries.
  Root cause: pnpm-lock.yaml contains two YAML documents (line 1: pnpm self-install entries, line 158: project dependencies, both lockfileVersion 9.0). Syft parsed only the first document (15 pnpm packages). Workaround and second tool needed.
- 2026-11-04: Trivy 0.76.1 CycloneDX SBOM of v6.74.0: 1,712 components (dev/test dependencies excluded by default). Trivy parsed the two-document pnpm lockfile correctly.

## SBOM verification (2026-11-04)
- Syft's default silently excluded some dev dependencies for Yarn (old release: 3,170 packages) but not for pnpm. Fixed by setting SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true for BOTH releases, so scope is identical: every third-party package in each lockfile. Dev vs runtime classification is done manually in Phase 4, not by tool defaults.
- Old (v5.105.0): Syft 4,044 npm packages = independent yarn.lock parse (4,044 unique name@version). Trivy (--include-dev-deps) agrees on 4,042. Trivy-only extras are all first-party: ~106 @tryghost/* workspace packages, ghost, ghost-admin, ghost-monorepo, bundled themes (casper, source), test fixture themes, and in-repo admin addons in ghost/admin/lib (asset-delivery, ember-power-calendar-moment, ember-power-calendar-utils). Syft-only: google-caja-bower, keymaster (git/URL deps).
- Latest (v6.74.0): Syft 2,787 = Trivy 2,787, agreement on 2,786. Differences: first-party @ghost-internal/i18n-review (Syft), node@22.23.4 runtime (Trivy; excluded from Syft by workaround, tracked separately).
- Conclusion: both SBOMs are complete for third-party npm dependencies and built with identical scope.
- Reproduce: export SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true before running Syft.
- Side finding: Trivy flagged ghost/identity-token-service/private.pem (committed private key file). To check whether it is a test key.

## Vulnerability scanning (2026-11-05)
- Grype 0.121.1, DB schema v6.1.10 built 2026-11-05T06:21Z. Trivy 0.76.1, DB v2 updated 2026-11-05T19:01Z. Both scanners run on the same verified Syft SBOMs so differences reflect the scanners, not the inventory.
- Old (v5.105.0): 568 matches, 424 unique IDs (both tools). Grype severity: 27 critical, 268 high, 211 medium, 62 low; 549 with a fix available, 19 without.
- Latest (v6.74.0): 11 matches, 8 unique IDs (both tools). Grype severity: 0 critical, 1 high, 9 medium, 1 low; 10 fixable, 1 not.
- Old release scanned with a 2026 database = retrospective analysis; many findings were disclosed after Dec 2024.
- ID normalization: Grype reports GHSA IDs, Trivy reports CVE IDs. After mapping GHSA to related CVE, agreement is 565/568 (old) and 11/11 (latest).
- Differences: Grype-only actions/download-artifact@v4 (GitHub Action), google-caja-bower (git dep), deepmerge CVE; Trivy-only bl/minimatch (legacy NSWG IDs), toml CVE. Severity disagreement: semver@2.3.2 CVE-2015-8855 (Grype HIGH, Trivy MEDIUM).
- Grype prompted an update to 0.121.2; kept 0.121.1 so both releases are scanned with the same version.
- NSWG check: Trivy-only bl@0.8.2 (NSWG-ECO-391) and minimatch@0.3.0 (NSWG-ECO-118) are legacy Node Security WG records; both tools already report the same CVEs on those package versions, so these are duplicates, not extra vulnerabilities. Net scanner agreement is effectively complete.

## Side finding: committed private key (2026-11-05)
- v5.105.0 contains ghost/identity-token-service/private.pem (PKCS#8 "BEGIN PRIVATE KEY"), flagged by Trivy secret scanning. Not referenced by name in the service's src or test code; README does not mention it. Absent from v6.74.0 (no private.pem anywhere in the repo).
- Assessment: low risk, likely an unused development leftover. Caveats: the key remains retrievable from git history, and code review alone cannot prove it was never used outside the repo. Recommendation: treat committed keys as exposed and rotate if ever used; add secret scanning to CI.

## Merge and normalize (2026-11-05)
- scripts/merge_scans.py reads all 4 scan files, groups findings by package@version, and joins records that share any ID (CVE or GHSA aliases), so no manual ID mapping is needed. Never deduplicates on CVE alone.
- Keeps per-tool evidence: both severities, scanners, max CVSS v3, fix version, lockfile, PURL. Adds a review column (single scanner, severity mismatch, legacy NSWG ID, no fix).
- Output: analysis/findings.csv, 582 rows (old 571, latest 11). Result matches the Phase 3 manual cross-check (565 + 3 + 3 for old).

## Enrichment (2026-11-05)
- scripts/enrich.py adds EPSS (FIRST API, scores dated per row in epss_date) and CISA KEV status (catalog 2026.11.04, 1,768 entries). Raw responses saved to analysis/enrichment/ for reproducibility.
- 384 unique CVEs across 582 findings; EPSS found for 383. Findings with only GHSA/NSWG IDs have no EPSS (latest: 2, old: 53).
- A finding takes the max EPSS of its CVE aliases; KEV = yes if any alias is in the catalog.

## Component tagging (2026-11-05)
- scripts/tag_components.py reads workspace package.json files and lockfiles directly from git (git show TAG:path, no checkout), builds a dependency graph, and walks it from each workspace.
- Categories: server-runtime (reachable from the server workspace's dependencies/optionalDependencies), frontend-runtime (apps/* or ghost/admin production deps), frontend-dev-or-build (frontend devDependencies: bundled or build tool, needs manual check), dev-tooling (reachable only from other workspaces/dev deps), ci-pipeline (GitHub Actions), unknown. dep_type = direct if any workspace declares it, else transitive. reached_from lists the workspaces that pull it in.
- Server workspace differs by release: ghost/core in v5.105.0, ghost in v6.74.0 (Ghost restructured; verified via ghost/package.json name "ghost" and index.js). First run missed this (sanity check printed "server root present: False"); fixed with a per-release mapping.
- Limitation: tags follow manifest sections, not actual code use. Example: vite is listed under app dependencies so it is tagged frontend-runtime, but it is a build tool. "server-runtime" means installed with the server, not proven to be called. Verified manually for deep-dive findings in Phase 5.
- Results: latest 8 server-runtime, 1 frontend-runtime, 2 dev-tooling. Old 341 server-runtime, 47 frontend-runtime, 157 frontend-dev-or-build, 25 dev-tooling, 1 ci-pipeline.
