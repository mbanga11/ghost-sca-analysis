# Findings Log

Running list of report-worthy findings. Details and evidence are in methodology.md.

## Security findings (Ghost)
- [ ] S1: Old v5.105.0 has 568 vulnerability matches (424 unique; 27 critical, 268 high). Latest v6.74.0 has 11 (8 unique; 0 critical, 1 high). Retrospective caveat: old release scanned with a 2026 database.
- [ ] S2: Ghost migrated Yarn to pnpm between releases; comparisons account for lockfile format.
- [ ] S3: CI/CD supply chain: GitHub Actions grew from 26 to 78. In v5.105.0 only 1 of 26 pinned to a commit SHA, several pinned to branch `main`. actions/download-artifact@v4 has a known advisory (GHSA-cxww-7g56-2vh6). actions/upload-artifact v3 (deprecated) in use.
- [ ] S4: Committed private key (ghost/identity-token-service/private.pem) in v5.105.0, removed by v6.74.0. Low risk, still in git history.
- [ ] S5: Node.js runtime pinned at 22.23.4 in v6.74.0. PENDING: manual check against Node security releases.

## Tooling / methodology findings
- [ ] T1: Syft 1.56.0 drops the entire pnpm lockfile when it hits a `node@runtime` entry (`type: variations`). Found by bisection. Candidate upstream bug report.
- [ ] T2: Syft's default silently excluded some dev deps for Yarn but not pnpm (3,170 vs 4,044). Fixed with SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true.
- [ ] T3: Grype reports GHSA IDs, Trivy reports CVE IDs; normalization needed. After it: 565/568 and 11/11 agreement.
- [ ] T4: Severity depends on source: semver@2.3.2 CVE-2015-8855 is HIGH in Grype, MEDIUM in Trivy.
- [ ] T5: Database coverage gaps: deepmerge (Grype only), toml (Trivy only). Trivy also lists legacy NSWG duplicates.

## Deep-dive candidates (Phase 5)
- [ ] minimatch@0.3.0: 5 HIGH findings on a very old version. Likely "scanner High, real risk Low."
- [ ] The 1 HIGH finding in v6.74.0
- [ ] The 1 not-fixed finding in v6.74.0
- [ ] Pick from the 27 criticals in v5.105.0

## Open checks
- [ ] Node.js 22.23.4 runtime vulnerabilities (S5)
- [ ] Decide whether to file the Syft bug report (T1)
