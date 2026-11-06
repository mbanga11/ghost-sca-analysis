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

## Added after Phase 4.1 merge
- [ ] S6: jsonwebtoken@8.5.1 still in v6.74.0 with 3 CVEs from 2022 (CVE-2022-23539/23540/23541), fix 9.0.0. Persistent ~4 years. Exploitability depends on how Ghost calls jwt.verify. DEEP-DIVE CANDIDATE.
- [ ] S7: express-brute@1.0.1 (brute-force protection) in both releases, GHSA-984p-xq9m-4rjw, no fix available. Flaw in a security control; remediation = replace the package. DEEP-DIVE CANDIDATE.
- [ ] S8: Abandoned dependencies: 17 old-release findings have no fix (request, lodash.pick, lodash.template, html-minifier, dicer, ip, extract-zip, etc.). Only remediation is replacement.
- Merge results: old 571 findings (565 both scanners, 6 single-scanner), latest 11 (all both). Matches Phase 3 manual analysis.

## Added after Phase 4.2 enrichment
- [ ] S9: vite@4.5.3 (old) CVE-2025-31125 is on CISA KEV (added 2026-01-22) with EPSS 0.749, highest of all findings, yet scanner severity is only MEDIUM. Related Vite CVE-2025-30208 (EPSS 0.748) and CVE-2025-31486 (0.405). Vite is dev tooling; risk depends on whether the dev server is network-exposed. TOP DEEP-DIVE CANDIDATE.
- [ ] S10: Severity vs exploitability mismatch: none of the 27 CRITICAL old-release findings appear among the top-10 EPSS scores. Severity-only triage would bury the one KEV vulnerability.
- [ ] S11: Latest v6.74.0: 0 KEV, all EPSS < 1% (max jsonwebtoken 0.8%). 2 findings (express-brute, @tiptap/core) have no EPSS because they only have GHSA IDs; no data is not the same as no risk.
- Old release: 6 findings with EPSS >= 10% (3x vite, decode-uri-component, lodash.template, moment).

## Added after Phase 4.3 component tagging
- [ ] S6/S7 strengthened: jsonwebtoken@8.5.1 and express-brute@1.0.1 are DIRECT dependencies of the server workspace (ghost) in v6.74.0, not transitive or dev-only.
- [ ] S12: Automated tagging limits: vite@4.5.3 is tagged frontend-runtime because Ghost's admin apps list it under dependencies, but Vite is a build tool. Manifests do not equal runtime. Verify in the vite deep dive.
- Old release: 341 of 571 findings are in server-runtime dependencies (installed with the server; reachability not yet verified).
