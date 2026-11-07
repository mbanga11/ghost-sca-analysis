# Findings Log

Running list of report-worthy findings. Details and evidence are in methodology.md.

## Security findings (Ghost)
- [ ] S1: Old v5.105.0 has 568 vulnerability matches (424 unique; 27 critical, 268 high). Latest v6.74.0 has 11 (8 unique; 0 critical, 1 high). Retrospective caveat: old release scanned with a 2026 database.
- [ ] S2: Ghost migrated Yarn to pnpm between releases; comparisons account for lockfile format.
- [ ] S3: CI/CD supply chain: GitHub Actions grew from 26 to 78. In v5.105.0 only 1 of 26 pinned to a commit SHA, several pinned to branch `main`. actions/download-artifact@v4 has a known advisory (GHSA-cxww-7g56-2vh6). actions/upload-artifact v3 (deprecated) in use.
- [ ] S4: Committed private key (ghost/identity-token-service/private.pem) in v5.105.0, removed by v6.74.0. Low risk, still in git history.
- [ ] S5: Node.js runtime pinned at 22.23.4 in v6.74.0. DONE: see Node.js runtime check below (fully patched; 22.x EOL 2027-04-30).

## Tooling / methodology findings
- [ ] T1: Syft 1.56.0 drops the entire pnpm lockfile when it hits a `node@runtime` entry (`type: variations`). Found by bisection. Candidate upstream bug report.
- [ ] T2: Syft's default silently excluded some dev deps for Yarn but not pnpm (3,170 vs 4,044). Fixed with SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true.
- [ ] T3: Grype reports GHSA IDs, Trivy reports CVE IDs; normalization needed. After it: 565/568 and 11/11 agreement.
- [ ] T4: Severity depends on source: semver@2.3.2 CVE-2015-8855 is HIGH in Grype, MEDIUM in Trivy.
- [ ] T5: Database coverage gaps: deepmerge (Grype only), toml (Trivy only). Trivy also lists legacy NSWG duplicates.

## Deep-dive candidates (Phase 5)
- [ ] minimatch@0.3.0: 5 HIGH findings on a very old version. Likely "scanner High, real risk Low."
- [ ] vite@4.5.3 (old): KEV + EPSS 0.75, tagged frontend-runtime but likely build-only (S9, S12)
- [ ] jsonwebtoken@8.5.1 (latest): direct server dependency, 3 CVEs since 2022 (S6)
- [ ] express-brute@1.0.1 (latest): direct server dependency, security control, no fix (S7)
- [ ] Pick from the 27 criticals in v5.105.0

## Open checks
- [x] Node.js 22.23.4 runtime vulnerabilities (S5): done
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

## Node.js runtime check (2026-11-05)
- [ ] S5 result: Ghost v6.74.0 pins Node.js 22.23.4 via pnpm runtime. 22.23.4 (2026-10-21) is itself a security release (Oct 2026 round, 10 CVEs across 22/24/26) and is the newest 22.x as of 2026-11-05, so the pinned runtime is fully patched. 22.x is Maintenance LTS until 2027-04-30 (EOL in ~6 months); recommend planning a move to Node 24. Sources: nodejs.org/en/blog/release/v22.23.4, nodejs.org/en/blog/release, checked 2026-11-05.

## Added after Phase 5.1 prioritization
- [ ] S13: Funnel: 582 findings -> 48 P0/P1 overall -> 1 P1 in the current release (jsonwebtoken CVE-2022-23539). Core headline.
- [ ] S14: Old-release P1s cluster in security-relevant server packages: multer (file uploads, 10 CVEs), handlebars (theme engine, 4 critical), nodemailer, body-parser, form-data. Retrospective; check which persist in latest (Phase 7).
- [ ] S15: @faker-js/faker tagged as a direct server dependency in old release; faker is a test-data library. Likely mis-declared in a manifest. Override candidate.

## Deep dive results
- [x] vite@4.5.3 (old): DONE. Rubric P0 -> override P3. Build/dev tool only; KEV-family CVEs need the dev server exposed via --host/server.host, which Ghost does not configure (0.0.0.0 set only on preview servers in 5 apps). Patches existed in 4.x (4.5.10-4.5.14); resolved in v6.74.0 (vite 8.1.6). Best example of "KEV does not mean urgent for this project." Details: analysis/deep-dives/vite.md
- [ ] TODO before publishing: confirm CVE-2025-31125 and CVE-2025-31486 advisories state the same dev-server exposure condition.
- [x] jsonwebtoken@8.5.1 (latest): DONE. Rubric P1/P2 -> override P3. All 4 verify paths use explicit algorithms (HS256/RS512), keys never falsy, RSA >= 2048 enforced. express-jwt bundles patched jsonwebtoken 9.0.3, so Ghost ships 8.5.1 and 9.0.3 side by side. Recommend upgrading the exact pin to 9.x. Details: analysis/deep-dives/jsonwebtoken.md
