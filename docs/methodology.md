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
- NSWG check: Trivy-only bl@0.8.2 (NSWG-ECO-391) and minimatch@0.3.0 (NSWG-ECO-118) are legacy Node Security WG records; both tools already report the same CVEs on those package versions, so these are duplicates, not extra vulnerabilities. Net scanner agreement is effectively complete.
