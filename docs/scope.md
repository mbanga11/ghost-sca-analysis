# Scope

## Target releases
| Release | Tag | Commit | Date | Lockfile | Package manager |
| --- | --- | --- | --- | --- | --- |
| Old | v5.105.0 | bb9bd0e233069ab71a665ac90c9af16987236cd8 | 2024-12-13 | yarn.lock | Yarn (packageManager not set) |
| Latest | v6.74.0 | 13dd2ddeb8447cb14758afec40c0829a5bd225a7 | 2026-11-03 | pnpm-lock.yaml | pnpm 12.16.1 |

Note: Ghost moved from Yarn to pnpm between these releases. Differences in findings may come from lockfile format, not only dependency changes.

## In scope
- Third-party dependencies declared in each release's lockfile
- Known vulnerabilities in direct and transitive dependencies
- Which part of Ghost uses each dependency (server, admin UI, dev tooling)
- Comparison between the two releases
- Remediation recommendations

## Out of scope
- Scanning or testing any live Ghost site or Ghost(Pro) infrastructure
- Auditing Ghost's own first-party code
- Claims that a scanner finding proves exploitability

This is an independent analysis of public source code, not an official Ghost audit.
