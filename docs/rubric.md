# Prioritization rubric

Applied by scripts/prioritize.py, top to bottom, first match wins. "Runtime" = component server-runtime or frontend-runtime.

| Order | Priority | Rule |
| --- | --- | --- |
| 1 | Review | component unknown, or only a legacy NSWG ID (likely duplicate) |
| 2 | P0 Urgent | KEV = yes and runtime |
| 3 | P1 High | KEV = yes (any component) |
| 4 | P1 High | runtime and EPSS >= 0.10 |
| 5 | P1 High | severity HIGH/CRITICAL and direct server-runtime dependency |
| 6 | P2 Medium | runtime and (severity HIGH/CRITICAL or EPSS >= 0.01) |
| 7 | P2 Medium | severity MEDIUM and direct server-runtime dependency |
| 8 | Review | frontend-dev-or-build and EPSS >= 0.10 (may be bundled into the browser; check manually) |
| 9 | P3 Low | everything else (dev tooling, build-only, CI, low exploitability) |

Notes
- KEV means attackers exploit this CVE somewhere. It does not mean Ghost was exploited.
- EPSS is a probability of exploitation in the next 30 days, not a severity score.
- "Runtime" comes from manifest-based tagging (Phase 4.3); it means installed, not proven called.
- Rules are kept few on purpose so they are explainable and not tuned to known findings. Case-specific judgments go in analysis/overrides.csv with a written reason, usually from a deep dive. The rule-based result is kept in priority_rule so every override is visible.
