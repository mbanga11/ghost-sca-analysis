# Deep dive: vite@4.5.3 (Ghost v5.105.0)

**Scanner view:** 20 findings. CVE-2025-31125 is on CISA KEV with EPSS 0.749 (highest in the whole dataset); CVE-2025-30208 EPSS 0.748; CVE-2025-31486 EPSS 0.405. Scanner severity only MEDIUM.
**Rubric result:** P0 (KEV + tagged frontend-runtime).
**Final priority:** P3 (override).

## 1. What is it?
Vite is a frontend build tool and local development server. The KEV-family CVEs (30208, 31125, 31486) are bypasses of the dev server's server.fs.deny / @fs file-access restriction, letting a request read arbitrary files from the machine running the dev server.

## 2. Where is it in Ghost?
vite 4.5.3 is used by 9 apps under apps/. 8 list it in devDependencies; only apps/admin-x-framework lists it in dependencies (the reason automated tagging said frontend-runtime). Every script that invokes Vite is build, watch, test (vitest), dev server, or preview. None run in production.

## 3. Can it be reached?
The advisory for CVE-2025-30208 states only apps that expose the Vite dev server to the network with --host or server.host are affected. Ghost's dev scripts run `vite` / `vite --port 6173` with no --host, and no vite.config sets server.host, so the dev server listens on localhost only. Five apps (announcement-bar, comments-ui, portal, signup-form, sodo-search) set host '0.0.0.0', but only inside the preview block, and comments-ui runs `preview --host`. The preview server serves built output, not the dev @fs feature.
Reachability: not reachable in Ghost's default configuration. All three advisories (CVE-2025-30208, CVE-2025-31125, CVE-2025-31486) state only apps exposing the dev server via --host or server.host are affected. CVE-2025-31486's .svg bypass also requires Vite 6.0+, so only its relative-path bypass applied to Ghost's 4.5.3.

## 4. How likely is exploitation?
High in general (KEV, EPSS ~0.75) because many projects do expose dev servers. For Ghost specifically, an attacker would need a developer to manually run the dev server with --host on a reachable network.

## 5. Rating and why
P3. Production Ghost servers and readers are not exposed. Residual risk is to developer machines, only under non-default usage. This is the clearest example in the dataset of KEV not meaning urgent for a specific project.

## 6. Fix
Patches existed within 4.x (4.5.10 to 4.5.14), so a minor upgrade would have closed the KEV-family CVEs. Resolved in v6.74.0, which uses vite 8.1.6 with zero findings. Hygiene recommendation: avoid binding preview servers to 0.0.0.0 by default.

## 7. Limitations
- Exposure condition verified against the advisories for all three KEV-family CVEs (30208, 31125, 31486).
- Developers can still run vite --host manually; that path is not controlled by the repo.
- The other 17 Vite CVEs were not individually reviewed; all are overridden on the same build-only basis.
- Automated tagging called this frontend-runtime because of one manifest line; this deep dive corrects it.
