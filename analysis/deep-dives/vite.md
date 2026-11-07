# Deep dive: vite@4.5.3 (Ghost v5.105.0)

**Scanner view:** 20 findings. CVE-2025-31125 is on CISA's KEV list with an EPSS of 0.749, the highest in the whole dataset. CVE-2025-30208 has EPSS 0.748 and CVE-2025-31486 has 0.405. The scanners only rated them MEDIUM.
**Rubric result:** P0 (on KEV and tagged as frontend runtime).
**Final priority:** P3 (override).

## 1. What is it?
Vite is a tool that builds Ghost's frontend apps and runs a local development server while developers work. The three KEV-family CVEs are ways to get around the dev server's file restrictions (server.fs.deny and the @fs feature), which lets someone read any file on the machine running that server.

## 2. Where is it in Ghost?
Nine apps under apps/ use vite 4.5.3. Eight of them list it in devDependencies. Only apps/admin-x-framework lists it in dependencies, and that single line is why my automated tagging called it "frontend runtime." Looking at every npm script that runs Vite, each one is a build, watch, test (vitest), dev server, or preview command. None of them run in production.

## 3. Can it be reached?
All three advisories (CVE-2025-30208, CVE-2025-31125, CVE-2025-31486) say the same thing: you're only affected if the dev server is exposed to the network with --host or server.host. Ghost's dev scripts run `vite` and `vite --port 6173` with no --host, and none of the vite.config files set server.host, so the dev server only listens on localhost.
Five apps (announcement-bar, comments-ui, portal, signup-form, sodo-search) do set host to '0.0.0.0', but only inside the preview block, and comments-ui runs `preview --host`. The preview server serves already-built files. It doesn't include the dev server's @fs feature that these CVEs abuse.
One more detail: CVE-2025-31486's .svg bypass only works on Vite 6.0+, so on Ghost's 4.5.3 only its relative-path bypass would have applied.
Reachability: not reachable in Ghost's default setup.

## 4. How likely is exploitation?
In general, very likely. It's on KEV and EPSS is around 0.75, because lots of projects do expose their dev servers. For Ghost specifically, an attacker would need a developer to manually start the dev server with --host on a network the attacker can reach.

## 5. Rating and why
P3. Ghost's production servers and the people reading Ghost sites are never exposed. The only leftover risk is to a developer's own machine, and only if they go out of their way to expose the dev server.

## 6. Fix
Patches were available inside the 4.x line (4.5.10 through 4.5.14), so a small upgrade would have closed all three KEV-family CVEs. It's resolved in v6.74.0, which uses vite 8.1.6 and has zero Vite findings. Small hygiene suggestion: don't bind preview servers to 0.0.0.0 by default.

## 7. Limitations
- Exposure condition checked against the advisories for all three KEV-family CVEs (30208, 31125, 31486).
- A developer can still run vite --host by hand; nothing in the repo controls that.
- I didn't review the other 17 Vite CVEs one by one; they're overridden on the same build-only basis.
- Automated tagging called this frontend runtime because of one manifest line. This deep dive corrects that.

## My take
This was the finding that surprised me most. It had the highest exploitation score in the entire dataset and was on CISA's actively exploited list, yet it never touched production. It's the clearest proof in this project that KEV and EPSS tell you what attackers are doing in general, not what matters for your specific app. You still have to check how the code is actually used.
