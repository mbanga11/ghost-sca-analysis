# Deep dive: express-brute@1.0.1 (Ghost v6.74.0, also in v5.105.0)

**Scanner view:** GHSA-984p-xq9m-4rjw, MEDIUM (CVSS 5.6, AC:H). Every version affected; no fixed version exists. No CVE, so no EPSS; not on KEV.
**Rubric result:** P2 (MEDIUM in a direct server dependency).
**Final priority:** P2 (confirmed by deep dive).

## 1. What is it?
express-brute is brute-force protection middleware. Per the advisory, concurrent requests can race and be counted incorrectly, so an attacker who sends many requests at the same moment can get more attempts than the configured limit before being locked out.

## 2. Where is it in Ghost?
All usage is in ghost/core/server/web/shared/middleware/api/spam-prevention.js: 18 limiters configured from the "spam" section of ghost/core/shared/config/defaults.json. Security-sensitive ones:
| Limiter | Protects | Default |
| --- | --- | --- |
| user_login | staff/admin login | 4 free retries, then lockout from 10 min growing to 7 days |
| user_reset, global_reset | password reset | 4 retries, then 1 hour |
| user_verification, send_verification_code, otc_verification | verification / one-time codes | 4 retries, then 1 hour |
| member_login, otc_verification_enumeration | member sign-in, account probing | 8 retries, then 10 min up to 12 hours |
The rest (global_block, private_block, content_api_key, checkout, webmentions, upgrade, invites, email preview, support) are abuse/cost controls.
Counters are stored in the database via @tryghost/brute-knex (table "brute").

## 3. Can it be reached?
Yes. The limiters sit directly in front of internet-facing login, reset and verification endpoints. The race is in express-brute's own read-then-write logic, so a database-backed store does not prevent it.

## 4. How likely is exploitation?
Moderate in principle, low in impact. AC:H: it requires tightly timed concurrent requests, and the counter still catches up, so the attacker gains some extra guesses per lockout window rather than unlimited attempts.

## 5. Rating and why
P2. The vulnerable behavior is reachable on authentication endpoints and cannot be patched, but impact is bounded by tight limits and long lockouts, and staff accounts have a second factor: staff device verification is enabled by default in production (defaults.json "staffDeviceVerification": true; disabled only in development/testing configs), and guessing that code is separately rate-limited.

## 6. Fix
No patched version exists, so remediation means replacing express-brute with a maintained limiter that uses atomic counters (for example an atomic increment in the database or Redis). Short term: keep staff device verification enabled, enforce strong passwords, and consider an upstream rate limit (reverse proxy / WAF) on login and verification routes.

## 7. Limitations
- Did not verify whether @tryghost/brute-knex implements atomic increments; conclusion rests on express-brute's documented read-then-write behavior.
- Self-hosters can disable staffDeviceVerification in config, which would remove the second-factor mitigation.
- No dynamic testing of the race; conclusions come from code and config review.
