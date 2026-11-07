# Deep dive: jsonwebtoken@8.5.1 (Ghost v6.74.0)

**Scanner view:** 3 findings, all from 2022: CVE-2022-23539 (HIGH), CVE-2022-23540 (MEDIUM), CVE-2022-23541 (MEDIUM). Fixed in 9.0.0. EPSS under 1% for all three. Not on KEV.
**Rubric result:** P1 (HIGH in a direct server dependency) / P2.
**Final priority:** P3 (override), upgrade recommended.

## 1. What is it?
jsonwebtoken signs and verifies JWTs. The three CVEs, in short:
- CVE-2022-23539: older versions accept insecure/legacy key types (and small RSA keys).
- CVE-2022-23540: verify() without an algorithms list and with a falsy key can fall back to the "none" algorithm (no signature check).
- CVE-2022-23541: key confusion when keys are looked up dynamically and algorithms are not restricted, letting an RSA public key be used as an HMAC secret.

## 2. Where is it in Ghost?
ghost/package.json pins exactly "jsonwebtoken": "8.5.1" (a deliberate pin, no semver range). Server files importing it: auth/api-key/admin.js, members token-service.js, scheduling/utils.ts, api/endpoints/featurebase.js, identity-token-service.ts, tinybird-service.js. tools/gx also uses it (dev tool).
Only three of those call jwt.verify (admin.js, token-service.js, tinybird-service.js); the rest only sign tokens, which these CVEs do not target. A fourth verify path is the members middleware (auth/members/index.js) via express-jwt@8.5.1, which bundles its own jsonwebtoken 9.0.3 (patched). Ghost therefore ships 8.5.1 and 9.0.3 side by side.

## 3. Can it be reached?
| Verify path | Algorithms | Key | Other checks |
| --- | --- | --- | --- |
| Admin API (admin.js) | HS256 only | per-integration secret from DB, always a Buffer | kid required and must exist in DB, key type must be admin, 5 minute maxAge, audience check |
| Members token service | RS512 only | RSA public key selected by kid | issuer check, scope must be members:identity |
| Members middleware (express-jwt) | RS512 only | function lookup by kid | audience and issuer checks; uses jsonwebtoken 9.0.3 |
| Tinybird | HS256 only | config token | if unset, verify errors out |

- 23540: not reachable. Every path passes an explicit algorithm, and keys are never falsy.
- 23541: not reachable. Dynamic key lookup exists (members), but algorithms are restricted to RS512, so an HMAC-signed forged token is rejected.
- 23539: not applicable. Admin/Tinybird use HMAC secrets; members keys are RSA generated at 2048 bits (MIN_MODULUS_LENGTH = 2048) and smaller keys trigger rotation.
Reachability: vulnerable code is installed and called, but the exploit conditions are not met in v6.74.0.

## 4. How likely is exploitation?
Low. EPSS under 1%, not on KEV, and Ghost's call sites block the documented attack conditions.

## 5. Rating and why
P3. Code-level defenses (explicit algorithms on every verify call, non-falsy keys, enforced key size) neutralize all three CVEs today. The residual risk is fragility: safety depends on every future verify call remembering an algorithms list, in an authentication path, on a library pinned to a 2022 version.

## 6. Fix
Upgrade ghost/package.json from 8.5.1 to 9.x. Low risk: jsonwebtoken 9.0.3 already runs inside Ghost via express-jwt, and Ghost's call sites already follow v9's stricter defaults. This also removes the duplicate version.
Hardening note: getVerificationKey falls back to the active key when the kid is unknown. Not a vulnerability (attacker still needs the private key), but rejecting unknown kids would be stricter.

## 7. Limitations
- Reviewed v6.74.0 code only; v5.105.0 call sites were not reviewed, so old-release rows keep their rubric priority.
- Search covered direct imports of jsonwebtoken in ghost/core/server (tests excluded). Other dependencies that use jsonwebtoken internally were not exhaustively reviewed, beyond express-jwt.
- No dynamic testing; conclusions come from code review.
