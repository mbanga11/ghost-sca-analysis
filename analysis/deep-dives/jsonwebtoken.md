# Deep dive: jsonwebtoken@8.5.1 (Ghost v6.74.0)

**Scanner view:** 3 findings, all from 2022: CVE-2022-23539 (HIGH), CVE-2022-23540 (MEDIUM), CVE-2022-23541 (MEDIUM). Fixed in 9.0.0. EPSS is under 1% for all three, and none are on KEV.
**Rubric result:** P1 (HIGH in a direct server dependency) and P2.
**Final priority:** P3 (override), but upgrading is still recommended.

## 1. What is it?
jsonwebtoken creates and checks JWTs, the signed tokens Ghost uses to prove a request comes from a real user or integration. In plain terms, the three CVEs are:
- CVE-2022-23539: older versions accept weak or legacy key types (including small RSA keys).
- CVE-2022-23540: if verify() is called without an algorithms list and the key is empty, it can fall back to "none," meaning no signature check at all.
- CVE-2022-23541: "key confusion." If keys are looked up dynamically and algorithms aren't restricted, an attacker can trick the server into treating an RSA public key as an HMAC secret.

## 2. Where is it in Ghost?
ghost/package.json pins exactly "jsonwebtoken": "8.5.1", with no version range, so it will never update on its own. Server files that import it: auth/api-key/admin.js, the members token-service.js, scheduling/utils.ts, api/endpoints/featurebase.js, identity-token-service.ts, and tinybird-service.js. tools/gx also uses it, but that's a dev tool.
Only three of those files actually verify tokens (admin.js, token-service.js, tinybird-service.js). The rest only create tokens, which these CVEs don't target. There's a fourth verify path in the members middleware (auth/members/index.js), which uses express-jwt@8.5.1. That library bundles its own jsonwebtoken 9.0.3, which is already patched. So Ghost actually ships two versions side by side: 8.5.1 and 9.0.3.

## 3. Can it be reached?
| Verify path | Algorithms | Key | Other checks |
| --- | --- | --- | --- |
| Admin API (admin.js) | HS256 only | per-integration secret from the database, always a Buffer | kid is required and must exist in the database, key type must be admin, 5 minute maxAge, audience check |
| Members token service | RS512 only | RSA public key chosen by kid | issuer check, scope must be members:identity |
| Members middleware (express-jwt) | RS512 only | function lookup by kid | audience and issuer checks; runs jsonwebtoken 9.0.3 |
| Tinybird | HS256 only | config token | if unset, verify just errors out |

- 23540 is not reachable: every path passes an explicit algorithm, and the key is never empty.
- 23541 is not reachable: the members path does look keys up dynamically, but only RS512 is allowed, so a forged HMAC token gets rejected.
- 23539 doesn't apply: Admin and Tinybird use HMAC secrets, and members keys are RSA generated at 2048 bits (MIN_MODULUS_LENGTH = 2048). Smaller keys get rotated automatically.
Reachability: the vulnerable code is installed and called, but none of the conditions needed to exploit it are met in v6.74.0.

## 4. How likely is exploitation?
Low. EPSS is under 1%, it's not on KEV, and Ghost's code blocks each documented attack.

## 5. Rating and why
P3. Ghost's own code (an explicit algorithm on every verify call, keys that are never empty, enforced key size) shuts down all three CVEs today. The real risk is fragility: the safety depends on every future verify call remembering to set an algorithms list, in an authentication path, using a library pinned to a 2022 version.

## 6. Fix
Bump ghost/package.json from 8.5.1 to 9.x. This should be low risk: jsonwebtoken 9.0.3 is already running inside Ghost through express-jwt, and Ghost's call sites already follow v9's stricter defaults. It would also remove the duplicate version.
Hardening note: getVerificationKey falls back to the active key when it doesn't recognize the kid. That isn't a vulnerability, since an attacker would still need the private key, but rejecting unknown kids would be stricter.

## 7. Limitations
- I only reviewed v6.74.0. I didn't review v5.105.0's call sites, so old-release rows keep their rubric priority.
- My search covered direct imports of jsonwebtoken in ghost/core/server (excluding tests). Apart from express-jwt, I didn't dig through other dependencies that might use jsonwebtoken internally.
- No live testing; everything here comes from reading the code.

## My take
This is the kind of finding that a scanner can't judge on its own. The library is old and genuinely vulnerable, but Ghost's developers wrote their verify calls defensively enough that the bugs can't be triggered. I'd still push for the upgrade, though. Relying on every developer to remember the right options forever is a weaker defense than just using the fixed version.
