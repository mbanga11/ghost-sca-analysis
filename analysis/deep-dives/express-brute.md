# Deep dive: express-brute@1.0.1 (Ghost v6.74.0, also in v5.105.0)

**Scanner view:** GHSA-984p-xq9m-4rjw, MEDIUM (CVSS 5.6, AC:H). Every version is affected and no fixed version exists. There's no CVE, so there's no EPSS score, and it's not on KEV.
**Rubric result:** P2 (MEDIUM in a direct server dependency).
**Final priority:** P2 (confirmed by this deep dive).

## 1. What is it?
express-brute is middleware that limits how many times someone can try things like logging in. According to the advisory, requests that arrive at the same moment can race each other and get miscounted. So an attacker who fires a burst of simultaneous requests can sneak in more attempts than the limit allows before getting locked out.

## 2. Where is it in Ghost?
Everything lives in ghost/core/server/web/shared/middleware/api/spam-prevention.js, which sets up 18 limiters using the "spam" section of ghost/core/shared/config/defaults.json. The security-sensitive ones:
| Limiter | Protects | Default |
| --- | --- | --- |
| user_login | staff/admin login | 4 free tries, then a lockout that starts at 10 min and grows to 7 days |
| user_reset, global_reset | password reset | 4 tries, then 1 hour |
| user_verification, send_verification_code, otc_verification | verification and one-time codes | 4 tries, then 1 hour |
| member_login, otc_verification_enumeration | member sign-in, account probing | 8 tries, then 10 min up to 12 hours |
The rest (global_block, private_block, content_api_key, checkout, webmentions, upgrade, invites, email preview, support) are for stopping spam and abuse.
Attempt counts are stored in Ghost's database through @tryghost/brute-knex (table "brute").

## 3. Can it be reached?
Yes. These limiters sit right in front of login, password reset, and verification endpoints that anyone on the internet can hit. The race is inside express-brute's own logic, which reads the count and then writes it in two separate steps. Storing the count in a database doesn't make those steps happen together, so it doesn't prevent the race.

## 4. How likely is exploitation?
Possible in principle, but with limited payoff. AC:H means it takes precisely timed simultaneous requests, and the counter still catches up afterward. The attacker gets some extra guesses per lockout window, not unlimited ones.

## 5. Rating and why
P2. The vulnerable behavior is reachable on login endpoints and there's no patch. But the damage is limited by tight limits and long lockouts, and staff accounts have a second layer: staff device verification is on by default in production (defaults.json "staffDeviceVerification": true; it's only turned off in development and testing configs), and guessing that code has its own rate limit.

## 6. Fix
Since there's no patched version, the real fix is replacing express-brute with a maintained rate limiter that uses atomic counters (for example, an atomic increment in the database or Redis). In the meantime: keep staff device verification on, enforce strong passwords, and consider adding rate limiting at the reverse proxy or WAF for login and verification routes.

## 7. Limitations
- I didn't check whether @tryghost/brute-knex does atomic increments; this conclusion is based on express-brute's documented read-then-write behavior.
- Self-hosters can turn off staffDeviceVerification in their config, which would remove the second-factor protection.
- I didn't test the race live; everything here comes from reviewing code and config.

## My take
This one mattered to me because it's the opposite of the other two deep dives. With vite and jsonwebtoken, the evidence pushed the priority down. Here the evidence held the rating where it was: the flaw is real, it's on the login page, and it can never be patched, only replaced. I think that balance is important. A good triage process should be able to say "this one is fine" and "this one is real" with the same level of proof.
