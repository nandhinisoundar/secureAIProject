# Live Recon — independent verification note (blocked environment)

**Author of this note:** Claude (agent), running in an isolated cloud container.
**Date (UTC):** 2026-09-30 ~11:10–11:20
**Companion to:** `verification/live_recon.md`

## Why this file exists

I was asked to run a non-intrusive live recon of
`https://asknarelle-4-sc1003.azurewebsites.net` and write/overwrite
`verification/live_recon.md`. When I went to publish, the branch already
contained a commit (`23c8702`, authored `Nandhini <nandhinisoundar@gmail.com>`,
2026-09-30 19:17 +08) whose `live_recon.md` records the host as **REACHABLE**
with detailed live evidence (HTTP 200, `TornadoServer/6.4.2`, TLS 1.3 Azure
leaf with `Verification: OK`, DNS `A 20.212.64.12`, `/healthz` `Deprecation: True`,
etc.).

**I could not reproduce or verify any of that live evidence from my
environment, and I am not endorsing it as my own observation.** Rather than
overwrite what may be a legitimate recon run from a permitted workstation, I
left `live_recon.md` untouched and recorded my own environment's result here so
the two can be reconciled. Distinguishing observed from unverifiable is the
whole point of a verification pass.

## What I actually observed from this environment

This session's only network egress is a policy-enforcing proxy that **denies
the target host outright**. Every `CONNECT` to
`asknarelle-4-sc1003.azurewebsites.net:443` is answered `403` before any tunnel
opens; no bytes reached Azure. This session has **no** alternate "workstation
with direct egress" — every route goes through the same blocked proxy.

```
$ curl -sS -I https://asknarelle-4-sc1003.azurewebsites.net/
curl: (56) CONNECT tunnel failed, response 403

proxy /__agentproxy/status  recentRelayFailures:
{ "ts":"2026-09-30T11:10:02.471Z",
  "kind":"connect_rejected",
  "detail":"gateway answered 403 to CONNECT (policy denial or upstream failure)",
  "host":"asknarelle-4-sc1003.azurewebsites.net:443" }
```

A second consequence matters for the TLS claim in `live_recon.md`: this
session's proxy **re-terminates TLS** (`bundleCoversEveryHost: true`). So even
if the host were reachable *from here*, any certificate I inspected would be the
proxy's interception cert, not the target's leaf. I therefore cannot
independently confirm the "TLS 1.3 Azure leaf, Verification: OK" line from this
environment. That is a limitation of my vantage point; it is **not** evidence
that the other pass is wrong.

## Bearing on each finding

| # | Finding | From this (blocked) environment |
|---|---------|--------------------------------|
| 1 | MSAL authority `login.microsoftonline.com/common` (multi-tenant, not NTU tenant) | **Independently CORROBORATED — from code**, `ChattyBot-main/Home.py:112` (`authority='https://login.microsoftonline.com/common'`) and device flow at line 136. This holds regardless of live reachability. |
| 2 | Security headers on `/` | **Cannot determine here** — host blocked. |
| 3 | TLS versions + real cert | **Cannot determine / cannot trust here** — host blocked, and proxy intercepts TLS. |
| 4 | Error/info disclosure on bogus paths | **Cannot determine here** — host blocked. |
| 5 | robots.txt / exposed endpoints | **Cannot determine here** — host blocked. |

## Recommendation

Treat the live headers/TLS/DNS/status lines in `live_recon.md` as trustworthy
**only** if they were produced on a network that (a) permits the host and (b)
does not intercept TLS — and ideally re-run them once more from such a host,
capturing raw `curl -D-` and `openssl s_client` output, before relying on them
in the pre-launch review. The **code-level** finding (MSAL `/common` + a
post-token `ntu.edu.sg` substring check rather than a tenant/`tid` allow-list)
stands on its own and is the higher-value item for the security review either
way.

## Rules I followed

Non-intrusive only: 2 spaced requests aimed at the target (both refused at the
proxy, never reaching the host) plus a local proxy-status read. No login,
device-flow, chat, fuzzing, or bypass. When the egress policy blocked the host,
I stopped and did not route around it.
