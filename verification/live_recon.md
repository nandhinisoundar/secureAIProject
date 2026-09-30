# Live Recon — AskNarelle / ChattyBot (non-intrusive pass)

**Target:** `https://asknarelle-4-sc1003.azurewebsites.net`
**Date (UTC):** 2026-09-30 ~10:15
**Scope:** Authorized, non-intrusive, unauthenticated observation only (see rules at bottom).
**Result:** **BLOCKED. No request reached the target.** The egress network policy of the
environment running this pass denied the connection. As the rules require, testing stopped
at that point and no one tried to get around the block.

---

## 1. What was attempted

| # | Request | Result |
|---|---------|--------|
| 1 | `curl -I https://asknarelle-4-sc1003.azurewebsites.net/` (HEAD) | Egress proxy returned `403 Forbidden` to `CONNECT`, so no tunnel was opened |
| 2 | `curl -v https://asknarelle-4-sc1003.azurewebsites.net/robots.txt` (GET) | Same `403` at `CONNECT`. This request confirmed the proxy's reason text. |

Raw evidence (request 2, trimmed):

```
* Establish HTTP proxy tunnel to asknarelle-4-sc1003.azurewebsites.net:443
> CONNECT asknarelle-4-sc1003.azurewebsites.net:443 HTTP/1.1
< HTTP/1.1 403 Forbidden
< Content-Type: text/plain; charset=utf-8
< X-Content-Type-Options: nosniff
< Content-Length: 95
< Connection: close
* CONNECT tunnel failed, response 403
```

**Important:** these response headers came from the **local egress proxy**
(`127.0.0.1:46273`), **not from the target**. For example, the `X-Content-Type-Options: nosniff`
above is the proxy's own header. It is **not** evidence about the app, and it must not be
counted toward the security-header check.

No other checks were run: no `/_stcore/health`, `/healthz`, `/static`, 404 probes or TLS
inspection.

## 2. TLS caveat (applies even to a future run from this kind of environment)

This sandbox sends all outbound HTTPS through a **TLS-intercepting proxy** with its own
CA bundle (`/root/.ccr/ca-bundle.crt`, status `bundleCoversEveryHost: true`). If the host had
been allowed, `openssl s_client` or `curl -v` from this environment would have shown the
**proxy's re-signed certificate**, not the target's real one. It would also have shown the
TLS versions negotiated with the proxy, not with Azure. So TLS findings from this environment
could not be counted as evidence even if the host were reachable. Run the TLS checks from a
direct, non-intercepted network.

## 3. Status of each code-review finding

| Goal | Code-review claim | Live status | Basis |
|------|-------------------|-------------|-------|
| 1. Login authority | MSAL `authority='https://login.microsoftonline.com/common'` (any Microsoft tenant) | **Cannot determine (live)** | *Observed in code only*: `Home.py` line 112. The "Verify Identity with NTU Email" text is an instruction to the user, not a tenant restriction. *Inferred*: with `/common` plus device flow, any Entra ID tenant (and possibly personal MSA accounts, depending on the app registration's `signInAudience`) can sign in unless the code checks `tid`/UPN domain after login. Confirming the effective audience needs the app registration's settings or a sign-in, and a sign-in is out of scope. Also, device-flow authentication runs server-side in Python, so an unauthenticated browser visitor would **not** see client-side calls to `login.microsoftonline.com`. |
| 2. Security headers | (not yet observed) | **Cannot determine** | No response from the target was received. |
| 3. TLS / certificate | (not yet observed) | **Cannot determine** | Blocked. Even if reachable, the intercepting proxy would mask the real certificate (§2). |
| 4. Error handling / info disclosure | (not yet observed) | **Cannot determine** | Blocked. *Inferred from code*: `Dockerfile` runs `streamlit run` with no `--client.showErrorDetails false` or `--server.enableXsrfProtection` hardening flags and uses base image `python:3.8` (EOL Oct 2024). Streamlit's default shows exception tracebacks in the UI. Confirming this live needs an error to be triggered, which may need interaction. |
| 5. robots.txt / exposed endpoints | (not yet observed) | **Cannot determine** | Blocked. |

**Refuted:** none. **Corroborated live:** none.

## 4. Items requiring authenticated testing (NOT done)

- Whether a non-NTU Microsoft account (another tenant or a personal MSA) can finish device-flow login and reach the chatbot, i.e. whether `/common` is enforced by any post-login `tid`/domain check.
- Whether the device-flow code shown in the UI can be phished or relayed (device-code phishing risk), and token/session lifetime.
- Chat-input handling: prompt injection, system-prompt leakage, output encoding / HTML rendering in Streamlit markdown.
- Per-user rate limiting and LLM cost-abuse controls.
- Access control on any logging or storage the chat writes to (e.g. conversation logs).
- Error/traceback disclosure reachable only after login.

## 5. How to complete this pass

Run the same short, spaced list of read-only checks from a network that reaches the host
**directly, without TLS interception** (e.g. the owner's workstation):

```bash
H=https://asknarelle-4-sc1003.azurewebsites.net
curl -sSI $H/                         # headers: HSTS, CSP, XFO, XCTO, Referrer-Policy, Cache-Control, Server
sleep 5; curl -sS $H/robots.txt -o - -w '\n%{http_code}\n'
sleep 5; curl -sS $H/_stcore/health -w '\n%{http_code}\n'
sleep 5; curl -sSI $H/nonexistent
sleep 5; curl -sSI $H/admin
echo | openssl s_client -connect asknarelle-4-sc1003.azurewebsites.net:443 \
  -servername asknarelle-4-sc1003.azurewebsites.net 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates
for v in tls1 tls1_1 tls1_2 tls1_3; do echo -n "$v: "; echo | openssl s_client -$v \
  -connect asknarelle-4-sc1003.azurewebsites.net:443 2>&1 | grep -q 'Cipher is (NONE)\|alert' && echo no || echo yes; done
```

Expected-if-genuine: issuer should be a Microsoft Azure TLS CA with subject `*.azurewebsites.net`.
Any other issuer means the cert was intercepted and cannot be used as evidence.

## Rules followed

Only 2 requests were attempted, and neither reached the target. No login, device-flow
completion, chat submission, fuzzing, brute force or load. The proxy denial was not
circumvented.
