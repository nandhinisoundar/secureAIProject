# Live Recon — AskNarelle / ChattyBot (non-intrusive pass)

**Target:** `https://asknarelle-4-sc1003.azurewebsites.net`  
**Date (UTC):** 2026-09-30 ~11:14–11:17  
**Observer host:** workstation with direct egress to Azure (no CONNECT-proxy block)  
**Scope:** Authorized, non-intrusive, unauthenticated observation only.  
**Result:** **REACHABLE.** This pass replaces the earlier write-ups that recorded an egress-policy block. Requests below hit the target, not a local intercepting proxy.

Legend used below:

- **Observed** — taken from this live traffic or from the checked-in application source.
- **Inferred** — interpretation, not directly proven by this pass.
- **Cannot determine** — would need a check that is out of scope (login, chat, more traffic, etc.).

---

## 1. What was tested (request inventory)

Spaced HTTPS GET/HEAD plus TLS inspection only. No login, no device-flow completion, no chat input, no fuzzing, no extra path guessing beyond the two named 404s.

| # | Time (UTC, from `Date` / local clock) | Request | Result |
|---|----------------------------------------|---------|--------|
| 1 | 11:14:55 | `HEAD /` | **200 OK**, `TornadoServer/6.4.2`, `Cache-Control: no-cache` |
| 2 | ~11:15 | `openssl s_client -showcerts` + system-trust verify | TLS 1.3, Microsoft Azure leaf, **Verification: OK** |
| 3 | ~11:15 | `GET /` (body capture) | **200**, 891-byte Streamlit HTML shell |
| 4 | 11:15:19 | `GET /robots.txt` | **404**, same Streamlit HTML shell |
| 5 | 11:15:24 | `GET /_stcore/health` | **200**, body `ok` |
| 6 | 11:15:29 | `GET /healthz` | **200**, body `ok`, `Deprecation: True` |
| 7 | 11:15:49 | `GET /nonexistent` | **404**, same Streamlit HTML shell (no traceback) |
| 8 | 11:15:54 | `GET /admin` | **404**, same Streamlit HTML shell (no traceback) |
| 9 | ~11:16 | `openssl s_client` TLS 1.0 / 1.1 / 1.2 / 1.3 probes | See §4 |
| 10 | 11:16:59 | `HEAD /` (`curl -vI`) | Same 200 headers; curl negotiated **TLSv1.3** |

DNS (observed):

```
asknarelle-4-sc1003.azurewebsites.net
  CNAME waws-prod-sg1-089.sip.azurewebsites.windows.net.
  CNAME waws-prod-sg1-089-34c2.southeastasia.cloudapp.azure.com.
  A     20.212.64.12
```

Not done (by design): loading the Streamlit JS/WebSocket app in a browser (that would fire many extra asset/WS requests); fetching `/static/js/...`; clicking “Agree and Proceed”; completing MSAL device flow; submitting chat.

---

## 2. Login authority (common / multi-tenant vs NTU tenant)

### Observed (code, target repo `ChattyBot-main/Home.py`)

```python
app = PublicClientApplication(
    client_id=APP_REGISTRATION_CLIENT_ID,
    authority='https://login.microsoftonline.com/common'
)
...
flow = app.initiate_device_flow(scopes=["User.Read"])
...
# after a token is obtained:
elif "ntu.edu.sg" in st.session_state.email[-10:] or st.session_state.email in allowed_users:
```

The MSAL authority is the **multi-tenant `/common` endpoint**, not an NTU tenant GUID (`https://login.microsoftonline.com/<tid>`). UI copy tells the user to “Verify Identity with NTU Email”; a post-token check looks for `ntu.edu.sg` in the UPN (or an allow-list in MongoDB).

### Observed (live, unauthenticated)

- `GET /` and `HEAD /` returned **200** with **no** `Location` redirect to `login.microsoftonline.com` (or any other IdP).
- Response body is the Streamlit SPA shell only (title `Streamlit`, empty `<div id="root">`). It does **not** contain `login.microsoftonline.com`, `/common`, a tenant ID, `msal`, or “NTU”.
- Therefore this pass **did not** observe any client-side call to Microsoft login. That matches the code: device-flow is started **server-side** only after the user accepts the consent checkbox — a step that was **not** taken.

### Cannot determine (live)

- Whether Azure AD app registration `signInAudience` is actually multi-tenant / MSA-capable.
- Whether a non-NTU account can obtain a token via device flow before the Python domain check runs.
- Whether the post-login `ntu.edu.sg` suffix check is sufficient (it is a string containment on the last 10 characters of the UPN, not a `tid` allow-list). Confirming effectiveness **requires authenticated testing (out of scope for this non-intrusive pass)**.

### Verdict

| Claim | Status |
|-------|--------|
| Code uses `.../common` (any Microsoft tenant, not NTU-specific authority) | **Corroborated from source** |
| Live page/redirects prove `/common` vs an NTU tenant | **Cannot determine** from unauthenticated traffic (no IdP redirect; login not started) |
| App is NTU-only in practice | **Cannot determine** without completing device flow |

---

## 3. Security headers on the app root

Raw `HEAD /` / `GET /` headers (**observed**, 2026-09-30 11:15:13 GMT):

```
HTTP/1.1 200 OK
Content-Length: 891
Content-Type: text/html
Date: Wed, 30 Sep 2026 11:15:13 GMT
Server: TornadoServer/6.4.2
Accept-Ranges: bytes
Cache-Control: no-cache
ETag: "51565dc400d851d83680810088e726c934644a7365fe05201d45aed7a88f197ba508cefcf60a014807d17b0c9792ec8b2bf1818a1d35ce9289423fb90509dfbc"
Last-Modified: Mon, 28 Sep 2026 20:48:16 GMT
Vary: Accept-Encoding
```

| Header | Status on `/` |
|--------|----------------|
| `Strict-Transport-Security` (HSTS) | **ABSENT** |
| `Content-Security-Policy` | **ABSENT** |
| `X-Frame-Options` / CSP `frame-ancestors` | **ABSENT** (no CSP at all) |
| `X-Content-Type-Options` | **ABSENT** |
| `Referrer-Policy` | **ABSENT** |
| `Cache-Control` | **PRESENT:** `no-cache` |
| `Permissions-Policy` / COOP / CORP | **ABSENT** |
| `Server` | **PRESENT:** `TornadoServer/6.4.2` |

**Hosting banner (observed):** application server identifies as **Tornado 6.4.2** (Streamlit’s default HTTP server). Hostname, DNS CNAMEs (`waws-prod-sg1-089...azurewebsites.windows.net`, Southeast Asia), and the platform wildcard cert identify **Azure App Service**. No `x-ms-*` / `x-azure-*` response headers were present on these responses.

**Verdict:** missing HSTS, CSP, framing controls, `X-Content-Type-Options`, and `Referrer-Policy` on the app root is **corroborated live**. Framework/version leakage via `Server: TornadoServer/6.4.2` is **observed**.

Additional header note (health endpoints only, not the root):

```
Set-Cookie: _streamlit_xsrf=...; Path=/
```

**Observed:** cookie attributes `Secure`, `HttpOnly`, and `SameSite` were **not** present on that `Set-Cookie`. Cookie *value* omitted here; only the flags are security-relevant for this write-up.

---

## 4. TLS / certificate

These checks used the system trust store (`Verification: OK` / `Verify return code: 0 (ok)`). The leaf is a public Microsoft Azure platform certificate, **not** a private/corporate interception CA. Chain:

| Depth | Subject | Issuer |
|-------|---------|--------|
| 0 (leaf) | `C=US, ST=WA, L=Redmond, O=Microsoft Corporation, CN=*.azurewebsites.net` | `Microsoft TLS G2 RSA CA OCSP 16` |
| 1 | `CN=Microsoft TLS G2 RSA CA OCSP 16` | `Microsoft TLS RSA Root G2` |
| 2 | `CN=Microsoft TLS RSA Root G2` | `DigiCert Global Root G2` |
| 3 | `CN=DigiCert Global Root G2` | DigiCert (public root) |

Leaf details **observed**:

```
subject= C=US, ST=WA, L=Redmond, O=Microsoft Corporation, CN=*.azurewebsites.net
issuer=  C=US, O=Microsoft Corporation, CN=Microsoft TLS G2 RSA CA OCSP 16
notBefore= Aug 28 20:27:37 2026 GMT
notAfter=  Feb 24 20:27:37 2027 GMT
SAN includes DNS:*.azurewebsites.net (covers this hostname)
SHA-256 fingerprint= 1B:C8:FC:15:55:20:E4:6B:37:43:DC:A2:A0:A6:C4:8F:58:B7:E5:AF:DE:59:46:92:8B:1E:28:57:D3:48:2F:0A
Serial= 55:00:c6:c8:d5:71:3f:ca:75:f0:74:6e:7d:00:00:00:c6:c8:d5
```

Default (and `curl -vI`) negotiation **observed:** **TLSv1.3**, cipher `TLS_AES_256_GCM_SHA384` (curl reported `TLSv1.3 / AEAD-AES256-GCM-SHA384`). ALPN: server accepted **http/1.1** (no h2 on this probe).

Forced-version probes **observed**:

| Client offer | Result |
|--------------|--------|
| TLS 1.3 (`-tls1_3`) | Handshake OK, `TLS_AES_256_GCM_SHA384` |
| TLS 1.2 (`-tls1_2`) | Handshake OK, `ECDHE-RSA-AES256-GCM-SHA384` |
| TLS 1.1 (`-tls1_1`) | **Inconclusive:** local OpenSSL returned `no protocols available` (this client build does not offer TLS 1.1). **Not** evidence that the server accepts or rejects 1.1. |
| TLS 1.0 (`-tls1`) | **Inconclusive:** same local-client limitation. |

**Verdict:** certificate is the **target Azure App Service hostname’s platform cert** (`*.azurewebsites.net` issued by Microsoft TLS G2, chaining to DigiCert). It is **not** a proxy interception cert. TLS 1.2 and 1.3 are accepted. TLS 1.0/1.1 server policy **cannot be determined** from this client.

---

## 5. Error handling / information disclosure

Benign nonexistent paths:

| Path | Status | Body |
|------|--------|------|
| `/robots.txt` | 404 | Same 891-byte Streamlit HTML shell as `/` |
| `/nonexistent` | 404 | Same shell |
| `/admin` | 404 | Same shell |

**Observed:** no Python traceback, no file paths, no Streamlit/Python version in the **body**. The 404 page is the generic Streamlit SPA HTML (`<title>Streamlit</title>`), not an Azure 404 or a debug dump.

**Observed (headers, all of the above):** `Server: TornadoServer/6.4.2` — framework family and version disclosed on every response sampled.

**Cannot determine:** whether authenticated or post-exception Streamlit pages render stack traces (`--client.showErrorDetails`). Triggering an application exception would require interacting with the app (and possibly logging in). Out of scope.

**Verdict:** unauthenticated 404s **do not** leak stack traces. They **do** leak the Tornado server version via the `Server` header. Live confirmation of in-app exception pages **cannot be determined**.

---

## 6. robots.txt and obviously exposed endpoints

| URL | Status | Notes |
|-----|--------|-------|
| `/robots.txt` | **404** | No robots policy served; same SPA shell |
| `/_stcore/health` | **200** `ok` | Standard Streamlit health; also set `_streamlit_xsrf` |
| `/healthz` | **200** `ok` | Deprecated alias; `Link: <http://asknarelle-4-sc1003.azurewebsites.net/_stcore/health>; rel="alternate"` (note: **http** in the Link URL, not https) |
| `/static/...` | **not fetched** | Shell HTML references `./static/js/main.cc5b8325.js` and CSS/fonts (public Streamlit assets). Extra GETs skipped to keep traffic minimal. |

**Inferred (not fetched):** Streamlit’s usual `/_stcore/stream` WebSocket and static JS/CSS are reachable to any unauthenticated visitor who loads the SPA. This pass did not open that WebSocket.

No other “admin” or debug UI was observed at `GET /admin` (404 shell only).

---

## 7. Status of each code-review finding

| Goal | Code-review claim | Live status | Basis |
|------|-------------------|-------------|-------|
| 1. Login authority | MSAL `authority='https://login.microsoftonline.com/common'` | **Corroborated in source; cannot confirm live** | Source: `Home.py` L112. Live unauth GET/HEAD: no AAD redirect, no client-side MSAL. Device flow not started. |
| 2. Security headers | Missing HSTS, CSP, XFO/frame-ancestors, XCTO, Referrer-Policy; hosting banner | **Corroborated live** | Root response has none of those headers. `Server: TornadoServer/6.4.2`. `Cache-Control: no-cache` is present. |
| 3. TLS / certificate | Real Azure cert, not interception | **Corroborated live** | Microsoft TLS G2 leaf `CN=*.azurewebsites.net`, DigiCert-rooted chain, system verify OK, TLS 1.2 + 1.3. |
| 4. Error handling / info disclosure | Stack traces / versions | **Partially corroborated** | Unauth 404 bodies are generic SPA HTML (no traces). `Server` header discloses Tornado 6.4.2. In-app exception UI not tested. |
| 5. robots.txt / exposed endpoints | Public Streamlit endpoints | **Corroborated live** | No `robots.txt`. `/_stcore/health` and `/healthz` return `ok` unauthenticated. |

**Refuted:** none of the scoped claims were refuted by this pass.

---

## 8. Items requiring authenticated testing (NOT done)

- Completing MSAL device flow or any other login.
- Whether a non-NTU Microsoft account (other Entra tenant or personal MSA) can obtain a token against `/common` and/or pass the post-login `ntu.edu.sg` / Mongo allow-list checks.
- Azure AD app registration `signInAudience`, redirect URIs, and whether device-code phishing of the on-screen `user_code` works.
- Submitting chat input (prompt injection, system-prompt leakage, markdown/HTML rendering, LLM cost).
- Per-user rate limiting and abuse controls.
- Access control on MongoDB conversation logs and the `users_permission` collections.
- Streamlit exception / traceback disclosure after login or after a server-side error.
- Effectiveness of the `_streamlit_xsrf` cookie (would require state-changing POSTs).
- WebSocket `/_stcore/stream` session behavior for an unauthenticated visitor who hydrates the SPA.

---

## Rules followed

Only the inventory in §1 was sent. No credentials, no device-flow completion, no chat, no fuzzing, no rate/load test, no access-control bypass. Earlier passes from a proxied environment that received `CONNECT 403` were not used as evidence about the app; this pass ran on a network that reached `20.212.64.12` directly.
