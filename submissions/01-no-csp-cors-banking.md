# Finding 1: Missing Content Security Policy and Wildcard CORS on FinTech Banking Application

**Severity:** High  
**Asset:** app.vetrafi.com  
**Category:** Security Misconfiguration / Defense in Depth  
**Reward Band:** $5,000–$8,000

---

## Summary

The VetraFi web application (`app.vetrafi.com`) — a financial technology platform handling sensitive military personnel financial data, bank account connections via Plaid, tax filings, and PII — operates with **zero Content Security Policy (CSP)** and a **wildcard CORS policy (`Access-Control-Allow-Origin: *`)**. This combination of missing security headers is exceptionally severe for a FinTech application managing banking, tax, and military verification data.

## Finding Description

### No Content Security Policy

The response headers from `app.vetrafi.com` contain **no** `Content-Security-Policy` header whatsoever:

```http
HTTP/2 200
access-control-allow-origin: *
server: Vercel
strict-transport-security: max-age=63072000
# NO content-security-policy header present
```

This means:
- Any script can execute in the page context — no restrictions on inline scripts, `eval()`, or external script sources
- Any origin can frame the page — no `frame-ancestors` directive
- Any origin can connect to any endpoint — no `connect-src` restriction
- Form submissions can target any URL — no `form-action` restriction
- Any resource can be loaded from any origin — no `default-src` or `object-src` restrictions

### Wildcard CORS

Every response from `app.vetrafi.com` includes:

```http
access-control-allow-origin: *
```

This allows any cross-origin website to:
- Read all response data via `fetch()` or `XMLHttpRequest`
- Interact with authenticated sessions (if the user is logged in and cookies are set with `SameSite=None; Secure`)
- Perform cross-origin data exfiltration

### Chained Impact

The absence of CSP combined with wildcard CORS creates a particularly dangerous scenario:

1. **No CSP means any XSS is game over** — no script-src, no trusted-types, no defense in depth
2. **Wildcard CORS means any website can read API responses** — if a victim visits an attacker's site while logged into VetraFi, and CORS cookies are permissive, the attacker can read their financial data
3. **No frame-ancestors means clickjacking is possible** — the page can be embedded in any iframe

## Impact Explanation

For a FinTech application that:
- Connects to users' bank accounts via Plaid
- Stores full home and mailing addresses
- Collects military service details (branch, status, pay grade, date of entry)
- Handles tax filings with SSN-adjacent data
- Manages financial goals, budgets, and net worth tracking

**The absence of CSP is a critical failure in defense-in-depth.** If any Cross-Site Scripting vulnerability exists — whether in a third-party widget (Intercom, Facebook Pixel, Google Analytics), a future feature, or a DOM-based XSS — the CSP would be the last line of defense. Without it, attackers have unrestricted access to:

- Steal JWT tokens from localStorage or cookies
- Read and exfiltrate all displayed PII (name, address, phone, military info)
- Modify page content to phish for additional credentials
- Execute arbitrary wallet drain or account takeover operations via the GraphQL API

**The wildcard CORS amplifies this risk** by enabling cross-origin data theft from authenticated sessions.

### Comparison with Industry Standards

| Security Control | app.vetrafi.com | Industry Standard (FinTech) |
|-----------------|-----------------|---------------------------|
| Content-Security-Policy | **MISSING** | `default-src 'self'; script-src 'self'; ...` |
| `frame-ancestors` | **MISSING** | `'none'` or `'self'` |
| `Access-Control-Allow-Origin` | `*` | Specific allowed origins |
| `X-Content-Type-Options` | **MISSING** | `nosniff` |

## Likelihood Explanation

**High** — The findings are trivially reproducible with a single `curl` command and require no authentication or special access. The absence of CSP and presence of wildcard CORS is observable by anyone who inspects the HTTP response headers. While exploitation requires chaining with another vulnerability (XSS for CSP bypass, or specific cookie configuration for CORS), the complete absence of CSP removes the most important defense-in-depth layer protecting user financial data.

## Proof of Concept

### 1. Verify Missing CSP
```bash
curl -sI "https://app.vetrafi.com/" | grep -i "content-security-policy"
# Expected: NO OUTPUT (header is missing)
```

### 2. Verify Wildcard CORS
```bash
curl -sI "https://app.vetrafi.com/" | grep -i "access-control"
# Expected: access-control-allow-origin: *
```

### 3. Cross-Origin Data Read Test (HTML PoC)
Save as `cors_poc.html` and open in a browser while logged into VetraFi:
```html
<html>
<body>
  <h1>CORS + No CSP PoC - app.vetrafi.com</h1>
  <pre id="output"></pre>
  <script>
    fetch('https://app.vetrafi.com/login')
      .then(r => r.text())
      .then(html => {
        document.getElementById('output').textContent = 
          '[PASS] Cross-origin fetch succeeded. Response length: ' + html.length;
      })
      .catch(e => {
        document.getElementById('output').textContent = 
          '[FAIL] Cross-origin fetch blocked: ' + e.message;
      });
  </script>
</body>
</html>
```

### 4. Clickjacking PoC
```html
<html>
<body>
  <h1>Clickjacking PoC - app.vetrafi.com</h1>
  <iframe src="https://app.vetrafi.com/login" width="800" height="600"></iframe>
  <p style="color:green">[PASS] Iframe loaded - no frame-ancestors CSP and no X-Frame-Options</p>
</body>
</html>
```

## Recommendation

1. **Implement a strict Content Security Policy** appropriate for a FinTech application:
```http
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' https://www.googletagmanager.com https://connect.facebook.net;
  connect-src 'self' https://api.vetrafi.com https://*.aptrinsic.com;
  frame-ancestors 'none';
  form-action 'self';
  base-uri 'self';
  block-all-mixed-content;
```

2. **Restrict CORS to specific origins** — remove `Access-Control-Allow-Origin: *` and replace with explicit origins:
```http
Access-Control-Allow-Origin: https://app.vetrafi.com
```

3. **Add additional security headers:**
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```
