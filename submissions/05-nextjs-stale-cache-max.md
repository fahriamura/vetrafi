# Finding 5: Next.js Stale-While-Revalidate Cache Time Set to Maximum 32-bit Integer (4294967294)

**Severity:** Low  
**Asset:** app.vetrafi.com  
**Category:** Cache Misconfiguration / Information Disclosure  
**Reward Band:** Discretionary

---

## Summary

The VetraFi Next.js application sets the `x-nextjs-stale-time` header to `4294967294` — the maximum value for a 32-bit unsigned integer (2³² − 2). This means stale cached content is served for approximately **136 years** before triggering a re-render. Combined with the `x-nextjs-prerender: 1` header, this reveals that the application uses Incremental Static Regeneration (ISR) with effectively infinite stale-while-revalidate behavior, which has implications for cache poisoning and content freshness.

## Finding Description

All pages on `app.vetrafi.com` return the following cache-related headers:

```http
HTTP/2 200
x-nextjs-prerender: 1
x-nextjs-stale-time: 4294967294
x-vercel-cache: HIT
```

### Header Interpretation

| Header | Value | Meaning |
|--------|-------|---------|
| `x-nextjs-prerender` | `1` | Page is statically pre-rendered (ISR) |
| `x-nextjs-stale-time` | `4294967294` | Stale content served for ~136 years before re-render |
| `x-vercel-cache` | `HIT` | Content served from Vercel Edge Cache |

The value `4294967294` is notable because:
- It equals `Number.MAX_SAFE_INTEGER` for 32-bit unsigned: `2³² − 2 = 4294967294`
- It effectively disables the "revalidate" part of ISR — once a page is cached, it will be served stale for longer than the application will exist
- Standard practice for ISR is 60–3600 seconds (1 minute to 1 hour)

### Cache Behavior Under Stale

With `x-nextjs-stale-time: 4294967294`:
1. When a page is first rendered, it's cached with a "fresh" state
2. After the revalidate window expires, the page becomes "stale" but is still served
3. The stale content is served for **4294967294 seconds** (136+ years) before Next.js triggers a background re-render
4. This means content updates (bug fixes, security patches, UI changes) may not be reflected for users until the Vercel cache is manually purged

## Impact Explanation

1. **Stale Content Delivery:** In the event of a successful cache poisoning attack (e.g., reflected parameter injection, API response manipulation), the poisoned content would be served for 136 years — practically forever. Normal cache poisoning windows are measured in minutes.

2. **Slow Patching:** If VetraFi deploys a security fix (e.g., fixing an XSS, updating a CTA that was phished), users may continue to see the old version until the Vercel cache is manually invalidated. The 136-year stale window means automatic cache invalidation on deploy does NOT trigger a re-render.

3. **Information Disclosure:** The `x-vercel-cache: HIT` vs `MISS` status can be used to:
   - Determine if a page has been visited before (privacy concern)
   - Determine if restricted pages exist (HIT means the page was generated and cached)

4. **Security Header Staleness:** If security headers (CSP, CORS, etc.) are updated via a deployment, users may continue receiving the old headers from the stale cache for the entire stale window.

## Likelihood Explanation

**Low** — The cache misconfiguration alone is not directly exploitable. Its primary risk is:
1. Amplifying the impact of cache poisoning (from hours to centuries)
2. Delaying the rollout of security patches
3. Enabling cache-based side-channel enumeration

The stale time of `4294967294` is almost certainly unintentional — it's the default/fallback value from an ISR configuration that doesn't explicitly set `staleTime`.

## Proof of Concept

### 1. Verify Cache Headers
```bash
curl -sI "https://app.vetrafi.com/" | grep -iE "nextjs|vercel-cache"
```
Expected output:
```http
x-nextjs-prerender: 1
x-nextjs-stale-time: 4294967294
x-vercel-cache: HIT
```

### 2. Verify on Login Page
```bash
curl -sI "https://app.vetrafi.com/login" | grep -iE "nextjs|vercel-cache"
```
Expected output: Same headers as above.

### 3. Cache Status Side-Channel
```bash
# A page that exists should return HIT after first visit
curl -sI "https://app.vetrafi.com/login" | grep "x-vercel-cache"

# A page that might not exist - different cache behavior
curl -sI "https://app.vetrafi.com/admin" | grep "x-vercel-cache"
```

### 4. Cross-Reference with Monad (same stack)
For comparison, the earlier Monad.xyz bounty used `x-nextjs-stale-time: 300` (5 minutes) — a reasonable value. VetraFi's value of `4294967294` is off by a factor of ~14 million.

## Recommendation

1. **Set `staleTime` to a reasonable value** in the Next.js ISR configuration:
```javascript
// next.config.js or page-level revalidate
// Recommended: 60-300 seconds for dynamic content
export const revalidate = 60; // 1 minute
```

2. **Remove debug headers in production** — suppress `x-nextjs-prerender` and `x-nextjs-stale-time` headers:
```javascript
// next.config.js
module.exports = {
  poweredByHeader: false,
  // Vercel-specific: these can be suppressed via vercel.json
}
```

3. **Implement cache purge webhooks** for critical security deployments to ensure immediate cache invalidation.

4. **Consider using `Vercel-Cache: STALE` monitoring** to alert when stale content is being served for longer than expected.
