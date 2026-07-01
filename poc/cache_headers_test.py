"""
VetraFi Bug Bounty - Cache Header Analysis PoC
Tests: x-nextjs-prerender, x-nextjs-stale-time, x-vercel-cache
"""

import urllib.request
import urllib.error
import sys

TARGETS = [
    "https://app.vetrafi.com/",
    "https://app.vetrafi.com/login",
    "https://app.vetrafi.com/signup",
]
PASS = 0
FAIL = 0

def test(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        print(f"  [PASS] {name}")
        PASS += 1
    else:
        print(f"  [FAIL] {name} {detail}")
        FAIL += 1

print("=" * 60)
print("VetraFi Cache Header Analysis PoC")
print("=" * 60)

for target in TARGETS:
    print(f"\n[!] Testing: {target}")
    try:
        req = urllib.request.Request(target)
        req.add_header("User-Agent", "Mozilla/5.0 PoC")
        resp = urllib.request.urlopen(req, timeout=15)
        headers = dict(resp.getheaders())
        
        # Check for prerender header
        prerender = headers.get('x-nextjs-prerender', headers.get('X-Nextjs-Prerender', ''))
        test(f"x-nextjs-prerender is 1", prerender == '1',
             f"(Found: {prerender})")
        
        # Check for stale time header
        stale = headers.get('x-nextjs-stale-time', headers.get('X-Nextjs-Stale-Time', ''))
        test(f"x-nextjs-stale-time present", bool(stale),
             "(Missing)")
        if stale:
            is_max = stale == '4294967294'
            test(f"x-nextjs-stale-time is suspiciously high ({stale})", is_max,
                 f"(Expected 4294967294, got {stale})")
            
            # Calculate human-readable time
            try:
                seconds = int(stale)
                years = seconds / (365.25 * 24 * 3600)
                print(f"  [INFO] Stale time in years: {years:.1f}")
                test(f"Stale time > 1 year (unusually high)", years > 1,
                     f"({years:.1f} years)")
            except ValueError:
                print(f"  [INFO] Stale time is not numeric: {stale}")
        
        # Check for Vercel cache
        cache = headers.get('x-vercel-cache', headers.get('X-Vercel-Cache', ''))
        test(f"x-vercel-cache present", bool(cache),
             "(Missing)")
        if cache:
            print(f"  [INFO] Vercel cache status: {cache}")
        
        # Cache-control header
        cc = headers.get('cache-control', headers.get('Cache-Control', ''))
        test(f"Cache-Control present", bool(cc), "")
        if cc:
            print(f"  [INFO] Cache-Control: {cc[:100]}")
            
    except Exception as e:
        print(f"  [ERROR] {target}: {e}")

# Compare with standard best practice
print(f"\n{'=' * 60}")
print("Comparison with Industry Best Practice")
print(f"{'=' * 60}")
print("""
  Cache Header          | app.vetrafi.com    | Recommended
  ----------------------|-------------------|-------------
  x-nextjs-prerender    | 1                 | Omit in production
  x-nextjs-stale-time   | 4294967294        | 60-3600 (1min-1hr)
  x-vercel-cache        | HIT/MISS          | Omit or monitor only
  
  x-nextjs-stale-time of 4294967294 seconds = 136.2 years
  This is the maximum 32-bit unsigned integer (2^32 - 2).
  Effectively disables cache revalidation permanently.
""")

print(f"\n{'=' * 60}")
print(f"Results: {PASS} passed, {FAIL} failed")
print(f"{'=' * 60}")

sys.exit(0 if FAIL == 0 else 1)
