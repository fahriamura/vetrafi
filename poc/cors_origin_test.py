"""
VetraFi Bug Bounty - Security Headers & CORS Test PoC
Tests: Missing CSP, Wildcard CORS, Missing security headers
"""

import urllib.request
import urllib.error
import json
import sys

TARGET = "https://app.vetrafi.com"
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
print(f"VetraFi Security Headers PoC")
print(f"Target: {TARGET}")
print("=" * 60)

try:
    req = urllib.request.Request(TARGET)
    req.add_header("User-Agent", "Mozilla/5.0 PoC")
    resp = urllib.request.urlopen(req, timeout=15)
    headers = dict(resp.getheaders())
    print(f"\n[+] HTTP {resp.status} - connected successfully")
    
    # Test for CSP
    csp_headers = [k for k in headers if 'content-security-policy' in k.lower()]
    has_csp = len(csp_headers) > 0
    test("Content-Security-Policy header present", has_csp, 
         "(MISSING - no CSP on FinTech app)")
    
    # Test CORS
    acao = headers.get('access-control-allow-origin', headers.get('Access-Control-Allow-Origin', ''))
    test("Access-Control-Allow-Origin is wildcard", acao == '*',
         f"(Found: {acao})")
    if acao and acao != '*':
        print(f"  [INFO] ACAO is restricted to: {acao}")
    
    # Test X-Frame-Options
    xfo = [v for k,v in headers.items() if 'x-frame-options' in k.lower()]
    has_xfo = len(xfo) > 0
    test("X-Frame-Options header present", has_xfo, "(MISSING - clickjacking possible)")
    if has_xfo:
        print(f"  [INFO] X-Frame-Options: {xfo[0]}")
    
    # Test X-Content-Type-Options
    xcto = [v for k,v in headers.items() if 'x-content-type-options' in k.lower()]
    has_xcto = len(xcto) > 0
    test("X-Content-Type-Options: nosniff", has_xcto, "(MISSING)")
    if has_xcto:
        test("X-Content-Type-Options value", xcto[0].lower() == 'nosniff',
             f"(Found: {xcto[0]})")
    
    # Test HSTS
    hsts = [v for k,v in headers.items() if 'strict-transport-security' in k.lower()]
    has_hsts = len(hsts) > 0
    test("Strict-Transport-Security present", has_hsts, "(MISSING)")
    if has_hsts:
        print(f"  [INFO] HSTS: {hsts[0][:80]}...")
    
    # Test Referrer-Policy
    rp = [v for k,v in headers.items() if 'referrer-policy' in k.lower()]
    has_rp = len(rp) > 0
    test("Referrer-Policy present", has_rp, "(MISSING)")
    
    # Print all relevant headers
    print("\n[+] All security-relevant headers:")
    security_keys = ['content-security', 'access-control', 'x-frame', 'x-content', 
                     'strict-transport', 'referrer-policy', 'x-xss', 'permissions-policy',
                     'server']
    for k, v in sorted(headers.items()):
        if any(sk in k.lower() for sk in security_keys):
            print(f"    {k}: {v}")

except Exception as e:
    print(f"\n[-] Connection error: {e}")

print(f"\n{'=' * 60}")
print(f"Results: {PASS} passed, {FAIL} failed")
print(f"{'=' * 60}")

sys.exit(0 if FAIL == 0 else 1)
