"""
VetraFi Bug Bounty - GraphQL API Reconnaissance PoC
Tests: GraphQL endpoint live, Me query exists, Operation extraction from JS
"""

import urllib.request
import urllib.error
import json
import re
import sys

API_TARGET = "https://api.vetrafi.com/graphql"
WEB_TARGET = "https://app.vetrafi.com/_next/static/chunks/app/layout-8455ea0eb07ed5fd.js?dpl=dpl_GUvMDsDgJdmAoAkau4bMeyXh8rsp"
PASS = 0
FAIL = 0
js = ""  # Will be populated by JS bundle download

def test(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        print(f"  [PASS] {name}")
        PASS += 1
    else:
        print(f"  [FAIL] {name} {detail}")
        FAIL += 1

print("=" * 60)
print("VetraFi GraphQL API Reconnaissance PoC")
print("=" * 60)

# Test 1: GraphQL endpoint is live
print("\n[Test 1] GraphQL endpoint reachability")
try:
    data = json.dumps({"query": "{ __typename }"}).encode()
    req = urllib.request.Request(API_TARGET, data=data, 
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 PoC"})
    resp = urllib.request.urlopen(req, timeout=15)
    body = json.loads(resp.read())
    typename = body.get("data", {}).get("__typename", "")
    test("GraphQL endpoint returns valid response", typename == "Query",
         f"(Got: {typename})")
except Exception as e:
    test("GraphQL endpoint reachable", False, f"(Error: {e})")

# Test 2: Me query exists (UNAUTHENTICATED response confirms it)
print("\n[Test 2] Me query exists (authentication required)")
try:
    data = json.dumps({"query": "{ me { id email } }"}).encode()
    req = urllib.request.Request(API_TARGET, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 PoC"})
    resp = urllib.request.urlopen(req, timeout=15)
    body = json.loads(resp.read())
    errors = body.get("errors", [])
    has_auth_error = any("UNAUTHENTICATED" in str(e.get("extensions", {})) for e in errors)
    has_me_error = any("me" in str(e.get("path", [])) for e in errors)
    test("Me query confirmed (UNAUTHENTICATED error)", has_auth_error or has_me_error,
         f"(Response: {json.dumps(body)[:200]})")
except Exception as e:
    test("Me query accessible", False, f"(Error: {e})")

# Test 3: Extract GraphQL operations from JS bundles
print("\n[Test 3] GraphQL operation enumeration from JS")
try:
    req = urllib.request.Request(WEB_TARGET, 
        headers={"User-Agent": "Mozilla/5.0 PoC"})
    resp = urllib.request.urlopen(req, timeout=30)
    js = resp.read().decode('utf-8', errors='replace')
    
    # Extract operation names
    operations = set(re.findall(r'(?:query|mutation)\s+(\w+)', js))
    test("Operations extracted from JS bundle", len(operations) > 10,
         f"(Found {len(operations)} operations)")
    
    print(f"\n  [*] Found {len(operations)} GraphQL operations:")
    for op in sorted(operations):
        if op not in ['error']:  # skip false positives
            print(f"      - {op}")
    
    # Check for specific sensitive operations
    sensitive_ops = ['generateUploadUrl', 'Me', 'AprilAuthCodeQuery', 
                     'ExchangeVeteransAffairsAuthorizationCode',
                     'GetMultiplePlaidItemDetails']
    for sop in sensitive_ops:
        found = sop in operations
        test(f"Sensitive operation found: {sop}", found, "(Not found in JS)")
        
except Exception as e:
    test("JS bundle accessible", False, f"(Error: {e})")

# Test 4: Verify PII fields in Me query
print("\n[Test 4] PII field enumeration from JS")
try:
    # In compiled JS, fields may appear differently - search for key PII field names
    pii_keywords = ['firstName', 'lastName', 'primaryPhoneNumber', 'addressLine1',
                    'addressCity', 'addressState', 'addressZip', 'militaryBranch',
                    'payGrade', 'dateOfEntry', 'militaryVerificationStatus',
                    'mailingAddressLine1']
    found_pii = [kw for kw in pii_keywords if kw in js]
    test("PII fields found in JS bundle", len(found_pii) >= 10,
         f"(Found {len(found_pii)}/{len(pii_keywords)} PII fields)")
    
    print(f"  [*] PII fields found: {', '.join(found_pii)}")
    missing = [kw for kw in pii_keywords if kw not in js]
    if missing:
        print(f"  [*] PII fields NOT found in substrings: {', '.join(missing)}")
    
    # Also try to extract the me query structure with a more flexible regex
    me_blocks = re.findall(r'query\s+Me\s*\{[^}]*me\s*\{[^}]+\}', js, re.DOTALL)
    if me_blocks:
        print(f"  [*] Found {len(me_blocks)} Me query blocks in JS")
    else:
        # Fall back to finding "me {" patterns
        me_refs = re.findall(r'me\s*\{[\w\s,]+\}', js[:50000])
        if me_refs:
            print(f"  [*] Found me field references: {me_refs[0][:200]}...")
    
except Exception as e:
    test("PII enumeration", False, f"(Error: {e})")

print(f"\n{'=' * 60}")
print(f"Results: {PASS} passed, {FAIL} failed")
print(f"{'=' * 60}")

sys.exit(0 if FAIL == 0 else 1)
