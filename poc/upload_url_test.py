"""
VetraFi Bug Bounty - S3 Pre-signed Upload URL Analysis PoC
Tests: generateUploadUrl mutation, S3 bucket configuration
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
print("VetraFi Upload URL Generation PoC")
print("=" * 60)

# Test 1: Verify generateUploadUrl mutation is documented in JS
print("\n[Test 1] generateUploadUrl mutation in client-side code")
WEB_TARGET = "https://app.vetrafi.com/_next/static/chunks/app/layout-8455ea0eb07ed5fd.js?dpl=dpl_GUvMDsDgJdmAoAkau4bMeyXh8rsp"
try:
    req = urllib.request.Request(WEB_TARGET,
        headers={"User-Agent": "Mozilla/5.0 PoC"})
    resp = urllib.request.urlopen(req, timeout=30)
    js = resp.read().decode('utf-8', errors='replace')
    
    has_mutation = 'generateUploadUrl' in js
    has_presigned = 'preSignedUrl' in js
    has_doc_url = 'documentURL' in js
    
    test("generateUploadUrl mutation found", has_mutation, "(Not in JS bundle)")
    test("preSignedUrl return field", has_presigned, "(Not in JS bundle)")
    test("documentURL return field", has_doc_url, "(Not in JS bundle)")
    
    if has_mutation:
        # Extract the mutation structure
        import re
        match = re.search(r'generateUploadUrl[^}]{0,500}\}', js, re.DOTALL)
        if match:
            print(f"\n  [*] Mutation structure found in JS:")
            for line in match.group(0).split('\\n'):
                stripped = line.strip()
                if stripped:
                    print(f"      {stripped}")
except Exception as e:
    test("JS bundle accessible", False, f"(Error: {e})")

# Test 2: Attempt the mutation (will likely require auth)
print("\n[Test 2] generateUploadUrl mutation access check")
try:
    data = json.dumps({"query": "mutation { generateUploadUrl(input: {}) { preSignedUrl documentURL } }"}).encode()
    req = urllib.request.Request(API_TARGET, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 PoC"})
    resp = urllib.request.urlopen(req, timeout=15)
    body = json.loads(resp.read())
    
    errors = body.get("errors", [])
    if errors:
        print(f"  [INFO] Mutation response: {json.dumps(errors[0])[:300]}")
        has_auth_error = any("UNAUTHENTICATED" in str(e) for e in errors)
        test("Upload requires authentication", has_auth_error, 
             "(Not authenticated - expected)")
    else:
        print(f"  [INFO] Mutation succeeded - check output")
        print(f"  {json.dumps(body, indent=2)[:500]}")
        
except Exception as e:
    print(f"  [INFO] Endpoint error: {e}")

print("\n[Test 3] Analysis (theoretical)")
print("""
  [*] The generateUploadUrl mutation generates S3 pre-signed URLs for document upload.
  [*] Potential abuse scenarios:
      1. Unrestricted content type upload to S3
      2. Path traversal in document URL
      3. Storage quota exhaustion
      4. Serving malicious content from VetraFi's domain
  [*] Requires authenticated session + actual S3 bucket testing to confirm.
  [*] THIS PoC SHOULD NOT BE RUN AGAINST PRODUCTION without explicit authorization.
""")

print(f"\n{'=' * 60}")
print(f"Results: {PASS} passed, {FAIL} failed")
print(f"{'=' * 60}")

sys.exit(0 if FAIL == 0 else 1)
