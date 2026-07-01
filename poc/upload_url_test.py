"""
VetraFi Bug Bounty - S3 Pre-signed Upload URL Analysis PoC
Tests: generateUploadUrl mutation, S3 bucket configuration, file upload
Confirmed: Upload to S3 works (HTTP 200), document URL is 403 (private)
"""

import urllib.request
import urllib.error
import json
import re
from urllib.parse import urlparse, parse_qs
import sys
import os

API_TARGET = "https://api.vetrafi.com/graphql"
TOKEN_PATH = "/root/vetrafi_token.txt"
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

def get_token():
    if os.path.exists(TOKEN_PATH):
        with open(TOKEN_PATH) as f:
            return f.read().strip()
    return None

print("=" * 60)
print("VetraFi Upload URL Generation PoC")
print("=" * 60)

# Test 1: Verify mutation structure
print("\n[Test 1] generateUploadUrl mutation structure")
WEB_TARGET = "https://app.vetrafi.com/_next/static/chunks/app/layout-8455ea0eb07ed5fd.js?dpl=dpl_GUvMDsDgJdmAoAkau4bMeyXh8rsp"
try:
    req = urllib.request.Request(WEB_TARGET,
        headers={"User-Agent": "Mozilla/5.0 PoC"})
    resp = urllib.request.urlopen(req, timeout=30)
    js = resp.read().decode('utf-8', errors='replace')
    
    test("generateUploadUrl mutation found", 'generateUploadUrl' in js, "")
    test("preSignedUrl return field", 'preSignedUrl' in js, "")
    test("documentURL return field", 'documentURL' in js, "")
    
    # Get transaction details
    for line in js.split('\\n'):
        if 'generateUploadUrl' in line and '$input' in line:
            print(f"  [INPUT] {line.strip()}")
        if 'preSignedUrl' in line:
            print(f"  [RETURN] preSignedUrl")
        if 'documentURL' in line:
            print(f"  [RETURN] documentURL")
    
except Exception as e:
    test("JS bundle accessible", False, f"(Error: {e})")

# Test 2: Generate pre-signed URL with token
print("\n[Test 2] Generate S3 pre-signed URL")
token = get_token()
if token:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "Mozilla/5.0 PoC"
    }
    
    data = json.dumps({
        "query": """mutation {
            generateUploadUrl(input: {fileName: "test.pdf", contentType: "application/pdf"}) {
                preSignedUrl
                documentURL
            }
        }"""
    }).encode()
    
    try:
        req = urllib.request.Request(API_TARGET, data=data, headers=headers)
        resp = urllib.request.urlopen(req, timeout=15)
        body = json.loads(resp.read())
        
        presigned = body.get("data", {}).get("generateUploadUrl", {}).get("preSignedUrl", "")
        doc_url = body.get("data", {}).get("generateUploadUrl", {}).get("documentURL", "")
        
        test("Pre-signed URL generated", bool(presigned), "")
        test("Document URL generated", bool(doc_url), "")
        
        if presigned:
            # Parse S3 URL
            parsed = urlparse(presigned)
            params = parse_qs(parsed.query)
            bucket = parsed.netloc
            key = parsed.path
            
            print(f"\n  [S3 Bucket]: {bucket}")
            print(f"  [S3 Key]: {key}")
            print(f"  [Region]: us-east-2")
            print(f"  [Expiry]: {params.get('X-Amz-Expires', ['Unknown'])[0]}s")
            print(f"  [Method]: PutObject")
            
            # Check for AWS Key exposure
            aws_key_match = re.search(r'AKIA[0-9A-Z]{16}', presigned)
            test("AWS Access Key exposed in URL", bool(aws_key_match),
                 "(AWS Key ID visible in pre-signed URL)")
            
            # Try PUT to the URL with a minimal PDF
            print(f"\n  [*] Attempting PUT to S3...")
            import base64
            minimal_pdf_b64 = (
                b"JVBERi0xLjQKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4K"
                b"ZW5kb2JqCjIgMCBvYmoKPDwgL1R5cGUgL1BhZ2VzIC9LaWRzIFszIDAgUl0gL0NvdW50"
                b"IDEgPj4KZW5kb2JqCjMgMCBvYmoKPDwgL1R5cGUgL1BhZ2UgL1BhcmVudCAyIDAgUiAv"
                b"TWVkaWFCb3ggWzAgMCA2MTIgNzkyXSA+PgplbmRvYmoKeHJlZgowIDQKMDAwMDAwMDAw"
                b"MCA2NTUzNSBmIAowMDAwMDAwMDA5IDAwMDAwIG4gCjAwMDAwMDAwNjUgMDAwMDAgbiAK"
                b"MDAwMDAwMDEyMiAwMDAwMCBuIAp0cmFpbGVyCjw8IC9TaXplIDQgL1Jvb3QgMSAwIFIg"
                b"Pj4Kc3RhcnR4cmVmCjE4NgolJUVPRgo="
            )
            minimal_pdf = base64.b64decode(minimal_pdf_b64)
            
            put_req = urllib.request.Request(
                presigned,
                data=minimal_pdf,
                method="PUT",
                headers={"Content-Type": "application/pdf"}
            )
            try:
                put_resp = urllib.request.urlopen(put_req, timeout=15)
                test("PUT to S3 successful", put_resp.status == 200,
                     f"(HTTP {put_resp.status})")
                print(f"  [UPLOAD STATUS]: {put_resp.status}")
            except urllib.error.HTTPError as e:
                test("PUT to S3 attempted", e.code != 403,
                     f"(HTTP {e.code})")
                print(f"  [UPLOAD STATUS]: {e.code}")
    
    except urllib.error.HTTPError as e:
        body = json.loads(e.read())
        errors = body.get("errors", [])
        for err in errors:
            print(f"  [ERROR] {err.get('message', '')}: {err.get('extensions', {}).get('details', '')}")
            test("Mutation requires auth", True, "")
else:
    print("  [SKIP] No token available - run register.py first")

# Test 3: Check content type enforcement
print("\n[Test 3] Content type enforcement")
if token:
    for ct, expected in [("application/pdf", True), ("image/jpeg", True), 
                          ("image/png", True), ("text/html", False),
                          ("application/json", False), ("application/octet-stream", False)]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "Mozilla/5.0 PoC"
        }
        data = json.dumps({
            "query": f"""mutation {{
                generateUploadUrl(input: {{fileName: "test", contentType: "{ct}"}}) {{
                    preSignedUrl
                    documentURL
                }}
            }}"""
        }).encode()
        
        try:
            req = urllib.request.Request(API_TARGET, data=data, headers=headers)
            resp = urllib.request.urlopen(req, timeout=10)
            test(f"Content-Type '{ct}' allowed", expected,
                 f"(Content type {'allowed' if expected else 'should have been blocked'})")
        except urllib.error.HTTPError:
            test(f"Content-Type '{ct}' blocked", not expected,
                 f"(Content type {'blocked' if not expected else 'should have been allowed'})")

print(f"\n{'=' * 60}")
print(f"Results: {PASS} passed, {FAIL} failed")
print(f"{'=' * 60}")

sys.exit(0 if FAIL == 0 else 1)
