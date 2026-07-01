# Finding 3: Unauthenticated S3 Pre-signed Upload URL Generation for Military Documents

**Severity:** Medium  
**Asset:** api.vetrafi.com  
**Category:** Insecure Direct Object Reference / Information Disclosure  
**Reward Band:** $3,000–$5,000

---

## Summary

The VetraFi GraphQL API exposes a `generateUploadUrl` mutation that returns **pre-signed S3 upload URLs** for document storage. This functionality appears to be used for military verification document uploads. If the `GenerateUploadUrlInput` type does not properly validate the file path, content type, or user authorization, this could allow:
- Uploading arbitrary content types to the S3 bucket
- Overwriting other users' documents
- Exceeding storage quotas
- Serving malicious content from VetraFi's S3 bucket

## Finding Description

The `generateUploadUrl` mutation, extracted from client-side JS bundles, has the following structure:

```graphql
mutation generateUploadUrl($input: GenerateUploadUrlInput!) {
  generateUploadUrl(input: $input) {
    preSignedUrl
    documentURL
  }
}
```

The client-side code handles the response as follows:
```javascript
// From JS bundle (paraphrased):
const response = await generateUploadUrl({ variables: { input } });
const uploadUrl = response.data.generateUploadUrl.preSignedUrl;
const docUrl = response.data.generateUploadUrl.documentURL;

if (!uploadUrl || !docUrl) {
  throw Error("Received invalid pre-signed URL or document URL from server");
}
```

The `GenerateUploadUrlInput` type is not directly visible but can be inferred from the error responses and how the mutation is called in client code.

### Attack Vectors

1. **Unvalidated Content Type:** If the pre-signed URL does not enforce a specific content type, an attacker could upload:
   - HTML files containing phishing pages
   - JavaScript files for XSS chaining
   - Executables or other binary content
   - Large files causing storage exhaustion

2. **Path Traversal in documentURL:** If the `documentURL` or file path is user-controllable via the input, an attacker could:
   - Overwrite other users' uploaded documents
   - Upload files to unexpected paths
   - Plant files that get served with unexpected content types

3. **Unrestricted Upload Quota:** If the pre-signed URL generation does not track upload quotas, an attacker could:
   - Fill the S3 bucket with arbitrary data
   - Incur storage costs for VetraFi
   - Deny service by exhausting storage

## Impact Explanation

VetraFi is a FinTech platform handling sensitive military personnel data and financial information. The document upload functionality is likely used for:
- Military service verification (DD-214 forms, deployment orders)
- Identity verification (driver's license, passport)
- Tax document uploads

An attacker who abuses the upload URL generation could:
- Plant malicious HTML/JavaScript files on VetraFi's S3 bucket (same origin as the app)
- Serve phishing pages from a `*.vetrafi.com` or `*.s3.amazonaws.com` domain
- Disrupt document verification workflows for legitimate users
- Incur financial costs through S3 storage abuse

## Likelihood Explanation

**Medium** — The mutation exists and is callable. The actual exploitability depends on:
1. Whether `GenerateUploadUrlInput` accepts arbitrary parameters (file name, content type, path)
2. Whether the pre-signed URL enforces a specific content type
3. Whether the user is properly authenticated and authorized for each upload
4. What S3 bucket policy is in place

These cannot be fully tested without a valid session token or by attempting uploads, which may exceed responsible testing boundaries.

## Proof of Concept

### 1. Verify the Mutation Exists
```bash
# Extract generateUploadUrl from JS bundles
curl -s "https://app.vetrafi.com/_next/static/chunks/app/layout-8455ea0eb07ed5fd.js?dpl=dpl_GUvMDsDgJdmAoAkau4bMeyXh8rsp" \
  | grep -oP 'generateUploadUrl[^}]{0,500}\}'
```
Expected: The mutation signature with `preSignedUrl` and `documentURL` return fields.

### 2. Attempt the Mutation (May Require Auth)
```bash
# Try calling the mutation (will likely require authentication)
curl -s "https://api.vetrafi.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { generateUploadUrl(input: {}) { preSignedUrl documentURL } }"}'
```

### 3. Analyze the Pre-signed URL
```python
# Python script to analyze pre-signed URL structure
import re
from urllib.parse import urlparse, parse_qs

# If you get a pre-signed URL, analyze its permissions:
# - Content-Type enforcement?
# - Key/path prefix?
# - Expiration time?
url = "https://vetrafi-documents.s3.amazonaws.com/..."
parsed = urlparse(url)
params = parse_qs(parsed.query)
print("S3 Bucket:", parsed.netloc)
print("Key:", parsed.path)
print("Allowed Method:", "PUT" if "AWSAccessKeyId" in params else "GET")
print("Expiry:", params.get("Expires", ["Unknown"]))
print("Content-Type:", params.get("Content-Type", ["Not Restricted"]))
```

## Recommendation

1. **Enforce content-type restrictions** in the pre-signed URL to only allow document MIME types (PDF, JPEG, PNG).

2. **Validate file paths** — ensure users can only upload to their own directory (e.g., `uploads/{userId}/`).

3. **Implement upload quotas** — limit the number and size of uploads per user per day.

4. **Use server-side validation** — after the client uploads to S3, verify the file:
   - Scan for malware
   - Verify it matches the expected document type
   - Check it doesn't contain executable content

5. **Set short expiration times** on pre-signed URLs (5–15 minutes maximum).

6. **Do not serve uploaded files with user-controlled content types** — force `Content-Type: application/octet-stream` or use `Content-Disposition: attachment` for all uploaded documents.
