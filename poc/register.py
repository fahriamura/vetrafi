"""
VetraFi - Register test account and save JWT token
"""
import urllib.request
import urllib.error
import json
import base64
import time
import sys

API_TARGET = "https://api.vetrafi.com/graphql"

# Generate unique email
timestamp = int(time.time())
email = f"vetrabug{timestamp}@mailinator.com"
password = "VetraAdmin123!!"

print("[*] Registering test account...")
print(f"[*] Email: {email}")
print(f"[*] Password: {password}")

query = """
mutation SignUp($email: String!, $password: String!, $termsAccepted: Boolean!) {
  signUp(email: $email, password: $password, termsAccepted: $termsAccepted) {
    token
  }
}
"""

variables = {
    "email": email,
    "password": password,
    "termsAccepted": True
}

data = json.dumps({"query": query, "variables": variables}).encode()
req = urllib.request.Request(
    API_TARGET,
    data=data,
    headers={
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
)

try:
    resp = urllib.request.urlopen(req, timeout=15)
    body = json.loads(resp.read())
    
    token = body.get("data", {}).get("signUp", {}).get("token")
    if token:
        print("\n[SUCCESS] Account created!")
        print(f"Token: {token[:50]}...")
        
        # Save token
        with open("/root/vetrafi_token.txt", "w") as f:
            f.write(token)
        print(f"\n[+] Token saved to /root/vetrafi_token.txt")
        
        # Decode JWT
        parts = token.split(".")
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        decoded = json.loads(base64.b64decode(padded))
        print(f"\n[+] JWT Payload:")
        print(json.dumps(decoded, indent=2))
    else:
        print(f"\n[ERROR] No token in response:")
        print(json.dumps(body, indent=2))
        
except urllib.error.HTTPError as e:
    print(f"\n[HTTP ERROR] {e.code}: {e.read().decode()[:300]}")
except Exception as e:
    print(f"\n[ERROR] {e}")
