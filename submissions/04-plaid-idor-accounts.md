# Finding 4: Potential Insecure Direct Object Reference (IDOR) in Plaid Banking Account Operations

**Severity:** Medium  
**Asset:** api.vetrafi.com  
**Category:** Insecure Direct Object Reference / Authorization Bypass  
**Reward Band:** $3,000–$5,000

---

## Summary

The VetraFi GraphQL API exposes multiple queries and mutations for managing Plaid-connected bank accounts. Of particular concern are `GetPlaidItemDetails(itemId: ID!)` and `GetMultiplePlaidItemDetails(itemIds: [ID!]!)`, which accept numeric `itemId` parameters to retrieve detailed bank account information including account numbers, balances, and institution details. If authorization is not properly enforced on these queries, an authenticated user could enumerate other users' Plaid-connected bank accounts.

## Finding Description

### Exposed Plaid Operations

The following Plaid-related GraphQL operations were found in client-side JS bundles:

```graphql
# Retrieve full details of a connected bank account item
query GetPlaidItemDetails($itemId: ID!) {
  getPlaidItemDetails(itemId: $itemId) {
    id
    institutionName
    institutionId
    logo
    createdAt
    updatedAt
    connectionStatus
    accounts {
      id
      name
      officialName
      type
      subtype
      mask
      balance {
        available
        current
        isoCurrencyCode
      }
    }
  }
}

# Batch retrieve multiple items
query GetMultiplePlaidItemDetails($itemIds: [ID!]!) {
  getMultiplePlaidItemDetails(itemIds: $itemIds) {
    id
    institutionName
    institutionId
    logo
    createdAt
    updatedAt
    connectionStatus
    accounts {
      id
      name
      officialName
      type
      subtype
      mask
      balance {
        available
        current
        isoCurrencyCode
      }
    }
  }
}

# Check if an institution is connected
query CheckIfInstitutionIsConnected($input: CheckIfInstitutionIsConnectedInput!) {
  checkIfInstitutionIsConnected(input: $input) {
    isConnected
  }
}

# Update which accounts are associated with a connected item
mutation UpdatePlaidAccountsForItem($input: UpdatePlaidAccountsForItemInput!) {
  updatePlaidAccountsForItem(input: $input) {
    success
    message
  }
}

# Remove a Plaid connection entirely
mutation RemovePlaidItem($input: RemovePlaidItemInput!) {
  removePlaidItem(input: $input) {
    success
    message
  }
}
```

### Potential IDOR Vectors

1. **Sequential/Guessable `itemId`:** If Plaid item IDs are sequential integers (1, 2, 3, ...) or follow a predictable pattern, an attacker can enumerate other users' connected bank accounts by iterating through IDs.

2. **Lack of Ownership Validation:** If `getPlaidItemDetails` does not verify the requesting user owns the item, an attacker could read:
   - Bank names and account types
   - Account masks (last 4 digits)
   - Current and available balances
   - Connection status and timestamps

3. **Mass Enumeration via Batch Query:** The `GetMultiplePlaidItemDetails` query accepts an array of IDs, making mass enumeration trivially efficient.

4. **Connected Institution Probing:** `CheckIfInstitutionIsConnected` could be used to determine whether other users bank at specific institutions.

5. **Account Removal:** `RemovePlaidItem` without proper authorization could allow attackers to disconnect other users' bank accounts.

## Impact Explanation

For a FinTech application, Plaid-connected bank accounts represent the most sensitive user data:
- **Financial surveillance:** Knowing a user's bank balances and transaction patterns
- **Institution fingerprinting:** Knowing which banks a user banks with
- **Account takeover:** Combined with other attacks, knowing account masks facilitates social engineering
- **Denial of service:** Malicious removal of Plaid connections disrupts budget tracking, savings goals, and net worth calculations

If item IDs are enumerable and authorization is missing, an attacker could:
1. Iterate through item IDs
2. Collect account masks and balances for thousands of users
3. Identify high-net-worth individuals for targeted attacks
4. Disconnect bank accounts at scale

## Likelihood Explanation

**Medium** — The likelihood depends on:
1. Whether Plaid item IDs are guessable (sequential, UUID, or hashed)
2. Whether authorization checks are implemented on each query
3. Whether rate limiting exists on the GraphQL endpoint

The batch query (`GetMultiplePlaidItemDetails`) makes this particularly dangerous if IDs are guessable, as thousands of IDs can be checked in a single request.

### ID Format Assessment

If the `itemId` is a simple integer (e.g., from a PostgreSQL `SERIAL PRIMARY KEY`), enumeration is trivial. If it's a UUID, enumeration is infeasible but the authorization check is still important.

## Proof of Concept

### 1. Verify GraphQL Endpoint and Check for Auth
```bash
# Try to enumerate Plaid items with test IDs
for itemId in 1 2 3 100 1000 10000; do
  result=$(curl -s "https://api.vetrafi.com/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer [YOUR_TOKEN]" \
    -d "{\"query\":\"{ getPlaidItemDetails(itemId: $itemId) { id institutionName accounts { name mask balance { current } } } }\"}")
  
  # Check if response contains actual data (not just errors)
  if echo "$result" | grep -q '"data":{[^}]*"getPlaidItemDetails"'; then
    echo "[PASS] Item $itemId returned data!"
    echo "$result"
  else
    echo "[INFO] Item $itemId: $(echo "$result" | grep -oP '"message":"[^"]*"')"
  fi
done
```

### 2. Check ID Pattern
```bash
# If you have access to your own Plaid item ID, check its format
# UUID (e.g., "a1b2c3d4-...") = harder to enumerate
# Integer (e.g., 42) or base64-encoded integer = enumerable
```

## Recommendation

1. **Implement ownership validation on ALL Plaid queries and mutations** — verify the requesting user's session owns the `itemId` before returning data or performing actions.

2. **Use UUIDs for item IDs** instead of sequential integers. If using PostgreSQL, use `gen_random_uuid()` as default.

3. **Rate limit the GraphQL endpoint** to prevent mass enumeration:
   - Per-user rate limits (e.g., 100 queries/minute)
   - Per-IP rate limits
   - Anomaly detection for bulk data access

4. **Remove the batch query** (`GetMultiplePlaidItemDetails`) or restrict it to only return items owned by the requesting user.

5. **Log and alert** on access patterns that suggest enumeration (e.g., sequential item ID access across different users).

6. **Implement database-level Row-Level Security (RLS)** to ensure users can only access their own Plaid items, even if application-level checks are bypassed.
