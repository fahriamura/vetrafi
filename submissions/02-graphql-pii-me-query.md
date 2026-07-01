# Finding 2: Full PII Exposure via Me Query and Complete GraphQL API Surface Enumeration from Client-Side JS Bundles

**Severity:** Medium  
**Asset:** api.vetrafi.com  
**Category:** Information Disclosure  
**Reward Band:** $3,000–$5,000

---

## Summary

The VetraFi GraphQL API (`api.vetrafi.com/graphql`) exposes a `me` query that returns extensive Personally Identifiable Information (PII) including full name, phone number, complete home and mailing addresses, and military service details. Additionally, the **entire GraphQL API surface — 30+ queries and mutations — can be enumerated from client-side JavaScript bundles** with zero authentication required. This gives attackers a complete roadmap of every backend operation without needing to guess or brute-force endpoint names.

## Finding Description

### Full PII in the `me` Query

The `Me` query, extracted from client-side JS bundles, reveals the following response structure:

```graphql
query Me {
  me {
    id
    email
    firstName
    lastName
    primaryPhoneNumber
    militaryVerificationStatus
    militaryBranch
    militaryStatus
    dateOfEntry
    payGrade
    addressLine1
    addressLine2
    addressCity
    addressState
    addressZip
    addressCountry
    mailingSameAsHome
    mailingAddressLine1
    mailingAddressLine2
    mailingCity
    mailingState
    mailingZip
    mailingCountry
  }
}
```

**PII categories exposed once authenticated:**
| Category | Fields |
|----------|--------|
| Identity | firstName, lastName, email |
| Contact | primaryPhoneNumber |
| Home Address | addressLine1, addressLine2, addressCity, addressState, addressZip, addressCountry |
| Mailing Address | mailingAddressLine1, mailingAddressLine2, mailingCity, mailingState, mailingZip, mailingCountry |
| Military Service | militaryBranch, militaryStatus, dateOfEntry, payGrade, militaryVerificationStatus |

### Complete API Surface Enumeration

The following 30+ operations were extracted from client-side JavaScript bundles without any server interaction:

**Authentication (4):**
- `SignIn(email: String!, password: String!) → { token }`
- `SignUp(email: String!, password: String!, termsAccepted: Boolean!) → { token }`
- `ResetPassword(email: String!) → { message, success }`
- `Me → { 23 fields of PII }`

**Profile (4):**
- `UpdateName(input: UpdateNameInput!) → { message, success }`
- `UpdateHomeAddress(input: UpdateAddressInfoInput!) → { message, success }`
- `UpdateOnboardingSection(input: UpdateOnboardingSectionInput!) → { success, message }`
- `VerifyUserPhoneNumber / SubmitUserPhoneNumberCode(input) → { success, message }`

**Military/Veterans Affairs (4):**
- `UpdateMilitaryInfo(input: UpdateMilitaryInfoInput!) → { message, needDocument, success }`
- `UpdateExistingMilitaryProfile(input) → { success, message }`
- `GetVeteransAffairsAuthorizationUrl(platform: AppPlatform!) → { url }`
- `ExchangeVeteransAffairsAuthorizationCode(input) → { success, message }`

**Banking/Plaid (14):**
- `GetPlaidLinkToken(input) → { linkToken, expiration, isUpdateMode }`
- `ExchangePlaidPublicToken(input) → { success, linkedAccounts, institutionName }`
- `GetPlaidItems → { ... }`
- `GetPlaidItemDetails(itemId: ID!) → { id, institutionName, accounts { id, name, type, subtype, mask, balance { available, current } } }`
- `GetMultiplePlaidItemDetails(itemIds: [ID!]!) → [{ ... }]`
- `GetPlaidInstitutionByPlaidId(input) → { institutionId, name, logo, url, routingNumber }`
- `RemovePlaidItem(input) → { success, message }`
- `UpdatePlaidAccountsForItem(input) → { success, message }`
- `CheckIfInstitutionIsConnected(input) → { isConnected }`
- `GetAvailableAccounts, GetExternalAccountIds, GetExternalTransactionSums`
- `GetMonthlySpendingOverview, GetNetWorthHistory, GetNetWorthSummary`

**Goals/Savings (13):**
- `CreateGoal, UpdateGoal, UpdateGoalArchivedAt, DeleteGoal`
- `CreateManyGoals, UpdateManyGoals`
- `GetAllGoals, GetActivitiesForGoal, GetGoalSnapshotsForDateRange`
- `UpdateSavingsPoolAccounts, GetSavingsPoolBalance`
- `UpdateOrCreateBudget, GetBudget, GetWeeklyBudgetSpending`

**Tax (3):**
- `AprilAuthCodeQuery(input) → { userAccessToken, userAuthCode }`
- `QueryTaxDeadlines, QueryUserTaxhub`

**File Upload (1):**
- `generateUploadUrl(input: GenerateUploadUrlInput!) → { preSignedUrl, documentURL }`

## Impact Explanation

1. **PII Aggregation:** The `me` query returns 23 fields of PII covering identity, contact, full address (home and mailing), and military service details. If an attacker gains access to any user session (via XSS, session hijacking, or token theft), they can exfiltrate the complete user profile with a single GraphQL query.

2. **Attack Surface Map:** The complete API enumeration from client-side JS gives attackers a ready-made attack surface map. Every mutation and query name, its input parameters, and its return types are documented without needing:
   - Brute-force endpoint discovery
   - GraphQL introspection queries (which are disabled on the server)
   - Reverse-engineering network traffic

3. **Tax Auth Code Exposure:** The `AprilAuthCodeQuery` mutation returns `userAccessToken` and `userAuthCode` — tokens that likely grant access to the April Tax Solutions platform. If these are long-lived tokens, an attacker with a valid session could access the user's tax filing data on a third-party platform.

4. **Veterans Affairs Integration:** The VA authorization mutations suggest VetraFi communicates with VA systems. The `GetVeteransAffairsAuthorizationUrl` and `ExchangeVeteransAffairsAuthorizationCode` mutations handle OAuth-like flows for VA data access.

## Likelihood Explanation

**Medium** — The PII exposure requires the attacker to first obtain a valid user session token (e.g., via XSS, phishing, or session hijacking). However, the complete API enumeration requires no authentication — it's static in publicly served JavaScript files. The tax auth code exposure is particularly noteworthy as it could enable account takeovers on connected third-party platforms.

## Proof of Concept

### 1. Extract GraphQL Operations from JS Bundles
```bash
# Download the main app layout JS chunk
curl -s "https://app.vetrafi.com/_next/static/chunks/app/layout-8455ea0eb07ed5fd.js?dpl=dpl_GUvMDsDgJdmAoAkau4bMeyXh8rsp" \
  | grep -oP '(query|mutation) \w+\([^)]*\)[\s\S]{0,200}?\}' \
  | head -40
```
Expected: All 30+ GraphQL operations appear in the output.

### 2. Verify the `me` Query Exists (Unauthenticated)
```bash
curl -s "https://api.vetrafi.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ me { id email } }"}'
```
Expected: `{"errors":[{"message":"Access denied! You need to be authenticated...","extensions":{"code":"UNAUTHENTICATED"}}]}`

This confirms the `me` query exists and requires auth, but the error message itself reveals it's a valid endpoint.

### 3. Verify GraphQL Endpoint is Live
```bash
curl -s "https://api.vetrafi.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'
```
Expected: `{"data":{"__typename":"Query"}}`

### 4. Extract Query Names Only
```bash
curl -s "https://app.vetrafi.com/_next/static/chunks/app/layout-8455ea0eb07ed5fd.js?dpl=dpl_GUvMDsDgJdmAoAkau4bMeyXh8rsp" \
  | grep -oP '(query|mutation) \w+' \
  | sort -u
```

## Recommendation

1. **Do not embed full GraphQL operation signatures in client-side JS bundles.** Use code splitting and dynamic imports to surface only the operations needed for the current page.

2. **Implement rate limiting and anomaly detection** on the `me` query to detect bulk PII exfiltration (e.g., multiple `me` queries in rapid succession).

3. **Review `AprilAuthCodeQuery`** — ensure `userAccessToken` and `userAuthCode` are short-lived and scoped to minimal permissions.

4. **Review `GetVeteransAffairsAuthorizationCode`** — ensure the VA OAuth tokens have appropriate expiry and scope restrictions.

5. **Consider obfuscating operation names** in production builds, or use persisted operations (e.g., Apollo persisted queries) to prevent schema enumeration from client bundles.
