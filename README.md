# VetraFi - Bug Bounty Findings

**Target:** VetraFi (https://app.vetrafi.com, https://api.vetrafi.com)  
**Bounty:** https://cantina.xyz/bounties/ba65a579-761a-4d63-adb9-01d6cfdf319d  
**Total Reward Pool:** $8,000  
**Submissions So Far:** 112  

---

## Reconnaissance Summary

### Tech Stack
| Component | Technology |
|-----------|-----------|
| Frontend | Next.js (Vercel) |
| API Backend | Express.js (Render) |
| GraphQL | Apollo Client + Apollo Server |
| Auth | JWT-based (token in mutation response) |
| Analytics | Google Analytics, Google Ads, Facebook Pixel, PostHog, GTM |
| Banking | Plaid (Link + Exchange) |
| File Upload | S3 pre-signed URLs |
| Tax Filing | April Tax Solutions |
| WAF | Cloudflare (API only) |
| CDN | Vercel Edge Network |

### GraphQL API Surface (30+ Operations Enumerated from Client-Side JS)

**Auth:** `SignIn`, `SignUp`, `ResetPassword`, `Me`  
**Profile:** `UpdateName`, `UpdateHomeAddress`, `UpdateOnboardingSection`, `VerifyUserPhoneNumber`, `SubmitUserPhoneNumberCode`  
**Military:** `UpdateMilitaryInfo`, `UpdateExistingMilitaryProfile`, `ExchangeVeteransAffairsAuthorizationCode`, `GetVeteransAffairsAuthorizationUrl`  
**Plaid/Banking:** `GetPlaidLinkToken`, `ExchangePlaidPublicToken`, `GetPlaidItems`, `GetPlaidItemDetails`, `GetMultiplePlaidItemDetails`, `GetPlaidInstitutionByPlaidId`, `RemovePlaidItem`, `UpdatePlaidAccountsForItem`, `CheckIfInstitutionIsConnected`, `GetAvailableAccounts`, `GetExternalAccountIds`, `GetExternalTransactionSums`, `GetMonthlySpendingOverview`, `GetNetWorthHistory`, `GetNetWorthSummary`  
**Goals/Budget:** `CreateGoal`, `UpdateGoal`, `DeleteGoal`, `CreateManyGoals`, `UpdateManyGoals`, `UpdateGoalArchivedAt`, `GetAllGoals`, `GetActivitiesForGoal`, `GetGoalSnapshotsForDateRange`, `UpdateOrCreateBudget`, `GetBudget`, `GetWeeklyBudgetSpending`, `GetEssentialSpendingRecommendations`  
**Savings:** `UpdateSavingsPoolAccounts`, `GetSavingsPoolBalance`  
**Tax:** `AprilAuthCodeQuery`, `QueryTaxDeadlines`, `QueryUserTaxhub`  
**Upload:** `generateUploadUrl`  

---

## 5 Unique Findings

| # | Finding | Severity | Asset |
|---|---------|----------|-------|
| 1 | **No CSP + Wildcard CORS on FinTech Banking App** | **High** | app.vetrafi.com |
| 2 | **Full PII Exposure via Me Query + GraphQL Surface Enumeration** | **Medium** | api.vetrafi.com |
| 3 | **S3 Pre-signed Upload URL Generation for Military Documents** | **Medium** | api.vetrafi.com |
| 4 | **Potential IDOR in Plaid Account Operations** | **Medium** | api.vetrafi.com |
| 5 | **Next.js Stale Cache Set to Maximum (4294967294)** | **Low** | app.vetrafi.com |

---

## Submission Files

| File | Finding |
|------|---------|
| [`submissions/01-no-csp-cors-banking.md`](./submissions/01-no-csp-cors-banking.md) | No CSP + Wildcard CORS on FinTech Banking App |
| [`submissions/02-graphql-pii-me-query.md`](./submissions/02-graphql-pii-me-query.md) | Full PII Exposure via Me Query + GraphQL Surface Enumeration |
| [`submissions/03-s3-upload-military-docs.md`](./submissions/03-s3-upload-military-docs.md) | S3 Pre-signed Upload URL Generation for Military Documents |
| [`submissions/04-plaid-idor-accounts.md`](./submissions/04-plaid-idor-accounts.md) | Potential IDOR in Plaid Account Operations |
| [`submissions/05-nextjs-stale-cache-max.md`](./submissions/05-nextjs-stale-cache-max.md) | Next.js Stale Cache Set to Maximum (4294967294) |

---

## PoC Scripts

| File | Description |
|------|-------------|
| [`poc/cors_origin_test.py`](./poc/cors_origin_test.py) | Test wildcard CORS on app.vetrafi.com |
| [`poc/graphql_recon.py`](./poc/graphql_recon.py) | GraphQL surface enumeration + Me query PII exposure |
| [`poc/upload_url_test.py`](./poc/upload_url_test.py) | Generate upload URL and test S3 bucket permissions |
| [`poc/plaid_idor_test.py`](./poc/plaid_idor_test.py) | IDOR testing on Plaid item/account queries |
| [`poc/cache_headers_test.py`](./poc/cache_headers_test.py) | Verify stale cache headers |

---

## How to Reproduce

Each `submissions/*.md` file is a complete Cantina submission. Copy the contents to the Cantina submission form and attach screenshots of the PoC script output.
