# 🛡️ P2P Alert Guard

**Don't release crypto on a fake bank alert.** An agent that checks a Naira payment with Paystack itself, over zkTLS, before a P2P seller releases crypto, and leaves a decision receipt anyone can check on zkVerify.

Entry for the **zkVerify Agent Games 2026, Wildcard track**.

- **Live demo:** https://p2p-alert-guard.vercel.app
- **API:** `POST https://p2p-alert-guard.vercel.app/check` · `GET /health`

---

## The problem

Nigeria runs one of the largest P2P crypto markets in the world. A seller lists USDT, a buyer "pays" in Naira, and the seller releases the crypto from escrow. The most common scam is the **fake credit alert**: an edited bank-app screenshot, a spoofed SMS or e-mail alert, or a real alert for a smaller amount shown with the number changed. Sellers under time pressure (order timers, an angry buyer in chat) release first and find out later. The crypto is gone and the "payment" never existed.

Screenshots prove nothing. The only thing that does is **the payment processor's own record**, and a seller can't easily show that record to a third party (an escrow, an arbiter, a buyer disputing a decision) without handing over their API key or a screenshot of their dashboard, which can be faked just as easily.

## Who it helps

- **P2P merchants and OTC desks** that take Naira through Paystack (payment links, checkout, virtual accounts): one call before every release.
- **P2P bots and escrow agents**: a machine-readable `APPROVE_RELEASE` / `REJECT` with reason codes that an automated release flow can enforce.
- **Arbiters and buyers in a dispute**: an independently checkable proof of what Paystack said and of the decision that followed, without the merchant's secret key.

## What it does

```
buyer's claim ──► POST /check {reference, expected_amount_ngn, trade_id?, payee?}
                     │
                     ├─ reuse guard (Redis): was this reference already used to release crypto?
                     ├─ Reclaim zkFetch ──TLS──► api.paystack.co/transaction/verify/:reference
                     │      (secret key = private header, used inside TLS, never in the proof)
                     ├─ verify the Reclaim proof (attestor signature, exact request, extracted fields)
                     ├─ policy, fail-closed: status=success ∧ amount exact ∧ NGN ∧ reference unused
                     ├─ Groth16 proof that the decision is the policy output for those facts
                     └─ submit the Groth16 proof to zkVerify (Kurier)
                     ▼
        { decision: APPROVE_RELEASE | REJECT, reason_code, attested facts, proofs }
```

### Reason codes

| code | meaning |
|---|---|
| `OK` | Paystack confirms a successful NGN payment of exactly the claimed amount, for this reference, never used before. Release. |
| `NOT_FOUND` | Paystack has no transaction with that reference on the merchant's account (typical of an invented reference on a fake screenshot). |
| `NOT_SUCCESS` | Transaction exists but is `failed`, `abandoned`, `ongoing`, `reversed`… |
| `AMOUNT_MISMATCH` | Paid amount ≠ claimed amount (e.g. paid ₦50,000, alert edited to ₦500,000). |
| `CURRENCY_MISMATCH` | Not NGN. |
| `REFERENCE_REUSED` | This reference already released crypto for another trade (one real alert shown for several orders). |
| `PAYEE_MISMATCH` | Claim names a different payee than the merchant account this guard verifies. |
| `TEST_MODE_PAYMENT` | Paystack test-mode payment while `ALLOW_TEST_MODE=false` (production setting). |
| `PROOF_INVALID` / `PROOF_UNAVAILABLE` / `UPSTREAM_ERROR` / `PROOF_BUDGET_EXHAUSTED` / `INTERNAL_ERROR` / `INVALID_REQUEST` / `NOT_CONFIGURED` | Anything unproven or broken is a **REJECT**. The guard never approves by default. |

A rejected check does not use up the reference: if the buyer mistyped the amount, a correct claim can still be approved. Only an **approval** claims the reference (atomic `SET NX`). Re-checking with the **same** `trade_id` replays the original approval (idempotent), while a different `trade_id` gets `REFERENCE_REUSED`.

## What the proofs establish, and what they don't

There are two proofs, and they say different things.

**1. Reclaim zkTLS proof (zkFetch).** A Reclaim attestor sat in the middle of the TLS session between the guard and `api.paystack.co` and signed a claim that:
- the request was exactly `GET https://api.paystack.co/transaction/verify/<reference>` (headers marked private, here `Authorization: Bearer sk_…`, are **not** in the proof);
- the response from Paystack's server contained `"data":{"id":…,"domain":…,"status":…,"reference":…,"receipt_number":…,"amount":…,` and `"channel":…,"currency":…`, from which `txid, domain (test/live), status, reference, amount, currency` are extracted. All other response bytes (customer e-mail, card BIN/last4, IP) are redacted.

The regex is anchored to the start of Paystack's `data` object and fixes field order, so a buyer-controlled field later in the body (e.g. `metadata` containing `"amount":99900000`) can't be matched instead. The test suite has this decoy case.

Anyone can re-verify it: `identifier == keccak256(provider, parameters, context)`, signature recovers to an address in Reclaim's attestor list (`api.reclaimprotocol.org/api/attestors`), and the parameters are the expected request and matchers. See `src/zktls.js → verifyReclaimProof` and `scripts/verify-proof.js`.

**2. Groth16 decision receipt (verified on zkVerify).** `circuits/release_decision.circom` (147 wires) takes as **public** signals:
`reclaimId` (first 248 bits of the Reclaim claim identifier), `refHash` (first 248 bits of sha256(reference)), `expectedKobo`, `paidKobo`, `statusOk`, `currencyOk`, `refUnused`, `liveOk`. It **outputs** `decision` and a `reasonMask` (1 NOT_SUCCESS, 2 AMOUNT_MISMATCH, 4 CURRENCY_MISMATCH, 8 REFERENCE_REUSED, 16 TEST_MODE). The decision is a circuit *output*: a prover can't get a valid proof of `decision=1` with a wrong amount or a non-success status. The proof goes to zkVerify through Kurier, which gives a public, timestamped on-chain record of the decision tied to one specific Reclaim proof.

**What this adds up to:** given the published result, a third party can check that (a) Paystack's own API returned those facts for that reference, and (b) the APPROVE/REJECT is exactly the published policy applied to those facts, with the verification recorded on zkVerify so it can't be quietly rewritten later.

**What it does not prove (honest limits):**
- **zkVerify does not verify the Reclaim proof itself.** Reclaim claims are attestor ECDSA signatures, and there is no documented zkVerify verifier for them today. The link between the two proofs is the `reclaimId` public signal, which a verifier checks off-chain (`scripts/verify-proof.js`). The circuit proves "correct decision for these facts", not "these facts came from Paystack". The Reclaim proof covers that second part.
- **`statusOk` / `currencyOk` are 0/1 flags fed in by the guard**, not string comparisons done inside the circuit. A verifier re-derives them from the Reclaim proof's extracted values (the verify script does this).
- **`refUnused` comes from the guard's own Redis.** It shows the guard's view of reuse, not a global one. Two different guards could each approve the same reference once.
- **Whose Paystack account?** The proof shows Paystack answered a request authorised by *some* secret key. That the key belongs to the seller follows from the setup (the seller runs, or is, the guard), not from the proof.
- **Trust model:** Reclaim's proxy-attestor model assumes the attestor doesn't collude with the prover. The Groth16 setup uses the public PSE Perpetual Powers of Tau (`ppot_0080_12.ptau`) for phase 1 and a single-party phase 2 plus beacon. Fine for a demo; production would run a multi-party phase 2.
- **Coverage:** only payments received through the merchant's Paystack account. Direct bank transfers to a personal account need a bank/aggregator API (Mono, Okra, a bank's statement API). The same zkFetch pattern applies.
- **Paystack's attestor can only sign 2xx responses**, so `NOT_FOUND` (HTTP 400) is decided from a plain HTTPS call and carries no zk proof. It's a REJECT, which is the safe direction.

## API

`POST /check`
```json
{ "reference": "p2pguard-ok-001", "expected_amount_ngn": 25000, "trade_id": "order-1234", "payee": "optional" }
```
Response (trimmed; add `?full=1` for the full proofs inline, or fetch `GET /api/result?id=<check_id>`):
```json
{
  "check_id": "chk_…", "decision": "APPROVE_RELEASE", "reason_code": "OK", "reasons": [],
  "attested": { "status": "success", "amount_ngn": 25000, "currency": "NGN", "mode": "test", "txid": "6690787448", "reference": "p2pguard-ok-001" },
  "zktls":   { "provider": "Reclaim zkFetch", "identifier": "0x…", "attestor": "0x…", "request": "GET https://api.paystack.co/transaction/verify/p2pguard-ok-001" },
  "zkverify":{ "circuit": "release_decision (Groth16/BN254)", "public_signals": ["1","0","…"], "submission": { "status": "submitted", "jobId": "…" } }
}
```
`GET /api/zkverify?id=<check_id>` polls the zkVerify job (Submitted → IncludedInBlock → Finalized, with tx hash).
`GET /health` shows configuration, store, and zkFetch usage.
`POST /api/demo-payment` (test keys only) creates a fresh Paystack **test-mode** payment with Paystack's public test card, so judges can try a reference that has never been used.

## Run it

```bash
cd p2p-alert-guard
npm install
npm test                      # 17 offline tests: real policy, real circuit, real proof verifier
cp .env.example .env          # fill in keys, then:
node --env-file=.env src/server.js   # http://localhost:3000
node scripts/verify-proof.js <check_id>   # independent verification of a live result
```

Environment: `PAYSTACK_SECRET_KEY`, `RECLAIM_APP_ID`, `RECLAIM_APP_SECRET`, `UPSTASH_REDIS_REST_URL`/`TOKEN` (or `KV_REST_API_URL`/`TOKEN`), optional `KURIER_API_KEY` (zkVerify testnet via Kurier), `MERCHANT_PAYEE`, `ALLOW_TEST_MODE` (set `false` in production), `ZKFETCH_DAILY_CAP`, `ZKFETCH_MONTHLY_CAP`, `STORE_PREFIX` (default `p2p:`).

Rebuild the circuit: `npx circom2 circuits/release_decision.circom --r1cs --wasm -l node_modules`, then `snarkjs groth16 setup` with `ppot_0080_12.ptau`.

## Tests

`npm test` runs offline. zkFetch is replaced by synthetic Reclaim claims signed by a test key that a mocked attestor list trusts. Everything else is real: policy, Redis-style store semantics, Groth16 proving and verification, and the Reclaim proof verifier. It covers approval, idempotent replay, reuse, amount mismatch (with a metadata decoy), a mismatch not burning the reference, not found, not success, currency, payee, bad input, tampered proof, non-attestor signer, proof for another reference, forged proof end-to-end, budget cap, and the circuit computing REJECT for a wrong amount.

## Deployment

Vercel Hobby (serverless Node 24, 60 s max), free Upstash Redis, Reclaim free tier (zkFetch calls are capped per day and month, and proofs are cached per reference, so re-checks cost nothing), Kurier testnet. $0 total.

## Files

- `src/guard.js`: decision engine (fail-closed)
- `src/zktls.js`: zkFetch call and independent Reclaim-proof verification
- `src/receipt.js`: Groth16 decision proof and zkVerify (Kurier) submission
- `src/store.js`: Upstash Redis / in-memory store (prefixed keys)
- `src/http.js`, `api/*.js`: HTTP handlers (Vercel functions); `src/server.js` for local
- `circuits/`: circom source, wasm, zkey, verification key
- `public/index.html`: demo page
- `scripts/verify-proof.js`: third-party verifier
