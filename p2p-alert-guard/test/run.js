// Offline test-suite: real decision logic, real Groth16 circuit, real Reclaim-proof verifier;
// zkFetch is replaced by synthetic proofs signed by a test key that the mocked attestor list trusts.
const assert = require('assert');
const { ethers } = require('ethers');
const sdk = require('@reclaimprotocol/js-sdk');
const realZk = require('../src/zktls');
const { makeGuard, parseNgn } = require('../src/guard');
const { memoryStore } = require('../src/store');

process.env.RECLAIM_APP_ID = '0xtest'; process.env.RECLAIM_APP_SECRET = 'x'; process.env.PAYSTACK_SECRET_KEY = 'sk_test_x';
process.env.MERCHANT_PAYEE = 'demo-merchant'; process.env.ZKFETCH_DAILY_CAP = '6'; delete process.env.KURIER_API_KEY;

const attestor = ethers.Wallet.createRandom();
const rogue = ethers.Wallet.createRandom();
const PAYSTACK = { // what Paystack's verify endpoint returns (shape copied from a real test-mode response)
  'p2pguard-ok-001': { id: 6690787448, status: 'success', amount: 2500000, currency: 'NGN' },
  'p2pguard-ok-002': { id: 6690791111, status: 'success', amount: 5000000, currency: 'NGN' },
  'p2pguard-fail-001': { id: 6690790000, status: 'failed', amount: 1000000, currency: 'NGN' },
  'p2pguard-usd-001': { id: 6690792222, status: 'success', amount: 2500000, currency: 'USD' },
};
const body = (ref, t) => `{"status":true,"message":"Verification successful","data":{"id":${t.id},"domain":"test","status":"${t.status}","reference":"${ref}","receipt_number":null,"amount":${t.amount},"message":null,"gateway_response":"Successful","channel":"card","currency":"${t.currency}","ip_address":"1.2.3.4","metadata":{"note":"\\"amount\\":99900000"}}}`;
function extract(ref, t) {
  const b = body(ref, t); const a = b.match(new RegExp(realZk.MATCH_CORE)); const c = b.match(new RegExp(realZk.MATCH_CCY));
  assert(a && c, 'regex must match the Paystack body'); return { ...a.groups, ...c.groups };
}
async function fakeProof(ref, { signer = attestor, tamper } = {}) {
  const t = PAYSTACK[ref];
  const params = JSON.stringify({ url: realZk.verifyUrl(ref), method: 'GET', headers: { accept: 'application/json' }, responseMatches: [{ type: 'regex', value: realZk.MATCH_CORE }, { type: 'regex', value: realZk.MATCH_CCY }], responseRedactions: [], body: '' });
  const claim = { provider: 'http', parameters: params, context: JSON.stringify({ extractedParameters: extract(ref, t) }), owner: '0x' + '11'.repeat(20), timestampS: 1792837300, epoch: 1 };
  claim.identifier = sdk.getIdentifierFromClaimInfo(claim);
  const sig = await signer.signMessage(sdk.createSignDataForClaim(claim));
  if (tamper) tamper(claim);
  return { claimData: claim, identifier: claim.identifier, signatures: [sig], extractedParameterValues: JSON.parse(claim.context).extractedParameters, witnesses: [] };
}
const fakeFetch = async () => ({ json: async () => ({ data: [{ address: attestor.address }] }) });
let zkCalls = 0; let nextProofOpts = null;
const zktls = { ...realZk,
  precheck: async (ref) => (PAYSTACK[ref] ? { found: true } : { found: false }),
  zkFetchPaystack: async (ref) => { zkCalls++; const o = nextProofOpts; nextProofOpts = null; return fakeProof(ref, o || {}); },
  verifyReclaimProof: (p, r) => realZk.verifyReclaimProof(p, r, { fetchImpl: fakeFetch }),
};

const results = [];
async function t(name, fn) { try { await fn(); results.push(['PASS', name]); } catch (e) { results.push(['FAIL', name + ' :: ' + e.message]); } }

(async () => {
  const store = memoryStore();
  const g = makeGuard({ store, zktls });
  await t('parseNgn handles ₦25,000 / 25000.5 / junk', async () => {
    assert.equal(parseNgn('₦25,000'), 2500000n); assert.equal(parseNgn('25000.5'), 2500050n); assert.equal(parseNgn('abc'), null); assert.equal(parseNgn('-5'), null);
  });
  await t('APPROVE: real success, exact amount', async () => {
    const r = await g.check({ reference: 'p2pguard-ok-001', expected_amount_ngn: 25000, payee: 'demo-merchant', trade_id: 'T1' });
    assert.equal(r.decision, 'APPROVE_RELEASE', JSON.stringify(r.reasons)); assert.equal(r.reason_code, 'OK');
    assert.equal(r.zkverify.public_signals[0], '1'); assert.equal(r.zkverify.public_signals[1], '0');
  });
  await t('idempotent replay: same trade_id gets the same approval, no new zkFetch', async () => {
    const before = zkCalls; const r = await g.check({ reference: 'p2pguard-ok-001', expected_amount_ngn: 25000, trade_id: 'T1' });
    assert.equal(r.decision, 'APPROVE_RELEASE'); assert.equal(r.idempotent_replay, true); assert.equal(zkCalls, before);
  });
  await t('REJECT REFERENCE_REUSED: same alert shown for a second trade (cached proof, no zkFetch)', async () => {
    const before = zkCalls; const r = await g.check({ reference: 'p2pguard-ok-001', expected_amount_ngn: 25000, trade_id: 'T2' });
    assert.equal(r.decision, 'REJECT'); assert.equal(r.reason_code, 'REFERENCE_REUSED'); assert.equal(zkCalls, before);
    assert.equal(r.zkverify.public_signals[1], '8');
  });
  await t('REJECT AMOUNT_MISMATCH: claims ₦500,000 for a ₦50,000 payment (metadata decoy ignored)', async () => {
    const r = await g.check({ reference: 'p2pguard-ok-002', expected_amount_ngn: '500,000', trade_id: 'T3' });
    assert.equal(r.decision, 'REJECT'); assert.equal(r.reason_code, 'AMOUNT_MISMATCH'); assert.equal(r.attested.amount_ngn, 50000);
  });
  await t('amount mismatch does not burn the reference: correct claim later approves', async () => {
    const r = await g.check({ reference: 'p2pguard-ok-002', expected_amount_ngn: 50000, trade_id: 'T3' });
    assert.equal(r.decision, 'APPROVE_RELEASE');
  });
  await t('REJECT NOT_FOUND: fabricated reference from a fake screenshot', async () => {
    const before = zkCalls; const r = await g.check({ reference: 'FAKE-GTB-ALERT-889', expected_amount_ngn: 25000 });
    assert.equal(r.reason_code, 'NOT_FOUND'); assert.equal(zkCalls, before);
  });
  await t('REJECT NOT_SUCCESS: failed card charge', async () => {
    const r = await g.check({ reference: 'p2pguard-fail-001', expected_amount_ngn: 10000 });
    assert.equal(r.reason_code, 'NOT_SUCCESS');
  });
  await t('REJECT CURRENCY_MISMATCH', async () => {
    const r = await g.check({ reference: 'p2pguard-usd-001', expected_amount_ngn: 25000 });
    assert.equal(r.reason_code, 'CURRENCY_MISMATCH');
  });
  await t('REJECT PAYEE_MISMATCH: payment claimed to another merchant', async () => {
    const r = await g.check({ reference: 'p2pguard-ok-001', expected_amount_ngn: 25000, payee: 'someone-else' });
    assert.equal(r.reason_code, 'PAYEE_MISMATCH');
  });
  await t('REJECT INVALID_REQUEST: bad reference / amount', async () => {
    assert.equal((await g.check({ reference: 'x', expected_amount_ngn: 1 })).reason_code, 'INVALID_REQUEST');
    assert.equal((await g.check({ reference: 'p2pguard-ok-001', expected_amount_ngn: 'lots' })).reason_code, 'INVALID_REQUEST');
  });
  await t('verifier rejects a tampered proof (amount edited after signing)', async () => {
    const p = await fakeProof('p2pguard-ok-002', { tamper: (c) => { c.context = c.context.replace('5000000', '9000000'); } });
    const v = await zktls.verifyReclaimProof(p, 'p2pguard-ok-002'); assert.equal(v.ok, false); assert.match(v.why, /identifier/);
  });
  await t('verifier rejects a proof not signed by a Reclaim attestor', async () => {
    const v = await zktls.verifyReclaimProof(await fakeProof('p2pguard-ok-002', { signer: rogue }), 'p2pguard-ok-002'); assert.equal(v.ok, false);
  });
  await t('verifier rejects a valid proof presented for a different reference', async () => {
    const v = await zktls.verifyReclaimProof(await fakeProof('p2pguard-ok-002'), 'p2pguard-ok-001'); assert.equal(v.ok, false); assert.match(v.why, /different request/);
  });
  await t('end-to-end PROOF_INVALID when zkFetch returns a forged proof', async () => {
    const s2 = memoryStore(); const g2 = makeGuard({ store: s2, zktls }); nextProofOpts = { signer: rogue };
    const r = await g2.check({ reference: 'p2pguard-ok-001', expected_amount_ngn: 25000 }); assert.equal(r.reason_code, 'PROOF_INVALID');
  });
  await t('zkFetch budget cap fails closed', async () => {
    process.env.ZKFETCH_DAILY_CAP = '0'; const g3 = makeGuard({ store: memoryStore(), zktls });
    const r = await g3.check({ reference: 'p2pguard-ok-001', expected_amount_ngn: 25000 }); process.env.ZKFETCH_DAILY_CAP = '6';
    assert.equal(r.reason_code, 'PROOF_BUDGET_EXHAUSTED');
  });
  await t('circuit outputs REJECT for a wrong amount (decision is a circuit output, not a prover choice)', async () => {
    const snarkjs = require('snarkjs'); const { circuitInput } = require('../src/receipt');
    const inp = circuitInput({ reclaimId: '0x' + 'ab'.repeat(32), reference: 'p2pguard-ok-002', expectedKobo: 50000000, paidKobo: 5000000, statusOk: true, currencyOk: true, refUnused: true, liveOk: true });
    const { publicSignals } = await snarkjs.groth16.fullProve(inp, 'circuits/release_decision.wasm', 'circuits/release_decision_final.zkey');
    assert.equal(publicSignals[0], '0'); assert.equal(publicSignals[1], '2');
  });
  for (const [s, n] of results) console.log(s, n);
  const failed = results.filter((r) => r[0] === 'FAIL').length;
  console.log(`\n${results.length - failed}/${results.length} passed; synthetic zkFetch calls: ${zkCalls}`);
  process.exit(failed ? 1 : 0);
})();
