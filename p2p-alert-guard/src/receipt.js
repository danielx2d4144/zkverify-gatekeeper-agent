// zkVerify receipt: a Groth16 proof (circuits/release_decision.circom) that the published
// decision is exactly what the release policy outputs for the facts taken from one Reclaim proof.
// Submitted to zkVerify through Kurier when KURIER_API_KEY is set.
const path = require('path');
const crypto = require('crypto');
const snarkjs = require('snarkjs');

const WASM = path.join(__dirname, '../circuits/release_decision.wasm');
const ZKEY = path.join(__dirname, '../circuits/release_decision_final.zkey');
const VK = require('../circuits/release_decision_vk.json');
const MASK = { 1: 'NOT_SUCCESS', 2: 'AMOUNT_MISMATCH', 4: 'CURRENCY_MISMATCH', 8: 'REFERENCE_REUSED', 16: 'TEST_MODE_PAYMENT' };

// 248-bit truncation keeps values inside the BN254 field.
const f248 = (hex) => BigInt('0x' + hex.replace(/^0x/, '').padStart(64, '0').slice(0, 62)).toString();
const refHash = (ref) => f248(crypto.createHash('sha256').update(String(ref)).digest('hex'));

function circuitInput({ reclaimId, reference, expectedKobo, paidKobo, statusOk, currencyOk, refUnused, liveOk }) {
  return {
    reclaimId: f248(reclaimId), refHash: refHash(reference),
    expectedKobo: String(expectedKobo), paidKobo: String(paidKobo),
    statusOk: statusOk ? '1' : '0', currencyOk: currencyOk ? '1' : '0',
    refUnused: refUnused ? '1' : '0', liveOk: liveOk ? '1' : '0',
  };
}

async function proveDecision(facts) {
  const input = circuitInput(facts);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  // publicSignals order: [decision, reasonMask, reclaimId, refHash, expectedKobo, paidKobo, statusOk, currencyOk, refUnused, liveOk]
  const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
  if (!ok) throw new Error('local groth16 verify failed');
  const mask = Number(publicSignals[1]);
  return {
    proof, publicSignals, input,
    decision: publicSignals[0] === '1' ? 'APPROVE_RELEASE' : 'REJECT',
    reasons: Object.entries(MASK).filter(([b]) => mask & Number(b)).map(([, n]) => n),
  };
}

const KURIER = () => process.env.KURIER_API_URL || 'https://api-testnet.kurier.xyz/api/v1';

async function registerVk(apiKey) {
  const r = await fetch(`${KURIER()}/register-vk/${apiKey}`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ proofType: 'groth16', proofOptions: { library: 'snarkjs', curve: 'bn128' }, vk: VK }),
  });
  const j = await r.json();
  return j.vkHash || (j.meta && j.meta.vkHash) || null;
}

async function submitToZkVerify(groth, store) {
  const apiKey = process.env.KURIER_API_KEY;
  if (!apiKey) return { status: 'not_configured' };
  let vkHash = process.env.KURIER_VK_HASH || (store && (await store.get('kurier:vkhash')));
  if (!vkHash) { vkHash = await registerVk(apiKey); if (vkHash && store) await store.set('kurier:vkhash', vkHash); }
  const body = vkHash
    ? { proofType: 'groth16', vkRegistered: true, proofOptions: { library: 'snarkjs', curve: 'bn128' }, proofData: { proof: groth.proof, publicSignals: groth.publicSignals, vk: vkHash } }
    : { proofType: 'groth16', vkRegistered: false, proofOptions: { library: 'snarkjs', curve: 'bn128' }, proofData: { proof: groth.proof, publicSignals: groth.publicSignals, vk: VK } };
  const r = await fetch(`${KURIER()}/submit-proof/${apiKey}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.jobId) return { status: 'submit_failed', http: r.status, error: j.message || j.error || null };
  return { status: 'submitted', jobId: j.jobId, optimisticVerify: j.optimisticVerify, vkHash };
}

async function jobStatus(jobId) {
  const apiKey = process.env.KURIER_API_KEY;
  if (!apiKey) return { status: 'not_configured' };
  const r = await fetch(`${KURIER()}/job-status/${apiKey}/${encodeURIComponent(jobId)}`);
  const j = await r.json().catch(() => ({}));
  return { status: j.status || 'unknown', txHash: j.txHash || null, blockHash: j.blockHash || null, updatedAt: j.updatedAt || null };
}

module.exports = { proveDecision, submitToZkVerify, jobStatus, circuitInput, refHash, f248, VK };
