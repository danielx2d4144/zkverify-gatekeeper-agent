// Independently verify a P2P Alert Guard result without trusting the server:
//   node scripts/verify-proof.js <check_id> [base_url]
// 1) re-checks the Reclaim zkTLS proof (identifier hash, attestor signature, exact Paystack request)
// 2) re-derives the Groth16 public signals from the attested facts and checks they match
// 3) verifies the Groth16 proof against circuits/release_decision_vk.json
const snarkjs = require('snarkjs');
const { verifyReclaimProof } = require('../src/zktls');
const { circuitInput, VK } = require('../src/receipt');
(async () => {
  const [id, base = 'https://p2p-alert-guard.vercel.app'] = process.argv.slice(2);
  const r = await (await fetch(`${base}/api/result?id=${id}`)).json();
  const v = await verifyReclaimProof(r.zktls.proof, r.reference);
  console.log('Reclaim proof:', v.ok ? `VALID (attestor ${v.attestor})` : `INVALID: ${v.why}`);
  if (!v.ok) process.exit(1);
  console.log('Attested by Paystack:', v.fields);
  const ps = r.zkverify.public_signals;
  const inp = circuitInput({ reclaimId: v.identifier, reference: r.reference, expectedKobo: Math.round(r.expected_amount_ngn * 100), paidKobo: v.fields.amount,
    statusOk: v.fields.status === 'success', currencyOk: v.fields.currency === 'NGN', refUnused: ps[8] === '1', liveOk: ps[9] === '1' });
  const expect = [inp.reclaimId, inp.refHash, inp.expectedKobo, inp.paidKobo, inp.statusOk, inp.currencyOk];
  const bound = expect.every((x, i) => ps[i + 2] === x);
  console.log('Public signals bound to this Reclaim proof + claim:', bound);
  const ok = await snarkjs.groth16.verify(VK, ps, r.zkverify.proof);
  console.log('Groth16 decision proof:', ok ? 'VALID' : 'INVALID', '| decision =', ps[0] === '1' ? 'APPROVE_RELEASE' : 'REJECT', '| reasonMask =', ps[1]);
  console.log('zkVerify submission:', JSON.stringify(r.zkverify.submission));
  process.exit(bound && ok ? 0 : 1);
})();
