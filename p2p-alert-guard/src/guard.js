// P2P Alert Guard core: decide whether a P2P seller may release crypto for a claimed Naira payment.
// Deterministic, fail-closed. The only APPROVE path is: a Reclaim zkTLS proof of Paystack's own
// verify endpoint shows status=success, the exact expected amount in NGN, the claimed reference,
// and the reference has never been used to approve another trade.
const crypto = require('crypto');
const zktlsDefault = require('./zktls');
const receiptDefault = require('./receipt');

const cfg = () => ({
  appId: process.env.RECLAIM_APP_ID,
  appSecret: process.env.RECLAIM_APP_SECRET,
  secretKey: process.env.PAYSTACK_SECRET_KEY,
  payee: (process.env.MERCHANT_PAYEE || '').trim().toLowerCase(),
  allowTest: (process.env.ALLOW_TEST_MODE || 'true') === 'true',
  dailyCap: Number(process.env.ZKFETCH_DAILY_CAP || 10),
  monthlyCap: Number(process.env.ZKFETCH_MONTHLY_CAP || 60),
});

const FINAL = new Set(['success', 'failed', 'reversed']);

function parseNgn(v) {
  const s = String(v ?? '').replace(/[₦,\s]/g, '').replace(/^NGN/i, '');
  if (!/^\d+(\.\d{1,2})?$/.test(s)) return null;
  const [n, d = ''] = s.split('.');
  const kobo = BigInt(n) * 100n + BigInt((d + '00').slice(0, 2));
  return kobo > 0n && kobo < 2n ** 63n ? kobo : null;
}

function makeGuard({ store, zktls = zktlsDefault, receipt = receiptDefault, now = () => Date.now() } = {}) {
  async function getProof(reference, c) {
    const cached = await store.get(`proof:${reference}`);
    if (cached) return { proof: cached, cached: true };
    const pre = await zktls.precheck(reference, c.secretKey);
    if (pre.error) return { reject: 'UPSTREAM_ERROR', detail: pre.error };
    if (!pre.found) return { reject: 'NOT_FOUND', detail: 'Paystack has no transaction with this reference on this merchant account' };
    const day = new Date(now()).toISOString().slice(0, 10);
    const month = day.slice(0, 7);
    const d = await store.incr(`zk:day:${day}`, 2 * 86400);
    const m = await store.incr(`zk:month:${month}`, 40 * 86400);
    if (d > c.dailyCap || m > c.monthlyCap) {
      await store.decr(`zk:day:${day}`); await store.decr(`zk:month:${month}`);
      return { reject: 'PROOF_BUDGET_EXHAUSTED', detail: 'zkTLS proof quota for this demo is used up; try again later' };
    }
    let proof;
    try { proof = await zktls.zkFetchPaystack(reference, c); }
    catch (e) {
      const msg = String(e.message || e);
      // failed before reaching Reclaim's attestor: don't count it against the quota
      if (/not registered|application secret|does not match/i.test(msg)) { await store.decr(`zk:day:${day}`); await store.decr(`zk:month:${month}`); }
      return { reject: 'PROOF_UNAVAILABLE', detail: 'zkFetch failed: ' + msg.slice(0, 200) };
    }
    return { proof, cached: false, fresh: true };
  }

  async function check(body) {
    const c = cfg();
    const t0 = now();
    const checkId = 'chk_' + crypto.randomBytes(8).toString('hex');
    const reference = String(body.reference || '').trim();
    const expectedKobo = parseNgn(body.expected_amount_ngn ?? body.amount);
    const tradeId = String(body.trade_id || checkId).slice(0, 80);
    const base = { check_id: checkId, reference, expected_amount_ngn: expectedKobo != null ? Number(expectedKobo) / 100 : null, trade_id: tradeId };
    const done = async (out) => {
      const res = { ...base, ...out, checked_at: new Date(t0).toISOString(), ms: now() - t0 };
      await store.set(`check:${checkId}`, res, 30 * 86400);
      return res;
    };
    const reject = (code, detail, extra = {}) => done({ decision: 'REJECT', reason_code: code, reasons: [code], detail, ...extra });

    if (!zktls.REF_RE.test(reference)) return reject('INVALID_REQUEST', 'reference must be 6-100 chars of A-Z a-z 0-9 . _ = -');
    if (expectedKobo == null) return reject('INVALID_REQUEST', 'expected_amount_ngn must be a positive Naira amount (max 2 decimals)');
    if (body.payee && c.payee && String(body.payee).trim().toLowerCase() !== c.payee)
      return reject('PAYEE_MISMATCH', `this guard only verifies payments received by merchant "${c.payee}"`);
    if (!c.secretKey || !c.appId || !c.appSecret) return reject('NOT_CONFIGURED', 'server is missing Paystack/Reclaim credentials');

    const used = await store.get(`used:${reference}`);
    if (used && used.trade_id === tradeId) {
      const prev = await store.get(`check:${used.check_id}`);
      if (prev) return { ...prev, idempotent_replay: true };
    }

    const got = await getProof(reference, c);
    if (got.reject) return reject(got.reject, got.detail);
    const v = await zktls.verifyReclaimProof(got.proof, reference);
    if (!v.ok) return reject('PROOF_INVALID', v.why);
    const f = v.fields;
    if (f.reference !== reference) return reject('PROOF_INVALID', 'attested reference differs from the claim');
    if (got.fresh) await store.set(`proof:${reference}`, got.proof, FINAL.has(f.status) ? undefined : 600);

    const facts = {
      reclaimId: v.identifier, reference, expectedKobo: expectedKobo.toString(), paidKobo: String(f.amount),
      statusOk: f.status === 'success', currencyOk: f.currency === 'NGN',
      refUnused: !used, liveOk: f.domain === 'live' || c.allowTest,
    };
    let groth = await receipt.proveDecision(facts);
    let usedBy = used;
    if (groth.decision === 'APPROVE_RELEASE') {
      const won = await store.claim(`used:${reference}`, { trade_id: tradeId, check_id: checkId, at: new Date(t0).toISOString() });
      if (!won) { usedBy = await store.get(`used:${reference}`); groth = await receipt.proveDecision({ ...facts, refUnused: false }); }
    }
    let zkv = { status: 'not_configured' };
    try { zkv = await receipt.submitToZkVerify(groth, store); } catch (e) { zkv = { status: 'submit_failed', error: String(e.message || e).slice(0, 160) }; }

    const reasons = groth.reasons;
    const detailBy = {
      NOT_SUCCESS: `Paystack status is "${f.status}", not "success"`,
      AMOUNT_MISMATCH: `paid ₦${(Number(f.amount) / 100).toLocaleString('en-NG')} but claim says ₦${(Number(expectedKobo) / 100).toLocaleString('en-NG')}`,
      CURRENCY_MISMATCH: `payment currency is ${f.currency}, expected NGN`,
      REFERENCE_REUSED: `reference already released crypto for trade ${usedBy ? usedBy.trade_id : '?'}`,
      TEST_MODE_PAYMENT: 'payment was made in Paystack test mode',
    };
    return done({
      decision: groth.decision,
      reason_code: groth.decision === 'APPROVE_RELEASE' ? 'OK' : reasons[0],
      reasons: groth.decision === 'APPROVE_RELEASE' ? [] : reasons,
      detail: groth.decision === 'APPROVE_RELEASE' ? 'Paystack itself confirms this exact payment; safe to release' : reasons.map((r) => detailBy[r]).join('; '),
      attested: { ...f, amount_ngn: Number(f.amount) / 100, mode: f.domain },
      zktls: { provider: 'Reclaim zkFetch', identifier: v.identifier, attestor: v.attestor, timestampS: v.timestampS, cached: !!got.cached, request: `GET ${zktls.verifyUrl(reference)}`, proof: got.proof },
      zkverify: { circuit: 'release_decision (Groth16/BN254)', public_signals: groth.publicSignals, proof: groth.proof, submission: zkv },
    });
  }
  return { check };
}

module.exports = { makeGuard, parseNgn };
