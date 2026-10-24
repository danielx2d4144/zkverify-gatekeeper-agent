// Shared HTTP helpers for the Vercel functions and the local server.
const { makeGuard } = require('./guard');
const { makeStore } = require('./store');
const { jobStatus } = require('./receipt');

let guard;
const getGuard = () => (guard ||= makeGuard({ store: makeStore() }));
const send = (res, code, obj) => { res.statusCode = code; res.setHeader('content-type', 'application/json'); res.setHeader('access-control-allow-origin', '*'); res.end(JSON.stringify(obj, null, 2)); };
async function readJson(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') return JSON.parse(req.body || '{}');
  const chunks = []; for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}
const slim = (r) => { // default response omits the bulky proof objects; ?full=1 includes them
  if (!r || !r.zktls) return r;
  const { proof, ...zk } = r.zktls; const { proof: gp, ...zv } = r.zkverify || {};
  return { ...r, zktls: { ...zk, proof_url: `/api/result?id=${r.check_id}` }, zkverify: { ...zv, proof_url: `/api/result?id=${r.check_id}` } };
};

async function handleCheck(req, res) {
  if (req.method === 'OPTIONS') { res.setHeader('access-control-allow-headers', 'content-type'); return send(res, 204, {}); }
  if (req.method !== 'POST') return send(res, 405, { error: 'POST JSON {reference, expected_amount_ngn, payee?, trade_id?}' });
  let body; try { body = await readJson(req); } catch { return send(res, 400, { decision: 'REJECT', reason_code: 'INVALID_REQUEST', detail: 'body must be JSON' }); }
  try {
    const out = await getGuard().check(body);
    const full = /[?&]full=1/.test(req.url || '');
    return send(res, 200, full ? out : slim(out));
  } catch (e) {
    console.error('check failed', e && e.message); // never log secrets
    return send(res, 200, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR', detail: 'fail-closed: ' + String(e.message || e).slice(0, 160) });
  }
}

async function handleHealth(req, res) {
  const store = makeStore();
  let storeOk = false; try { storeOk = await store.ping(); } catch {}
  const day = new Date().toISOString().slice(0, 10);
  let used = null; try { used = { today: Number((await store.get(`zk:day:${day}`)) || 0), month: Number((await store.get(`zk:month:${day.slice(0, 7)}`)) || 0) }; } catch {}
  let reclaimApp = null; try { const m = await import('./zkfetch.mjs'); reclaimApp = await m.appRegistered(process.env.RECLAIM_APP_ID || ''); } catch {}
  send(res, 200, {
    ok: true, service: 'p2p-alert-guard', version: '1.0.0', node: process.version, store: store.kind, store_ok: storeOk,
    configured: { paystack: !!process.env.PAYSTACK_SECRET_KEY, reclaim: !!(process.env.RECLAIM_APP_ID && process.env.RECLAIM_APP_SECRET), zkverify_kurier: !!process.env.KURIER_API_KEY, reclaim_app_zkfetch_enabled: reclaimApp },
    merchant_payee: process.env.MERCHANT_PAYEE || null, test_mode_allowed: (process.env.ALLOW_TEST_MODE || 'true') === 'true',
    zkfetch_used: used, zkfetch_caps: { daily: Number(process.env.ZKFETCH_DAILY_CAP || 10), monthly: Number(process.env.ZKFETCH_MONTHLY_CAP || 60) },
  });
}

async function handleResult(req, res) {
  const id = new URL(req.url, 'http://x').searchParams.get('id') || '';
  if (!/^chk_[0-9a-f]{16}$/.test(id)) return send(res, 400, { error: 'id required' });
  const r = await makeStore().get(`check:${id}`);
  if (!r) return send(res, 404, { error: 'not found' });
  send(res, 200, r);
}

async function handleZkVerify(req, res) {
  const u = new URL(req.url, 'http://x');
  const id = u.searchParams.get('id') || '';
  const store = makeStore();
  const r = /^chk_[0-9a-f]{16}$/.test(id) ? await store.get(`check:${id}`) : null;
  const job = r && r.zkverify && r.zkverify.submission && r.zkverify.submission.jobId;
  if (!job) return send(res, 404, { error: 'no zkVerify job for this check' });
  const st = await jobStatus(job);
  if (st.status && st.status !== 'unknown') { r.zkverify.submission = { ...r.zkverify.submission, ...st, checkedAt: new Date().toISOString() }; await store.set(`check:${id}`, r, 30 * 86400); }
  send(res, 200, { check_id: id, jobId: job, ...st, explorer: st.txHash ? `https://zkverify-testnet.subscan.io/extrinsic/${st.txHash}` : null });
}

// Demo helper: makes a fresh Paystack TEST-mode payment with Paystack's public test card so judges
// can try a brand-new reference. Refuses unless the key is a test key. Capped per day.
async function handleDemoPayment(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'POST {amount_ngn, outcome: "success"|"failed"}' });
  const key = process.env.PAYSTACK_SECRET_KEY || '';
  if (!key.startsWith('sk_test_') || process.env.DEMO_PAYMENTS === 'false') return send(res, 403, { error: 'demo payments disabled' });
  let b = {}; try { b = await readJson(req); } catch {}
  const amount = Math.round(Number(b.amount_ngn || 25000));
  if (!(amount >= 100 && amount <= 1000000)) return send(res, 400, { error: 'amount_ngn 100..1,000,000' });
  const store = makeStore(); const day = new Date().toISOString().slice(0, 10);
  if ((await store.incr(`demo:pay:${day}`, 2 * 86400)) > Number(process.env.DEMO_PAYMENTS_DAILY_CAP || 25)) return send(res, 429, { error: 'demo payment cap reached for today' });
  const failed = b.outcome === 'failed';
  const reference = `p2pdemo-${Date.now().toString(36)}-${require('crypto').randomBytes(3).toString('hex')}`;
  const card = failed ? { number: '4084080000005408', cvv: '001', expiry_month: '12', expiry_year: '2030' } : { number: '4084084084084081', cvv: '408', expiry_month: '12', expiry_year: '2030' };
  const r = await fetch('https://api.paystack.co/charge', { method: 'POST', headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' }, body: JSON.stringify({ email: 'p2p-demo-buyer@example.com', amount: String(amount * 100), reference, card }) });
  const j = await r.json().catch(() => ({}));
  send(res, 200, { reference, amount_ngn: amount, paystack_status: j.data && j.data.status, mode: j.data && j.data.domain, note: 'Paystack test mode, public test card; no real money moved' });
}

module.exports = { handleDemoPayment, handleCheck, handleHealth, handleResult, handleZkVerify, send };
