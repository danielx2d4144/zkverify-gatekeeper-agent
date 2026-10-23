// Replays every documented trap against a running agent, signed like the platform.
const crypto = require('crypto');
const URL_ = process.env.AGENT_URL || 'http://localhost:8080/agent';
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
const key = /^[0-9a-f]{64}$/i.test(SECRET) ? Buffer.from(SECRET, 'hex') : Buffer.from(SECRET);
const base = { registered_vk: '0x7d3a00f291', proof_vk: '0x7d3a00f291', minimum: '1000', public_balance: '1460', expiry_block: 8430000, current_block: 8420000,
  recipient: '0xDe42000000000000000000000000000000009f01', condition_recipient: '0xde42000000000000000000000000000000009f01', amount: '500', max_transfer: '1000' };
const cases = [
  ['VALID_CONDITION', 'APPROVE', {}],
  ['VK_SUBSTITUTION', 'REJECT', { proof_vk: '0xa4c1b8ff' }],
  ['THRESHOLD_MISMATCH', 'REJECT', { public_balance: '999' }],
  ['EXPIRED_CONDITION', 'REJECT', { current_block: 8430000 }],
  ['RECIPIENT_MISMATCH', 'REJECT', { recipient: '0xBad0000000000000000000000000000000000001' }],
  ['AMOUNT_OVERFLOW', 'REJECT', { amount: '1001' }],
  ['VALID_EDGE (balance==min, amount==cap)', 'APPROVE', { public_balance: '1000', amount: '1000' }],
];
async function post(body) {
  const raw = Buffer.from(JSON.stringify(body));
  const r = await fetch(URL_, { method: 'POST', headers: { 'content-type': 'application/json', 'x-agent-games-signature': crypto.createHmac('sha256', key).update(raw).digest('hex') }, body: raw });
  const txt = await r.text(); const sigOk = r.headers.get('x-agent-games-signature') === crypto.createHmac('sha256', key).update(txt).digest('hex');
  return { status: r.status, body: JSON.parse(txt), sigOk };
}
(async () => {
  let pass = 0, n = 0; const t = (ok, msg) => { n++; if (ok) pass++; console.log(ok ? 'PASS' : 'FAIL', msg); };
  const pf = await post({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc' });
  t(pf.body.ok === true && pf.body.protocolVersion === 'v1' && pf.sigOk, 'preflight signed');
  const bad = await fetch(URL_, { method: 'POST', headers: { 'x-agent-games-signature': 'deadbeef' }, body: '{}' }); t(bad.status === 401, 'rejects bad signature');
  const run = Date.now();
  for (const [i, [name, want, over]] of cases.entries()) {
    const t0 = Date.now();
    const r = await post({ type: 'agent-games.proof-gatekeeper.v1', task_id: `gk_${run}_${i}`, mode: 'practice', input: { ...base, ...over, proof_tx: `0x${run.toString(16)}${i}` } });
    t(r.body.decision === want && r.sigOk && Array.isArray(r.body.public_signals) && r.body.proof, `${name} -> ${r.body.decision}/${r.body.reason_code} proof:${!!r.body.proof} ${Date.now() - t0}ms`);
  }
  const reuse = await post({ type: 'agent-games.proof-gatekeeper.v1', task_id: `gk_${run}_reuse`, input: { ...base, proof_tx: `0x${run.toString(16)}0` } });
  t(reuse.body.decision === 'REJECT' && reuse.body.reason_code === 'PROOF_REUSED', `PROOF_REUSED -> ${reuse.body.decision}/${reuse.body.reason_code}`);
  const retry = await post({ type: 'agent-games.proof-gatekeeper.v1', task_id: `gk_${run}_0`, input: { ...base, proof_tx: `0x${run.toString(16)}0` } });
  t(retry.body.decision === 'APPROVE', 'retry of same task_id is idempotent (not flagged as reuse)');
  console.log(`\n${pass}/${n} passed`); process.exit(pass === n ? 0 : 1);
})();
