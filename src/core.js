// Transport-independent agent: verify HMAC on the raw body, decide, prove, sign the reply.
const crypto = require('crypto');
const { decide } = require('./decide');
const { prove } = require('./prove');
const { makeStore } = require('./store');

const store = makeStore();
const log = (...a) => console.log(new Date().toISOString(), ...a);
const secret = () => process.env.AGENT_GAMES_HMAC_SECRET || '';
const keys = () => {
  const s = secret();
  const hex = /^[0-9a-f]{64}$/i.test(s) && process.env.SECRET_IS_HEX !== '0';
  return hex ? [Buffer.from(s, 'hex'), Buffer.from(s)] : [Buffer.from(s)];
};
const hmac = (buf, key) => crypto.createHmac('sha256', key).update(buf).digest();

function verifySig(raw, header) {
  if (!secret() || !header) return null;
  const h = String(header).replace(/^sha256=/i, '').trim();
  for (const key of keys()) {
    const d = hmac(raw, key);
    for (const enc of [d.toString('hex'), d.toString('base64')]) {
      if (enc.length === h.length && crypto.timingSafeEqual(Buffer.from(enc), Buffer.from(h))) return key;
    }
  }
  return null;
}
function reply(status, obj, key) {
  const body = Buffer.from(JSON.stringify(obj));
  const sig = (process.env.SIG_PREFIX || '') + hmac(body, key || keys()[0]).toString('hex');
  return { status, body, headers: { 'content-type': 'application/json', 'x-agent-games-signature': sig } };
}

async function handle(msg) {
  if (msg.type === 'agent-games.preflight.v1') return { ok: true, protocolVersion: 'v1' };
  if (msg.type !== 'agent-games.proof-gatekeeper.v1') return { error: 'unsupported_type' };
  const id = msg.task_id;
  if (id) { const cached = await store.getResponse(id); if (cached) return cached; } // retry: same answer
  const input = msg.input || {};
  const tx = String(input.proof_tx || '').trim().toLowerCase();
  const owner = tx ? await store.getSeen(tx) : null;
  const d = decide(input, () => !!owner && owner !== id);
  const out = { decision: d.decision, reason_code: d.reason_code };
  if (input.proof_tx) out.proof_tx = input.proof_tx;
  if (tx && d.reason_code !== 'PROOF_REUSED' && !(await store.claimSeen(tx, id))) {
    out.decision = 'REJECT'; out.reason_code = 'PROOF_REUSED'; // lost a race to a concurrent task
  }
  if (out.reason_code !== 'PROOF_REUSED' && out.reason_code !== 'MALFORMED_INPUT') {
    try { Object.assign(out, await prove(id, input, out.decision === 'APPROVE')); }
    catch (e) {
      // The circuit refuses a wrong decision; if our call disagrees with it, fail closed to REJECT.
      log('prove failed', id, e.message);
      if (out.decision === 'APPROVE') {
        out.decision = 'REJECT'; out.reason_code = 'CIRCUIT_DISAGREES';
        try { Object.assign(out, await prove(id, input, false)); } catch (e2) { log('reject proof failed', e2.message); }
      }
    }
  }
  if (id) await store.putResponse(id, out);
  log('task', id, out.decision, out.reason_code);
  return out;
}

// raw: Buffer of the exact request body; sigHeader: x-agent-games-signature value.
async function handleRaw(raw, sigHeader) {
  const key = verifySig(raw, sigHeader);
  if (!key) { log('bad signature'); return reply(401, { error: 'bad_signature' }); }
  let msg; try { msg = JSON.parse(raw.toString('utf8')); } catch { return reply(400, { error: 'bad_json' }, key); }
  const failClosed = { decision: 'REJECT', reason_code: 'TIMEOUT_FAIL_CLOSED', proof_tx: msg?.input?.proof_tx };
  const limit = Number(process.env.FAIL_CLOSED_MS || 50000);
  try {
    const out = await Promise.race([handle(msg), new Promise(r => setTimeout(() => r(failClosed), limit).unref?.())]);
    return reply(200, out, key);
  } catch (e) { log('error', e.message); return reply(200, { decision: 'REJECT', reason_code: 'INTERNAL_FAIL_CLOSED' }, key); }
}
module.exports = { handleRaw, store };
