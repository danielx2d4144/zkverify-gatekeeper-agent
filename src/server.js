const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { decide } = require('./decide');
const { prove } = require('./prove');

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const PORT = Number(process.env.PORT || 8080);
const AGENT_PATH = process.env.AGENT_PATH || '/agent';
const DATA = process.env.DATA_DIR || path.join(__dirname, '../data');
fs.mkdirSync(DATA, { recursive: true });
const STATE = path.join(DATA, 'state.json');

// Persistent seen-set (proof_tx -> task_id) and response cache (task_id -> body) for idempotent retries.
let state = { seen: {}, responses: {} };
try { state = JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch {}
const save = () => { fs.writeFileSync(STATE + '.tmp', JSON.stringify(state)); fs.renameSync(STATE + '.tmp', STATE); };

const secretKey = () => (/^[0-9a-f]{64}$/i.test(SECRET) && process.env.SECRET_IS_HEX !== '0') ? Buffer.from(SECRET, 'hex') : Buffer.from(SECRET);
const hmac = (buf, key) => crypto.createHmac('sha256', key).update(buf).digest();
function verifySig(raw, header) {
  if (!SECRET || !header) return false;
  const h = String(header).replace(/^sha256=/i, '').trim();
  for (const key of [secretKey(), Buffer.from(SECRET)]) {
    const d = hmac(raw, key);
    for (const enc of [d.toString('hex'), d.toString('base64')]) {
      if (enc.length === h.length && crypto.timingSafeEqual(Buffer.from(enc), Buffer.from(h))) { usedKey = key; return true; }
    }
  }
  return false;
}
let usedKey = null;
function send(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  const sig = hmac(body, usedKey || secretKey()).toString('hex');
  res.writeHead(status, { 'content-type': 'application/json', 'x-agent-games-signature': (process.env.SIG_PREFIX || '') + sig });
  res.end(body);
}
const log = (...a) => console.log(new Date().toISOString(), ...a);

async function handle(msg) {
  if (msg.type === 'agent-games.preflight.v1') return { ok: true, protocolVersion: 'v1' };
  if (msg.type !== 'agent-games.proof-gatekeeper.v1') return { error: 'unsupported_type' };
  const id = msg.task_id;
  if (id && state.responses[id]) return state.responses[id]; // retry: same answer
  const input = msg.input || {};
  const tx = String(input.proof_tx || '').trim().toLowerCase();
  const d = decide(input, (t) => state.seen[t] && state.seen[t] !== id);
  const out = { decision: d.decision, reason_code: d.reason_code };
  if (input.proof_tx) out.proof_tx = input.proof_tx;
  if (d.reason_code !== 'PROOF_REUSED' && d.reason_code !== 'MALFORMED_INPUT') {
    try { Object.assign(out, await prove(id, input, d.decision === 'APPROVE')); }
    catch (e) {
      // The circuit refuses a wrong decision; if our call disagrees with it, fail closed to REJECT.
      log('prove failed', id, e.message);
      if (d.decision === 'APPROVE') { out.decision = 'REJECT'; out.reason_code = 'CIRCUIT_DISAGREES';
        try { Object.assign(out, await prove(id, input, false)); } catch (e2) { log('reject proof failed', e2.message); } }
    }
  }
  if (tx && !state.seen[tx]) state.seen[tx] = id;
  if (id) state.responses[id] = out;
  save();
  log('task', id, out.decision, out.reason_code);
  return out;
}

http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/health' || req.url === '/')) { res.writeHead(200, {'content-type':'application/json'}); return res.end('{"ok":true}'); }
  if (req.method !== 'POST' || req.url.split('?')[0] !== AGENT_PATH) { res.writeHead(404); return res.end(); }
  const chunks = []; let size = 0;
  req.on('data', c => { size += c.length; if (size > 1e6) req.destroy(); else chunks.push(c); });
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    if (!verifySig(raw, req.headers['x-agent-games-signature'])) { log('bad signature'); return send(res, 401, { error: 'bad_signature' }); }
    let msg; try { msg = JSON.parse(raw.toString('utf8')); } catch { return send(res, 400, { error: 'bad_json' }); }
    const timer = setTimeout(() => { if (!res.writableEnded) send(res, 200, { decision: 'REJECT', reason_code: 'TIMEOUT_FAIL_CLOSED', proof_tx: msg?.input?.proof_tx }); }, 50000);
    try { const out = await handle(msg); clearTimeout(timer); if (!res.writableEnded) send(res, 200, out); }
    catch (e) { clearTimeout(timer); log('error', e.message); if (!res.writableEnded) send(res, 200, { decision: 'REJECT', reason_code: 'INTERNAL_FAIL_CLOSED' }); }
  });
}).listen(PORT, () => log(`gatekeeper agent on :${PORT}${AGENT_PATH}${SECRET ? '' : ' (WARNING: AGENT_GAMES_HMAC_SECRET not set)'}`));
