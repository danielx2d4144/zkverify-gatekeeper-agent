// Storage for the proof-reuse set and per-task response cache.
// Uses Upstash Redis (REST) when its env vars are set (Vercel), otherwise a JSON file in DATA_DIR.
const fs = require('fs');
const path = require('path');

function redisStore(url, token) {
  const cmd = async (...args) => {
    const r = await fetch(url, { method: 'POST', headers: { authorization: `Bearer ${token}` }, body: JSON.stringify(args) });
    const j = await r.json();
    if (j.error) throw new Error('redis: ' + j.error);
    return j.result;
  };
  return {
    kind: 'redis',
    getSeen: (tx) => cmd('GET', `gk:seen:${tx}`),
    // SET NX so two concurrent tasks can't both claim one proof_tx.
    claimSeen: async (tx, id) => (await cmd('SET', `gk:seen:${tx}`, id, 'NX')) === 'OK' || (await cmd('GET', `gk:seen:${tx}`)) === id,
    getResponse: async (id) => { const v = await cmd('GET', `gk:resp:${id}`); return v ? JSON.parse(v) : null; },
    putResponse: (id, out) => cmd('SET', `gk:resp:${id}`, JSON.stringify(out)),
  };
}

function fileStore(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'state.json');
  let s = { seen: {}, responses: {} };
  try { s = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {}
  const save = () => { fs.writeFileSync(file + '.tmp', JSON.stringify(s)); fs.renameSync(file + '.tmp', file); };
  return {
    kind: 'file',
    getSeen: async (tx) => s.seen[tx] || null,
    claimSeen: async (tx, id) => { if (!s.seen[tx]) { s.seen[tx] = id; save(); } return s.seen[tx] === id; },
    getResponse: async (id) => s.responses[id] || null,
    putResponse: async (id, out) => { s.responses[id] = out; save(); },
  };
}

function makeStore() {
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
  if (url && token) return redisStore(url, token);
  return fileStore(process.env.DATA_DIR || (process.env.VERCEL ? '/tmp/gk-data' : path.join(__dirname, '../data')));
}
module.exports = { makeStore };
