// State: seen references (reuse guard), cached zkTLS proofs, check records, zkFetch budget.
// Upstash Redis REST when configured (Vercel), otherwise in-memory (tests / local dev).
// All keys are prefixed (default "p2p:") so a Redis DB can be shared with other apps.
const PREFIX = process.env.STORE_PREFIX || 'p2p:';

function redisStore(url, token) {
  const cmd = async (...args) => {
    const r = await fetch(url, { method: 'POST', headers: { authorization: `Bearer ${token}` }, body: JSON.stringify(args) });
    const j = await r.json();
    if (j.error) throw new Error('redis: ' + j.error);
    return j.result;
  };
  const getJ = async (k) => { const v = await cmd('GET', PREFIX + k); return v ? JSON.parse(v) : null; };
  return {
    kind: 'redis',
    get: getJ,
    set: (k, v, ttlSec) => ttlSec ? cmd('SET', PREFIX + k, JSON.stringify(v), 'EX', ttlSec) : cmd('SET', PREFIX + k, JSON.stringify(v)),
    // atomic claim: returns true only for the first writer
    claim: async (k, v) => (await cmd('SET', PREFIX + k, JSON.stringify(v), 'NX')) === 'OK',
    incr: async (k, ttlSec) => { const n = await cmd('INCR', PREFIX + k); if (n === 1 && ttlSec) await cmd('EXPIRE', PREFIX + k, ttlSec); return n; },
    decr: (k) => cmd('DECR', PREFIX + k),
    ping: async () => (await cmd('PING')) === 'PONG',
  };
}

function memoryStore() {
  const m = new Map();
  const live = (k) => { const e = m.get(k); if (!e) return null; if (e.exp && e.exp < Date.now()) { m.delete(k); return null; } return e; };
  return {
    kind: 'memory',
    get: async (k) => { const e = live(k); return e ? JSON.parse(e.v) : null; },
    set: async (k, v, ttl) => { m.set(k, { v: JSON.stringify(v), exp: ttl ? Date.now() + ttl * 1000 : 0 }); },
    claim: async (k, v) => { if (live(k)) return false; m.set(k, { v: JSON.stringify(v), exp: 0 }); return true; },
    incr: async (k, ttl) => { const e = live(k); const n = (e ? Number(JSON.parse(e.v)) : 0) + 1; m.set(k, { v: String(n), exp: e ? e.exp : (ttl ? Date.now() + ttl * 1000 : 0) }); return n; },
    decr: async (k) => { const e = live(k); const n = (e ? Number(JSON.parse(e.v)) : 0) - 1; m.set(k, { v: String(n), exp: e ? e.exp : 0 }); return n; },
    ping: async () => true,
  };
}

let singleton;
function makeStore() {
  if (singleton) return singleton;
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
  singleton = url && token ? redisStore(url, token) : memoryStore();
  return singleton;
}
module.exports = { makeStore, memoryStore };
