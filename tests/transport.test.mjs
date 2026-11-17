import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { handle, kind } from '../src/handler.mjs';

const secret = 'test-only-hmac-secret-never-use-in-a-deployment';
const now = Date.parse('2026-10-28T16:00:00Z');
const hmac = (raw, key) => createHmac('sha256', key).update(raw).digest();
const call = (payload, { key = secret, fmt = b => b.toString('hex'), handlers, raw } = {}) => {
  raw ??= Buffer.from(JSON.stringify(payload));
  return handle(raw, fmt(hmac(raw, key)), { secret, handlers, now, log: () => {} });
};
const preflight = { type: 'agent-games.preflight.v1', agent_id: 'agt_x', issued_at: new Date(now).toISOString(), nonce: 'abc123' };

test('signed preflight returns the documented body, signed over the raw response', async () => {
  const r = await call(preflight);
  assert.equal(r.status, 200);
  assert.deepEqual(JSON.parse(r.body), { ok: true, protocolVersion: 'v1' });
  assert.equal(r.headers['x-agent-games-signature'], hmac(r.body, secret).toString('hex'));
});

test('sha256= prefixed and base64 signatures are accepted and mirrored', async () => {
  const r1 = await call(preflight, { fmt: b => `sha256=${b.toString('hex')}` });
  assert.equal(r1.headers['x-agent-games-signature'], `sha256=${hmac(r1.body, secret).toString('hex')}`);
  const r2 = await call(preflight, { fmt: b => b.toString('base64') });
  assert.equal(r2.headers['x-agent-games-signature'], hmac(r2.body, secret).toString('base64'));
});

test('hex secret used as decoded bytes is accepted', async () => {
  const hexSecret = 'a'.repeat(64);
  const raw = Buffer.from(JSON.stringify(preflight));
  const r = await handle(raw, hmac(raw, Buffer.from(hexSecret, 'hex')).toString('hex'), { secret: hexSecret, now, log: () => {} });
  assert.equal(r.status, 200);
  assert.equal(r.headers['x-agent-games-signature'], hmac(r.body, Buffer.from(hexSecret, 'hex')).toString('hex'));
});

test('wrong key or tampered body is rejected before parsing', async () => {
  assert.equal((await call(preflight, { key: 'some-other-secret-value-xxxxxxxx' })).status, 401);
  const raw = Buffer.from('{not json');
  assert.equal((await handle(raw, hmac('{}', secret).toString('hex'), { secret, now, log: () => {} })).status, 401);
});

test('stale envelopes are refused', async () => {
  assert.equal((await call({ ...preflight, issued_at: new Date(now - 3_600_000).toISOString() })).status, 400);
});

test('routing by envelope shape', () => {
  assert.equal(kind({ type: 'agent-games.proof-gatekeeper.v1' }), 'gatekeeper');
  assert.equal(kind({ eventId: 'steal-the-vfy', matchId: 'm', turn: 1 }), 'steal');
  assert.equal(kind({ matchId: 'm', turn: 0 }), 'steal');
  assert.equal(kind({ type: 'other' }), 'unknown');
});

test('handler output is returned signed', async () => {
  const handlers = { steal: async e => ({ matchId: e.matchId, turn: e.turn, action: { type: 'HOLD' } }) };
  const r = await call({ eventId: 'steal-the-vfy', matchId: 'm1', turn: 3, issuedAt: new Date(now).toISOString() }, { handlers });
  assert.equal(r.status, 200);
  assert.deepEqual(JSON.parse(r.body), { matchId: 'm1', turn: 3, action: { type: 'HOLD' } });
});
