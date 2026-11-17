import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, HOLD, FORTIFY, EXTRACT } from '../src/policy.mjs';
import { publicInputsHash, idempotencyKey, holdWithoutProof } from '../src/steal.mjs';

const st = (selfBalance, opponentBalance) => ({ selfBalance: BigInt(selfBalance), opponentBalance: BigInt(opponentBalance) });

test('policy branches mirror the circuit: fortify-below, extract-above, else hold', () => {
  const p = [7n, 50n, 30n, 0n, 0n, 0n, 0n, 0n];
  assert.deepEqual(decide(p, st(49, 100)), { action: FORTIFY, amount: 0n });
  assert.deepEqual(decide(p, st(50, 31)), { action: EXTRACT, amount: 7n });
  assert.deepEqual(decide(p, st(50, 30)), { action: HOLD, amount: 0n });
  assert.deepEqual(decide([7n, 0n, 0n, 1n, 0n, 0n, 0n, 0n], st(100, 100)), { action: HOLD, amount: 0n });
});

test('publicInputsHash packs eight 32-byte words in the documented order', () => {
  const h = publicInputsHash({ commitment: 5n, matchId: '9f4e1b2a-0000-4000-8000-000000000001', turn: 3, selfBalance: 95n, opponentBalance: 105n, action: 2n, amount: 10n });
  assert.match(h, /^0x[0-9a-f]{64}$/);
  assert.notEqual(h, publicInputsHash({ commitment: 5n, matchId: '9f4e1b2a-0000-4000-8000-000000000001', turn: 4, selfBalance: 95n, opponentBalance: 105n, action: 2n, amount: 10n }));
});

test('idempotency key is stable per turn and differs across turns', () => {
  assert.equal(idempotencyKey('m', 1), idempotencyKey('m', 1));
  assert.notEqual(idempotencyKey('m', 1), idempotencyKey('m', 2));
  assert.match(idempotencyKey('m', 1), /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('fallback HOLD omits action.amount entirely', () => {
  const r = holdWithoutProof({ matchId: '9f4e1b2a-0000-4000-8000-000000000001', turn: 2, mode: 'practice', state: { selfBalance: '100', opponentBalance: '100' } });
  assert.deepEqual(r.action, { type: 'HOLD' });
  assert.equal(r.turn, 2);
  assert.equal(r.protocolVersion, 'v1');
  assert.match(r.policyProof.publicInputsHash, /^0x[0-9a-f]{64}$/);
  assert.equal(r.policyProof.proof, undefined);
});
