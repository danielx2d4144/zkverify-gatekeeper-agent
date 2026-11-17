import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateStatement } from '../src/gatekeeper.mjs';

const hex = (n, bytes) => `0x${BigInt(n).toString(16).padStart(bytes * 2, '0')}`;
export const validInput = {
  registered_vk: hex(123,32), proof_vk: hex(123,32),
  minimum: '1000', public_balance: '1460', expiry_block: 200, current_block: 100,
  recipient: hex(456,20), condition_recipient: hex(456,20),
  amount: '500', max_transfer: '1000', proof_tx: hex(789,32),
};

for (const [name, patch, expected] of [
  ['valid condition', {}, 'VALID_PROOF'],
  ['wrong verification key', { proof_vk: hex(124,32) }, 'VK_SUBSTITUTION'],
  ['balance below minimum', { public_balance: '999' }, 'THRESHOLD_MISMATCH'],
  ['expired', { current_block: 201 }, 'EXPIRED_CONDITION'],
  ['expiry equality (official circuit boundary)', { current_block: 200 }, 'EXPIRED_CONDITION'],
  ['wrong recipient', { recipient: hex(457,20) }, 'RECIPIENT_MISMATCH'],
  ['amount above cap', { amount: '1001' }, 'AMOUNT_OVERFLOW'],
  ['balance equals threshold and amount equals cap', { public_balance: '1000', amount: '1000' }, 'VALID_PROOF'],
]) {
  test(name, () => assert.equal(evaluateStatement({ ...validInput, ...patch }).reason_code, expected));
}
test('accepted proof replay rejects', () => {
  assert.equal(evaluateStatement(validInput, new Set([validInput.proof_tx])).reason_code, 'PROOF_REPLAY');
});
test('integer comparisons retain precision above Number.MAX_SAFE_INTEGER', () => {
  assert.equal(evaluateStatement({ ...validInput, minimum: '9007199254740993', public_balance: '9007199254740992' }).decision, 'REJECT');
});
for (const invalid of ['-1', '1.5', '1e3', ' 1000', '0x10', '18446744073709551616', Number.MAX_SAFE_INTEGER + 1, null]) {
  test(`reject malformed or unsafe integer ${invalid}`, () => assert.throws(() => evaluateStatement({ ...validInput, minimum: invalid })));
}
test('missing proof reference rejects rather than approving incomplete evidence', () => {
  const input = { ...validInput }; delete input.proof_tx;
  assert.throws(() => evaluateStatement(input));
});


test('gatekeeper task: proof for valid and trap decisions, replay gets no proof', async () => {
  const { witnessFor } = await import('../src/gatekeeper-task.mjs');
  const { proveGatekeeper } = await import('../src/proofs.mjs');
  const env = { task_id: 'gk_8d31_test', input: { ...validInput, registered_vk: `0x${'6b'.repeat(32)}`, proof_vk: `0x${'6b'.repeat(32)}` } };
  const ok = await proveGatekeeper(witnessFor(env, true));
  assert.equal(ok.public_signals[11], '1');
  const trap = { ...env, input: { ...env.input, current_block: 200 } };
  assert.equal((await proveGatekeeper(witnessFor(trap, false))).public_signals[11], '0');
  await assert.rejects(proveGatekeeper(witnessFor(trap, true)));
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
});
