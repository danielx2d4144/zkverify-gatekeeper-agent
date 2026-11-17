import { randomBytes } from 'node:crypto';
import { evaluateStatement } from './gatekeeper.mjs';
import { acceptedBy, markAccepted } from './seen.mjs';
import { proveGatekeeper, FIELD_PRIME } from './proofs.mjs';
import { encodeTaskId } from './gk-encoding.mjs';

const fe = hex => (BigInt(hex) % FIELD_PRIME).toString();

export function witnessFor(envelope, approve) {
  const i = envelope.input;
  return {
    registeredVkHash: fe(i.registered_vk), proofVkHash: fe(i.proof_vk),
    minimum: String(i.minimum), publicBalance: String(i.public_balance),
    expiryBlock: String(i.expiry_block), currentBlock: String(i.current_block),
    recipient: fe(i.recipient), conditionRecipient: fe(i.condition_recipient),
    amount: String(i.amount), maxTransfer: String(i.max_transfer),
    decision: approve ? '1' : '0', taskId: encodeTaskId(envelope.task_id),
    salt: (BigInt(`0x${randomBytes(31).toString('hex')}`)).toString(),
  };
}

export async function gatekeeperTask(envelope, log = console.log) {
  const input = envelope.input ?? {};
  let prior;
  try { prior = await acceptedBy(String(input.proof_tx)); }
  catch (error) { log(JSON.stringify({ at: 'seen-read-failed', error: String(error) })); }
  const replay = prior !== undefined && prior !== envelope.task_id;
  const result = evaluateStatement(input, replay ? new Set([String(input.proof_tx).toLowerCase()]) : new Set());
  const response = { decision: result.decision, reason_code: result.reason_code, proof_tx: input.proof_tx };
  // A replay has no fresh statement to prove; the docs exclude it from the proof bonus.
  if (result.reason_code !== 'PROOF_REPLAY') {
    try {
      Object.assign(response, await proveGatekeeper(witnessFor(envelope, result.decision === 'APPROVE')));
    } catch (error) {
      log(JSON.stringify({ at: 'gatekeeper-proof-failed', error: error.stack ?? String(error) }));
    }
  }
  if (result.decision === 'APPROVE') {
    await markAccepted(String(input.proof_tx), envelope.task_id)
      .catch(error => log(JSON.stringify({ at: 'seen-write-failed', error: String(error) })));
  }
  return response;
}
