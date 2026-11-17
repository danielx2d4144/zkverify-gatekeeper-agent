const UINT64_MAX = (1n << 64n) - 1n;

export function uint64(value, field) {
  if (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) throw new Error(`Invalid ${field}`);
  if (!['string', 'number'].includes(typeof value) || !/^(0|[1-9][0-9]*)$/.test(String(value))) {
    throw new Error(`Invalid ${field}`);
  }
  const n = BigInt(value);
  if (n > UINT64_MAX) throw new Error(`Out of range ${field}`);
  return n;
}

// Exact equality is all that matters, so accept any 0x value up to `bytes` long.
function hex(value, bytes, field) {
  if (typeof value !== 'string' || !new RegExp(`^0x[0-9a-fA-F]{1,${bytes * 2}}$`).test(value)) {
    throw new Error(`Invalid ${field}`);
  }
  return value.toLowerCase();
}

// This evaluates the statement only. It deliberately does NOT label a network
// transaction finalized or authorize money movement. Network evidence is separate.
export function evaluateStatement(input, acceptedProofs = new Set()) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Missing input');
  const registeredVk = hex(input.registered_vk, 32, 'registered_vk');
  const proofVk = hex(input.proof_vk, 32, 'proof_vk');
  const recipient = hex(input.recipient, 20, 'recipient');
  const conditionRecipient = hex(input.condition_recipient, 20, 'condition_recipient');
  const proofTx = hex(input.proof_tx, 32, 'proof_tx');
  const numbers = Object.fromEntries(['minimum', 'public_balance', 'expiry_block', 'current_block', 'amount', 'max_transfer']
    .map(field => [field, uint64(input[field], field)]));

  const reject = (reason_code, category) => ({ decision: 'REJECT', reason_code, category, proof_tx: proofTx });
  if (acceptedProofs.has(proofTx)) return reject('PROOF_REPLAY', 'PROOF_REUSED');
  if (registeredVk !== proofVk) return reject('VK_SUBSTITUTION', 'VK_SUBSTITUTION');
  if (numbers.public_balance < numbers.minimum) return reject('THRESHOLD_MISMATCH', 'THRESHOLD_MISMATCH');
  // The supplied circuit requires currentBlock < expiryBlock. Equality rejects.
  if (numbers.current_block >= numbers.expiry_block) return reject('EXPIRED_CONDITION', 'EXPIRED_CONDITION');
  if (recipient !== conditionRecipient) return reject('RECIPIENT_MISMATCH', 'RECIPIENT_MISMATCH');
  if (numbers.amount > numbers.max_transfer) return reject('AMOUNT_OVERFLOW', 'AMOUNT_OVERFLOW');
  return { decision: 'APPROVE', reason_code: 'VALID_PROOF', category: 'VALID_CONDITION', proof_tx: proofTx };
}

