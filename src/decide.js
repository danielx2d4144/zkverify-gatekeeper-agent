// Deterministic Proof Gatekeeper policy. Mirrors the official circuit:
// APPROVE iff proof_vk == registered_vk, public_balance >= minimum,
// current_block < expiry_block, recipient == condition_recipient,
// amount <= max_transfer, and proof_tx has not been seen on another task.
const norm = (s) => String(s ?? '').trim().toLowerCase();
const big = (s) => { try { return BigInt(String(s).trim()); } catch { return null; } };

function decide(input, seen) {
  const need = ['registered_vk','proof_vk','minimum','public_balance','expiry_block','current_block','recipient','condition_recipient','amount','max_transfer'];
  for (const k of need) if (input?.[k] === undefined || input?.[k] === null || input?.[k] === '') return { decision: 'REJECT', reason_code: 'MALFORMED_INPUT' };
  const min = big(input.minimum), bal = big(input.public_balance), exp = big(input.expiry_block),
        cur = big(input.current_block), amt = big(input.amount), cap = big(input.max_transfer);
  if ([min,bal,exp,cur,amt,cap].some(v => v === null)) return { decision: 'REJECT', reason_code: 'MALFORMED_INPUT' };
  if (input.proof_tx && seen && seen(norm(input.proof_tx))) return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  if (norm(input.proof_vk) !== norm(input.registered_vk)) return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  if (cur >= exp) return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  if (norm(input.recipient) !== norm(input.condition_recipient)) return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  if (bal < min) return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  if (amt > cap) return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}
module.exports = { decide };
