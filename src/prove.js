// Groth16 proof with the official gatekeeper circuit (13 inputs, found by probing the wasm).
const snarkjs = require('snarkjs');
const crypto = require('crypto');
const path = require('path');
const P = 21888242871839275222246405745257275088548364400416459323624222408131840495617n;
const WASM = path.join(__dirname, '../circuits/gatekeeper.wasm');
const ZKEY = path.join(__dirname, '../circuits/gatekeeper_final.zkey');

// Field encoding. Numbers and 0x-hex map directly (mod p). Any other string
// (e.g. task_id "gk_8d31_...") maps to sha256(string) mod p. Confirm against
// practice-mode results and adjust TASK_ID_ENCODING if the platform differs.
function toField(v) {
  const s = String(v).trim();
  if (/^0x[0-9a-f]+$/i.test(s) || /^\d+$/.test(s)) return (BigInt(s) % P).toString();
  return (BigInt('0x' + crypto.createHash('sha256').update(s).digest('hex')) % P).toString();
}
function taskIdField(id) {
  const mode = process.env.TASK_ID_ENCODING || 'sha256';
  const s = String(id);
  if (mode === 'utf8') return (BigInt('0x' + (Buffer.from(s).toString('hex') || '0')) % P).toString();
  if (mode === 'keccak') { const { keccak256, toBytes } = require('viem'); return (BigInt(keccak256(toBytes(s))) % P).toString(); }
  return toField(s);
}

async function prove(taskId, input, approve) {
  const witness = {
    registeredVkHash: toField(input.registered_vk), proofVkHash: toField(input.proof_vk),
    minimum: toField(input.minimum), publicBalance: toField(input.public_balance),
    expiryBlock: toField(input.expiry_block), currentBlock: toField(input.current_block),
    recipient: toField(input.recipient), conditionRecipient: toField(input.condition_recipient),
    amount: toField(input.amount), maxTransfer: toField(input.max_transfer),
    taskId: taskIdField(taskId), decision: approve ? '1' : '0',
    salt: (BigInt('0x' + crypto.randomBytes(31).toString('hex'))).toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(witness, WASM, ZKEY);
  return { proof, public_signals: publicSignals };
}
module.exports = { prove, toField };
