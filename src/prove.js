// Groth16 proof with the official gatekeeper circuit (13 inputs, found by probing the wasm).
const snarkjs = require('snarkjs');
const crypto = require('crypto');
const path = require('path');
// BN254 scalar field prime. FIXED 2026-11-14: the previous constant had garbled
// digits in the middle (...445932362422240813184... instead of ...034343698204186...),
// so every field reduction was wrong, the platform could not verify any proof
// (dashboard: PROOFS VERIFIED 0, -2 per task, no reliability bonus). The correct
// value is the standard r = 21888242871839275222246405745257275088548364400416034343698204186575808495617.
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const WASM = path.join(__dirname, '../circuits/gatekeeper.wasm');
const ZKEY = path.join(__dirname, '../circuits/gatekeeper_final.zkey');

// Field encoding. Numbers and 0x-hex map directly (mod p). Any other string
// (e.g. a vk hash label) maps to sha256(string) mod p.
function toField(v) {
  const s = String(v).trim();
  if (/^0x[0-9a-f]+$/i.test(s) || /^\d+$/.test(s)) return (BigInt(s) % P).toString();
  return (BigInt('0x' + crypto.createHash('sha256').update(s).digest('hex')) % P).toString();
}
// task_id -> field element. The platform's mapping is unpublished; the default is
// keccak256(string) mod p — the same choice as the competition's top agent (pecker),
// whose proofs verified 3/8 in Round 1 while sha256-default agents verified 0.
// (Michael Pastko's agent defaults to sha256; nobody's mapping is proven.)
// Override with TASK_ID_ENCODING=sha256|utf8. NOTE: the old keccak branch required
// 'viem', which was never installed — it would have crashed. This uses @noble/hashes,
// the same keccak as the Steal agent; vectors verified (keccak256('')=c5d24601...).
const { keccak_256 } = require('@noble/hashes/sha3.js');
function taskIdField(id) {
  const mode = process.env.TASK_ID_ENCODING || 'keccak';
  const s = String(id);
  if (mode === 'utf8') return (BigInt('0x' + (Buffer.from(s).toString('hex') || '0')) % P).toString();
  if (mode === 'sha256') return toField(s);
  return (BigInt('0x' + Buffer.from(keccak_256(Buffer.from(s))).toString('hex')) % P).toString();
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
  // Self-verify before answering (as the competition's top agent does): never send
  // a proof that does not verify against the official verification key (vk.json).
  const vk = require('../vk.json');
  if (!await snarkjs.groth16.verify(vk, publicSignals, proof)) throw new Error('proof failed local verification');
  return { proof, public_signals: publicSignals };
}
module.exports = { prove, toField };
