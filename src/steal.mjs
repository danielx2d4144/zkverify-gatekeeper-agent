import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { keccak256, concat, numberToHex } from 'viem';
import { groth16 } from 'snarkjs';
import { decide, witness, EXTRACT, HOLD } from './policy.mjs';

const root = fileURLToPath(new URL('../artifacts/', import.meta.url));
const vkey = JSON.parse(readFileSync(`${root}vfy-policy.vkey.json`, 'utf8'));
const NAME = ['HOLD', 'FORTIFY', 'EXTRACT'];

let cached;
export function config(env = process.env) {
  if (cached) return cached;
  const params = String(env.STRATEGY_PARAMS ?? '').split(',').map(s => BigInt(s.trim()));
  if (params.length !== 8) throw new Error('STRATEGY_PARAMS must hold 8 comma-separated integers');
  return (cached = { params, salt: BigInt(env.STRATEGY_SALT), commitment: env.STRATEGY_COMMITMENT && BigInt(env.STRATEGY_COMMITMENT) });
}

// Build guide: keccak256 over eight 32-byte big-endian words, in this order.
export function publicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount }) {
  return keccak256(concat([
    commitment, BigInt(`0x${matchId.replace(/-/g, '')}`), turn, selfBalance, opponentBalance, action, amount, 1n,
  ].map(v => numberToHex(BigInt(v), { size: 32 }))));
}

// UUIDv5-shaped (version + variant bits set; the platform's uuid schema checks them).
// Deterministic per (match, turn): a retry reuses the key, a new turn never does.
export function idempotencyKey(matchId, turn) {
  const b = createHash('sha256').update(`${matchId}:${turn}`).digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x50;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// Shape practice accepted for other entrants, plus the proof inside policyProof
// as /build describes. Retries get the identical body.
const answers = new Map();
function respond(envelope, s, pick, hashCommitment, proved) {
  const body = {
    protocolVersion: 'v1', matchId: envelope.matchId, turn: envelope.turn,
    action: pick.action === EXTRACT ? { type: 'EXTRACT', amount: Number(pick.amount) } : { type: NAME[pick.action] },
    policyProof: {
      circuitVersion: 'v1',
      publicInputsHash: publicInputsHash({ commitment: hashCommitment, ...s, action: pick.action, amount: pick.amount }),
      ...(proved && { proof: proved.proof, public_signals: proved.publicSignals }),
    },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: idempotencyKey(envelope.matchId, envelope.turn),
  };
  if (proved) answers.set(`${envelope.mode}:${envelope.matchId}:${envelope.turn}`, body);
  return body;
}

const state = envelope => ({
  matchId: envelope.matchId, turn: envelope.turn,
  selfBalance: BigInt(envelope.state.selfBalance), opponentBalance: BigInt(envelope.state.opponentBalance),
});

// publicInputsHash must use the commitment the platform holds (the envelope's);
// the proof must use ours. They differ only in practice placeholders or a bad registration.
const commitments = (envelope, cfg) => {
  const sent = envelope.strategyCommitment?.hash ? BigInt(envelope.strategyCommitment.hash) : undefined;
  return { hash: sent ?? cfg?.commitment ?? 0n, proof: cfg?.commitment ?? sent };
};

export function holdWithoutProof(envelope) {
  let cfg;
  try { cfg = config(); } catch { /* fall through with envelope commitment */ }
  return respond(envelope, state(envelope), { action: HOLD, amount: 0n }, commitments(envelope, cfg).hash);
}

export async function stealTurn(envelope, log = console.log) {
  const { matchId, turn } = envelope;
  if (typeof matchId !== 'string' || !Number.isSafeInteger(turn) || !envelope.state) throw new Error('Malformed turn envelope');
  const hit = answers.get(`${envelope.mode}:${matchId}:${turn}`);
  if (hit) return hit;
  const cfg = config();
  const c = commitments(envelope, cfg);
  if (c.hash !== c.proof) log(JSON.stringify({ at: 'commitment-mismatch', mode: envelope.mode, sent: envelope.strategyCommitment?.hash, ours: `0x${c.proof.toString(16).padStart(64, '0')}` }));
  const s = state(envelope);
  const pick = decide(cfg.params, s);
  const proved = await groth16.fullProve(
    witness(cfg.params, cfg.salt, c.proof, s, pick), `${root}vfy-policy.wasm`, `${root}vfy-policy_final.zkey`,
    undefined, undefined, { singleThread: true },
  );
  if (!await groth16.verify(vkey, proved.publicSignals, proved.proof)) throw new Error('Local policy proof failed to verify');
  return respond(envelope, s, pick, c.hash, proved);
}
