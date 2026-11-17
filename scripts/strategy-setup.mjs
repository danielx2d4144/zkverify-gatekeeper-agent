// Usage: node scripts/strategy-setup.mjs 10,0,0,0,0,0,0,0 [--push]
// Generates a fresh salt (never printed), saves params+salt to .env.strategy (0600),
// proves one sample turn to confirm the circuit accepts them, prints the commitment,
// and with --push writes STRATEGY_PARAMS / STRATEGY_SALT to Vercel production.
import { randomBytes } from 'node:crypto';
import { writeFileSync, chmodSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { buildPoseidon } from 'circomlibjs';
import { groth16 } from 'snarkjs';

const params = (process.argv[2] ?? '').split(',').map(s => BigInt(s.trim()));
if (params.length !== 8) throw new Error('give 8 comma-separated params');
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const salt = BigInt(`0x${randomBytes(31).toString('hex')}`) % P;
const poseidon = await buildPoseidon();
const commitment = poseidon.F.toObject(poseidon([...params, salt]));

process.env.STRATEGY_PARAMS = params.join(',');
process.env.STRATEGY_SALT = salt.toString();
const { stealTurn } = await import('../src/steal.mjs');
const envelope = { matchId: '9f4e1b2a-0000-4000-8000-000000000001', turn: 1, state: { selfBalance: '100', opponentBalance: '100' },
  strategyCommitment: { hash: `0x${commitment.toString(16).padStart(64, '0')}` } };
const sample = await stealTurn(envelope, () => {});
console.log('sample turn at 100/100 ->', JSON.stringify(sample.action), 'proof verified locally');

writeFileSync('.env.strategy', `STRATEGY_PARAMS=${params.join(',')}\nSTRATEGY_SALT=${salt}\n`);
chmodSync('.env.strategy', 0o600);
console.log('commitment (hex):    ', envelope.strategyCommitment.hash);
console.log('commitment (decimal):', commitment.toString());

if (process.argv.includes('--push')) {
  for (const [name, value] of [['STRATEGY_PARAMS', params.join(',')], ['STRATEGY_SALT', salt.toString()]]) {
    execFileSync('vercel', ['env', 'add', name, 'production', '--force', '--sensitive', '--yes'], { input: value, stdio: ['pipe', 'ignore', 'inherit'] });
  }
  console.log('pushed STRATEGY_PARAMS and STRATEGY_SALT to Vercel production (redeploy to apply)');
}
if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
