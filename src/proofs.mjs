import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { groth16 } from 'snarkjs';

export const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const root = fileURLToPath(new URL('../artifacts/', import.meta.url));

export const gatekeeperSignalNames = [
  'evaluationCommitment', 'registeredVkHash', 'proofVkHash', 'minimum',
  'publicBalance', 'expiryBlock', 'currentBlock', 'recipient',
  'conditionRecipient', 'amount', 'maxTransfer', 'decision', 'taskId',
];

export function field(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error('Expected a decimal field element');
  const result = BigInt(value);
  if (result >= FIELD_PRIME) throw new Error('Field element is out of range');
  return result;
}

export function assertGatekeeperBinding(signals, witness) {
  if (signals.length !== gatekeeperSignalNames.length) throw new Error('Wrong public signal count');
  for (let i = 0; i < signals.length; i++) {
    field(signals[i]);
    if (i && String(witness[gatekeeperSignalNames[i]]) !== signals[i]) {
      throw new Error(`Public signal mismatch: ${gatekeeperSignalNames[i]}`);
    }
  }
}

export async function proveGatekeeper(witness) {
  for (const name of [...gatekeeperSignalNames.slice(1), 'salt']) field(witness[name]);
  const { proof, publicSignals } = await groth16.fullProve(
    witness, `${root}gatekeeper.wasm`, `${root}gatekeeper_final.zkey`, undefined,
    { memorySize: 1024 }, { singleThread: true },
  );
  assertGatekeeperBinding(publicSignals, witness);
  const key = JSON.parse(readFileSync(`${root}gatekeeper.vkey.json`, 'utf8'));
  if (!await groth16.verify(key, publicSignals, proof)) {
    throw new Error('Local proof verification failed');
  }
  return { proof, public_signals: publicSignals };
}

