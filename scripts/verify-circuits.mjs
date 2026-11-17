import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { groth16 } from 'snarkjs';
import { proveGatekeeper, gatekeeperSignalNames, assertGatekeeperBinding } from '../src/proofs.mjs';

// These are synthetic LOCAL witnesses. They are not scored platform tasks,
// chain receipts, production practice results, or evidence of earned tokens.
const base = {
  publicBalance: '1460', minimum: '1000', salt: '7', recipient: '123',
  conditionRecipient: '123', amount: '500', maxTransfer: '1000',
  expiryBlock: '200', currentBlock: '100', decision: '1',
  registeredVkHash: '321', proofVkHash: '321', taskId: '456',
};
const fixtures = {
  valid: {},
  vkSubstitution: { proofVkHash: '322', decision: '0' },
  thresholdMismatch: { publicBalance: '999', decision: '0' },
  expired: { currentBlock: '201', decision: '0' },
  expiryEquality: { currentBlock: '200', decision: '0' },
  recipientMismatch: { recipient: '124', decision: '0' },
  amountOverflow: { amount: '1001', decision: '0' },
  inclusiveAmountAndBalance: { amount: '1000', publicBalance: '1000' },
};
const results = [];
const key = JSON.parse(readFileSync(new URL('../artifacts/gatekeeper.vkey.json', import.meta.url), 'utf8'));
let validProof;
try {
  for (const [name, patch] of Object.entries(fixtures)) {
    const start = performance.now();
    const proof = await proveGatekeeper({ ...base, ...patch });
    const ms = Math.round(performance.now() - start);
    results.push({ name, verifiedLocally: true, generationAndVerificationMs: ms });
    if (name === 'valid') validProof = proof;
    console.log(`${name}: verified in ${ms}ms`);
  }
  const tampered = [...validProof.public_signals];
  tampered[4] = '1461';
  if (await groth16.verify(key, tampered, validProof.proof)) throw new Error('Tampered public balance verified');
  results.push({ name: 'tamperedPublicBalance', rejectedLocally: true });
  let rejected = false;
  try { assertGatekeeperBinding(validProof.public_signals, { ...base, taskId: '457' }); } catch { rejected = true; }
  if (!rejected) throw new Error('Wrong task binding accepted');
  results.push({ name: 'wrongTaskBinding', rejectedLocally: true });
  const files = ['gatekeeper.wasm', 'gatekeeper_final.zkey', 'gatekeeper.vkey.json', 'vfy-policy.wasm', 'vfy-policy_final.zkey', 'vfy-policy.vkey.json'];
  const artifacts = Object.fromEntries(files.map(name => {
    const content = readFileSync(new URL(`../artifacts/${name}`, import.meta.url));
    return [name, { bytes: content.length, sha256: createHash('sha256').update(content).digest('hex') }];
  }));
  const report = {
    verifiedAt: new Date().toISOString(), scope: 'Synthetic local circuit verification only',
    officialArtifactSource: 'https://agentgames.zkverify.io/build',
    networkTransactionsSubmitted: 0, platformPracticeTasksRun: 0, tokensEarned: 0,
    publicSignalOrder: gatekeeperSignalNames, results, artifacts,
    limitations: [
      'Opaque task-ID and VK field encodings must be confirmed against signed practice requests.',
      'No platform account secret is configured; no endpoint has been registered.',
      'No mainnet proof verification or finalized transaction has been claimed.',
      'Steal the VFY strategy witness semantics remain unconfirmed.',
    ],
  };
  writeFileSync(new URL('../docs/local-proof-verification.json', import.meta.url), `${JSON.stringify(report, null, 2)}\n`);
  console.log(`Verified ${results.length} local cases. Report: docs/local-proof-verification.json`);
} finally {
  // snarkjs's verifier caches a worker pool globally. Release it for CLI runs.
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
  if (globalThis.curve_bls12381) await globalThis.curve_bls12381.terminate();
}
