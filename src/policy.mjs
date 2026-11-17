// Mirrors the organizer's VfyPolicyProof circuit (differentially tested against vfy-policy.wasm).
// strategyParams = [extractAmount 1..10, fortifyBelow, extractAbove, noExtract 0|1, 0, 0, 0, 0];
// balances and thresholds must fit the circuit's 16-bit comparators.
// commitment = Poseidon(strategyParams[0..7], salt) — computed offline by scripts/strategy-setup.mjs.
export const HOLD = 0n, FORTIFY = 1n, EXTRACT = 2n;

export function decide([extractAmount, fortifyBelow, extractAbove, noExtract], { selfBalance, opponentBalance }) {
  if (selfBalance < fortifyBelow) return { action: FORTIFY, amount: 0n };
  if (opponentBalance > extractAbove && noExtract === 0n) return { action: EXTRACT, amount: extractAmount };
  return { action: HOLD, amount: 0n };
}

export const matchIdField = matchId => BigInt(`0x${matchId.replace(/-/g, '')}`);

export function witness(params, salt, commitment, s, pick) {
  return {
    strategyParams: params.map(String), salt: String(salt), commitment: String(commitment),
    matchId: matchIdField(s.matchId).toString(), turnNumber: String(s.turn),
    selfBalance: String(s.selfBalance), opponentBalance: String(s.opponentBalance),
    action: String(pick.action), amount: String(pick.amount), circuitVersion: '1',
  };
}
