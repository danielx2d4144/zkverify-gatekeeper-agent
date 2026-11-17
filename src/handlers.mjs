// Each game handler fails to its safest scored answer instead of a 5xx:
// Steal falls back to HOLD, Gatekeeper to REJECT (wrong reject −3 beats timeout/approving a trap).
export const handlers = {
  async steal(envelope) {
    try {
      const { stealTurn } = await import('./steal.mjs');
      return await stealTurn(envelope);
    } catch (error) {
      console.log(JSON.stringify({ at: 'steal-fallback', error: error.stack ?? String(error) }));
      try {
        const { holdWithoutProof } = await import('./steal.mjs');
        return holdWithoutProof(envelope);
      } catch {
        return { protocolVersion: 'v1', matchId: envelope.matchId, turn: envelope.turn, action: { type: 'HOLD' }, policyProof: { circuitVersion: 'v1' }, agentTimestamp: new Date().toISOString() };
      }
    }
  },
  async gatekeeper(envelope) {
    try {
      const { gatekeeperTask } = await import('./gatekeeper-task.mjs');
      return await gatekeeperTask(envelope);
    } catch (error) {
      console.log(JSON.stringify({ at: 'gatekeeper-fallback', error: error.stack ?? String(error) }));
      return { decision: 'REJECT', reason_code: 'PUBLIC_INPUT_MISMATCH', proof_tx: envelope.input?.proof_tx };
    }
  },
};
