import { authenticate, sign, checkTime } from './security.mjs';

const json = (status, payload, signer) => {
  const body = JSON.stringify(payload);
  const headers = { 'content-type': 'application/json', 'cache-control': 'no-store' };
  if (signer) headers['x-agent-games-signature'] = signer(body);
  return { status, body, headers };
};

export const kind = envelope =>
  envelope.type === 'agent-games.preflight.v1' ? 'preflight'
    : envelope.type === 'agent-games.proof-gatekeeper.v1' ? 'gatekeeper'
      : envelope.eventId === 'steal-the-vfy' || (envelope.matchId && envelope.turn !== undefined) ? 'steal'
        : 'unknown';

// Transport core shared by the Vercel function and the local server.
// handlers: { gatekeeper(envelope), steal(envelope) } -> response payload.
export async function handle(raw, signature, { secret, handlers, now = Date.now(), log = console.log }) {
  const signer = authenticate(raw, signature, secret);
  if (!signer) {
    log(JSON.stringify({ at: 'auth-failed', signatureHeader: String(signature ?? '').slice(0, 80), bytes: raw.length, head: raw.subarray(0, 300).toString() }));
    return json(401, { error: 'Invalid signature' });
  }
  let envelope;
  try {
    envelope = JSON.parse(raw);
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) throw new Error('not an object');
    checkTime(envelope, now);
  } catch (error) {
    log(JSON.stringify({ at: 'bad-envelope', error: error.message, head: raw.subarray(0, 500).toString() }));
    return json(400, { error: 'Invalid request' }, signer);
  }
  const type = kind(envelope);
  log(JSON.stringify({ at: 'envelope', kind: type, envelope }));
  if (type === 'preflight') return json(200, { ok: true, protocolVersion: 'v1' }, signer);
  if (!handlers?.[type]) return json(400, { error: `Unsupported task type` }, signer);
  try {
    const payload = await handlers[type](envelope);
    log(JSON.stringify({ at: 'response', kind: type, payload }));
    return json(200, payload, signer);
  } catch (error) {
    log(JSON.stringify({ at: 'handler-error', kind: type, error: error.stack ?? String(error) }));
    return json(503, { error: 'Task processing failed' }, signer);
  }
}

export { sign };
