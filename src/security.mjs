import { createHmac, timingSafeEqual } from 'node:crypto';

// The docs don't say whether the one-time secret is used as a UTF-8 string or
// decoded bytes, nor the exact header encoding. Accept each plausible reading
// of the secret and reply in the same form the platform used.
function keys(secret) {
  if (typeof secret !== 'string' || secret.length < 16) throw new Error('HMAC secret is missing or too short');
  const out = [Buffer.from(secret, 'utf8')];
  if (/^[0-9a-f]{64}$/i.test(secret)) out.push(Buffer.from(secret, 'hex'));
  if (/^[A-Za-z0-9+/_-]{43}=?$/.test(secret)) out.push(Buffer.from(secret, 'base64'));
  return out;
}

const mac = (raw, key) => createHmac('sha256', key).update(raw).digest();

function parseHeader(header) {
  const text = String(header ?? '').trim();
  const prefix = /^sha256=/i.test(text) ? text.slice(0, 7) : '';
  const value = text.slice(prefix.length);
  if (/^[0-9a-f]{64}$/i.test(value)) return { prefix, encoding: 'hex', bytes: Buffer.from(value, 'hex') };
  if (/^[A-Za-z0-9+/]{43}=$/.test(value)) return { prefix, encoding: 'base64', bytes: Buffer.from(value, 'base64') };
  return null;
}

// Returns a signer bound to the matching key/format, or null if unauthenticated.
export function authenticate(raw, header, secret) {
  const given = parseHeader(header);
  if (!given) return null;
  const key = keys(secret).find(k => timingSafeEqual(given.bytes, mac(raw, k)));
  if (!key) return null;
  return body => given.prefix + mac(body, key).toString(given.encoding);
}

// Default signer for unauthenticated replies and tests: UTF-8 key, hex digest.
export function sign(raw, secret) {
  keys(secret);
  return mac(raw, Buffer.from(secret, 'utf8')).toString('hex');
}

// Replay window only. Deadlines are the platform's to enforce; answering a
// little late costs nothing extra, refusing a valid task costs a forfeit.
export function checkTime(envelope, now = Date.now()) {
  const issued = Date.parse(envelope.issued_at ?? envelope.issuedAt);
  if (!Number.isFinite(issued) || issued > now + 120_000 || issued < now - 600_000) {
    throw new Error('Invalid or stale issue timestamp');
  }
}
