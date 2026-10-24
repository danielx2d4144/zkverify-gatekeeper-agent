// zkTLS layer: Reclaim zkFetch of Paystack's verify endpoint + independent proof verification.
// The Paystack secret key travels only in zkFetch's *private* headers: it is used inside the
// TLS session but never appears in the proof (claim parameters hold only the public request).
const PAYSTACK_VERIFY = 'https://api.paystack.co/transaction/verify/';
const ATTESTORS_URL = 'https://api.reclaimprotocol.org/api/attestors';
const REF_RE = /^[A-Za-z0-9._=-]{6,100}$/; // Paystack reference charset

// One ordered regex over the top of Paystack's `data` object binds id, mode, status, reference
// and amount together (so a buyer-controlled metadata field later in the body can't be matched
// instead). A second ordered regex takes the currency that follows `channel`.
const MATCH_CORE = '"data":\\{"id":(?<txid>\\d+),"domain":"(?<domain>[a-z]+)","status":"(?<status>[a-z_]+)","reference":"(?<reference>[A-Za-z0-9._=-]+)","receipt_number":(?:null|"[^"]*"),"amount":(?<amount>\\d+),';
const MATCH_CCY = '"channel":"[a-z_]+","currency":"(?<currency>[A-Z]{3})"';

function verifyUrl(reference) {
  if (!REF_RE.test(reference)) throw new Error('bad reference');
  return PAYSTACK_VERIFY + encodeURIComponent(reference);
}

// Cheap, unproven pre-check (no zkFetch quota): only used to short-circuit NOT_FOUND / upstream
// errors, which zkTLS cannot attest anyway (the attestor only signs 2xx responses).
async function precheck(reference, secretKey, fetchImpl = fetch) {
  const r = await fetchImpl(verifyUrl(reference), { headers: { authorization: `Bearer ${secretKey}`, accept: 'application/json' } });
  let body = null; try { body = await r.json(); } catch {}
  if (r.status === 400 || r.status === 404) {
    if (body && (body.code === 'transaction_not_found' || /not found/i.test(body.message || ''))) return { found: false, http: r.status };
  }
  if (!r.ok || !body || body.status !== true) return { error: `paystack http ${r.status}`, http: r.status };
  return { found: true, http: r.status };
}

let client;
async function zkFetchPaystack(reference, { appId, appSecret, secretKey }) {
  if (!client) {
    const { ReclaimClient } = require('@reclaimprotocol/zk-fetch');
    client = new ReclaimClient(appId, appSecret);
  }
  const proof = await client.zkFetch(
    verifyUrl(reference),
    { method: 'GET', headers: { accept: 'application/json' } },
    {
      headers: { authorization: `Bearer ${secretKey}` }, // private: hidden from the proof
      responseMatches: [{ type: 'regex', value: MATCH_CORE }, { type: 'regex', value: MATCH_CCY }],
      // reveal only the matched fields; customer e-mail, card BIN/last4 etc. stay redacted
      responseRedactions: [{ regex: MATCH_CORE }, { regex: MATCH_CCY }],
    }
  );
  return proof;
}

let attestorCache = { at: 0, list: [] };
async function attestors(fetchImpl = fetch) {
  if (Date.now() - attestorCache.at < 3600e3 && attestorCache.list.length) return attestorCache.list;
  const r = await fetchImpl(ATTESTORS_URL);
  const j = await r.json();
  attestorCache = { at: Date.now(), list: (j.data || []).map((a) => a.address.toLowerCase()) };
  return attestorCache.list;
}

// Independent verification of a Reclaim proof object. Anyone can run this (see scripts/verify-proof.js).
// Checks: (1) identifier == keccak(provider, parameters, context); (2) signature recovers to a
// Reclaim attestor; (3) the attested request is exactly GET <paystack verify url for reference>
// with our regexes; (4) returns the extracted, attested fields.
async function verifyReclaimProof(proof, reference, { fetchImpl = fetch } = {}) {
  const sdk = require('@reclaimprotocol/js-sdk');
  const cd = proof && proof.claimData;
  if (!cd || !proof.signatures || !proof.signatures.length) return { ok: false, why: 'malformed proof' };
  const id = sdk.getIdentifierFromClaimInfo({ provider: cd.provider, parameters: cd.parameters, context: cd.context });
  if (id !== String(cd.identifier).toLowerCase()) return { ok: false, why: 'identifier mismatch' };
  const signers = sdk.recoverSignersOfSignedClaim({ claim: cd, signatures: proof.signatures.map((s) => Buffer.from(s.replace(/^0x/, ''), 'hex')) });
  const known = await attestors(fetchImpl);
  const attestor = signers.find((s) => known.includes(s));
  if (!attestor) return { ok: false, why: 'not signed by a Reclaim attestor' };
  let params, ctx;
  try { params = JSON.parse(cd.parameters); ctx = JSON.parse(cd.context || '{}'); } catch { return { ok: false, why: 'bad claim json' }; }
  if (cd.provider !== 'http') return { ok: false, why: 'provider not http' };
  if (params.url !== verifyUrl(reference) || (params.method || 'GET') !== 'GET') return { ok: false, why: 'proof is for a different request' };
  const regs = (params.responseMatches || []).map((m) => m.value);
  if (!regs.includes(MATCH_CORE) || !regs.includes(MATCH_CCY)) return { ok: false, why: 'unexpected response matchers' };
  const ex = ctx.extractedParameters || {};
  return {
    ok: true, attestor, identifier: id, timestampS: cd.timestampS,
    fields: { txid: ex.txid, domain: ex.domain, status: ex.status, reference: ex.reference, amount: ex.amount, currency: ex.currency },
  };
}

module.exports = { precheck, zkFetchPaystack, verifyReclaimProof, verifyUrl, REF_RE, MATCH_CORE, MATCH_CCY };
