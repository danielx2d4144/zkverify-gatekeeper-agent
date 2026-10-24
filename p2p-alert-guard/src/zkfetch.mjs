// ESM port of @reclaimprotocol/zk-fetch@1.1.0 `ReclaimClient.zkFetch` (non-TEE path, stwo engine).
// Why: the published package is CommonJS that require()s ESM-only deps (@reclaimprotocol/tls,
// attestor-core). Vercel's Node runtime refuses require(esm), so we load the same building blocks
// with native ESM imports. Behaviour mirrors the SDK, including its app-registration check and
// usage logging to Reclaim (so the free-tier metering is respected, not bypassed).
import { setCryptoImplementation } from '@reclaimprotocol/tls';
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto';
import { createClaimOnAttestor } from '@reclaimprotocol/attestor-core';
import { Wallet } from 'ethers';
import { randomUUID } from 'node:crypto';

setCryptoImplementation(webcryptoCrypto);
const APP_BACKEND_URL = 'https://api.reclaimprotocol.org';
const LOGS_BACKEND_URL = 'https://logs.reclaimprotocol.org';
const ATTESTOR_NODE_URL = 'wss://attestor.reclaimprotocol.org/ws';

let attestorUrl; const appNames = {};
async function getAttestorUrl() {
  if (attestorUrl) return attestorUrl;
  try {
    const r = await fetch(`${APP_BACKEND_URL}/api/feature-flags/get?featureFlagNames=zkFetchAttestorURL`, { headers: { 'Content-Type': 'application/json' } });
    const flags = r.ok ? await r.json() : [];
    const f = Array.isArray(flags) && flags.find((x) => x.name === 'zkFetchAttestorURL');
    attestorUrl = (f && f.value) || ATTESTOR_NODE_URL;
  } catch { attestorUrl = ATTESTOR_NODE_URL; }
  return attestorUrl;
}
async function fetchAppById(appId) {
  if (appNames[appId]) return appNames[appId];
  const r = await fetch(`${APP_BACKEND_URL}/api/applications/sdk/get-zk-enabled-app/${appId}`);
  if (r.status !== 200) throw new Error(`Reclaim application ${appId} is not registered as a zkFetch app (HTTP ${r.status})`);
  const j = await r.json();
  return (appNames[appId] = j.application.name);
}
async function sendLogs(sessionId, logType, applicationId) {
  const applicationName = await fetchAppById(applicationId);
  await fetch(`${LOGS_BACKEND_URL}/api/business-logs/zkfetch`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionId, logType, date: new Date().toISOString(), applicationId, applicationName }),
  }).catch(() => {});
}

export async function zkFetch(appId, appSecret, url, options, secretOptions) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(appSecret || '')) throw new Error('Invalid application secret: must be 0x + 64 hex');
  if (new Wallet(appSecret).address.toLowerCase() !== String(appId).toLowerCase()) throw new Error('applicationId does not match applicationSecret');
  const sessionId = randomUUID();
  await sendLogs(sessionId, 'VERIFICATION_STARTED', appId);
  const claim = await createClaimOnAttestor({
    name: 'http',
    params: {
      method: options.method || 'GET', url,
      responseMatches: secretOptions.responseMatches,
      headers: options.headers, responseRedactions: secretOptions.responseRedactions || [], body: options.body || '',
    },
    secretParams: { cookieStr: '', headers: secretOptions.headers || {} },
    zkEngine: 'stwo',
    ownerPrivateKey: appSecret,
    client: { url: await getAttestorUrl() },
  });
  if (claim.error) { await sendLogs(sessionId, 'ERROR', appId).catch(() => {}); throw new Error('attestor: ' + claim.error.message); }
  await sendLogs(sessionId, 'PROOF_GENERATED', appId).catch(() => {});
  // same shape as zk-fetch's transformProof()
  return {
    claimData: claim.claim,
    identifier: claim.claim.identifier,
    signatures: ['0x' + Buffer.from(claim.signatures.claimSignature).toString('hex')],
    extractedParameterValues: claim.claim.context ? JSON.parse(claim.claim.context).extractedParameters : '',
    witnesses: [{ id: claim.signatures.attestorAddress, url: await getAttestorUrl() }],
  };
}

export async function appRegistered(appId) {
  try { await fetchAppById(appId); return true; } catch { return false; }
}
