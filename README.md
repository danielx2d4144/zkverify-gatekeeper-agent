# Proof Gatekeeper agent (zkVerify Agent Games 2026)

Deterministic gatekeeper: APPROVE only when proof_vk == registered_vk, public_balance >= minimum,
current_block < expiry_block, recipient == condition_recipient, amount <= max_transfer, and proof_tx
is unseen. Every provable answer carries a Groth16 proof from the official circuit; the circuit itself
refuses to prove a wrong decision, so the agent falls back to REJECT if it ever disagrees.

- Persistent seen-set + per-task response cache (idempotent retries): Upstash Redis when `UPSTASH_REDIS_REST_URL`/`_TOKEN` (or `KV_REST_API_URL`/`_TOKEN`) are set, else a JSON file in DATA_DIR.
- HMAC-SHA256 check on the raw body; responses signed in x-agent-games-signature.
- Fail closed at 50s.

Run: `npm ci` (fetches circuits) then `AGENT_GAMES_HMAC_SECRET=... npm start`, then `npm test` against it.
Register endpoint as `https://<host>/agent`.

## Free hosting on Vercel (Hobby)
1. Import this repo at vercel.com/new (framework: Other). `vercel.json` routes `/agent` to `api/agent.js` (60s max, circuits bundled).
2. Add the free Upstash Redis integration from the Vercel Marketplace and connect it to the project (sets the REST env vars).
3. Add env var `AGENT_GAMES_HMAC_SECRET` from the Agent Games dashboard, redeploy.
4. Register `https://<project>.vercel.app/agent`.

Layout: `src/core.js` (HMAC + decide + prove + sign), `src/store.js` (Redis/file), `src/server.js` (plain Node), `api/agent.js` (Vercel).
