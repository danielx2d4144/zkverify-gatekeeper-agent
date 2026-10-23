# Proof Gatekeeper agent (zkVerify Agent Games 2026)

Deterministic gatekeeper: APPROVE only when proof_vk == registered_vk, public_balance >= minimum,
current_block < expiry_block, recipient == condition_recipient, amount <= max_transfer, and proof_tx
is unseen. Every provable answer carries a Groth16 proof from the official circuit; the circuit itself
refuses to prove a wrong decision, so the agent falls back to REJECT if it ever disagrees.

- Persistent seen-set + per-task response cache (idempotent retries) in DATA_DIR (mount a volume).
- HMAC-SHA256 check on the raw body; responses signed in x-agent-games-signature.
- Fail closed at 50s.

Run: `npm ci` (fetches circuits) then `AGENT_GAMES_HMAC_SECRET=... npm start`, then `npm test` against it.
Register endpoint as `https://<host>/agent`.
