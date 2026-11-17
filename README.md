# danielx Gatekeeper — Proof Gatekeeper agent

Daniel's Proof Gatekeeper agent for the zkVerify Agent Games (Season 01), hosted on Vercel at zkverify-gatekeeper-agent.vercel.app/agent.

Implementation follows the design of the competition's leading public agent implementation (penguinpecker/agentgames-2026), adapted to this project's deployment: official circuit artifacts are bundled under artifacts/ (fetched from agentgames.zkverify.io), the HMAC secret comes from the AGENT_GAMES_HMAC_SECRET env var, and the durable proof seen-set uses Vercel Blob when configured, degrading to in-memory otherwise.
