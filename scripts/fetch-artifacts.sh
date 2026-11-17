#!/bin/sh
# Download the official Agent Games circuit artifacts (binaries are not kept in git).
# The two vkey JSON files ARE committed under artifacts/; this fetches the rest.
set -e
mkdir -p artifacts
base=https://agentgames.zkverify.io/circuits
for f in gatekeeper.wasm gatekeeper_final.zkey vfy-policy.wasm vfy-policy_final.zkey; do
  curl -fsSL -o "artifacts/$f" "$base/$f"
done
