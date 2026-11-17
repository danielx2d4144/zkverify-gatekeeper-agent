#!/bin/sh
# Download the official Agent Games gatekeeper circuit artifacts.
set -e
mkdir -p circuits
curl -fsSL -o circuits/gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -fsSL -o circuits/gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
