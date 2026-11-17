// Download the official Agent Games circuit artifacts at build time.
// (Node fetch is used instead of curl, which is not present in every build image.)
// The two vkey JSON files are committed under artifacts/; this fetches the binaries.
import { mkdir, writeFile } from 'node:fs/promises';

const base = 'https://agentgames.zkverify.io/circuits';
const files = ['gatekeeper.wasm', 'gatekeeper_final.zkey', 'vfy-policy.wasm', 'vfy-policy_final.zkey'];
await mkdir('artifacts', { recursive: true });
for (const f of files) {
  const r = await fetch(`${base}/${f}`);
  if (!r.ok) throw new Error(`fetch ${f}: HTTP ${r.status}`);
  const buf = Buffer.from(await r.arrayBuffer());
  await writeFile(`artifacts/${f}`, buf);
  console.log(`fetched ${f} (${buf.length} bytes)`);
}
