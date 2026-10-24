// Vercel's Node runtime runs without ESM syntax auto-detection, so ESM files shipped under a
// package without "type":"module" (esprima-next's dist/esm) load as CommonJS and break
// attestor-core's named imports. Mark those folders as ESM explicitly.
const fs = require('fs'); const path = require('path');
for (const dir of ['node_modules/esprima-next/dist/esm']) {
  const d = path.join(__dirname, '..', dir);
  if (fs.existsSync(d)) { fs.writeFileSync(path.join(d, 'package.json'), '{"type":"module"}\n'); console.log('patched', dir); }
}
