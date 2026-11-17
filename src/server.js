// Plain Node HTTP server (Docker / any VM / local testing).
const http = require('http');
const { handleRaw, store } = require('./core');
const PORT = Number(process.env.PORT || 8080);
const AGENT_PATH = process.env.AGENT_PATH || '/agent';

http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/health' || req.url === '/')) { res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{"ok":true}'); }
  if (req.method !== 'POST' || req.url.split('?')[0] !== AGENT_PATH) { res.writeHead(404); return res.end(); }
  const chunks = []; let size = 0;
  req.on('data', c => { size += c.length; if (size > 1e6) req.destroy(); else chunks.push(c); });
  req.on('end', async () => {
    const r = await handleRaw(Buffer.concat(chunks), req.headers['x-agent-games-signature']);
    res.writeHead(r.status, r.headers); res.end(r.body);
  });
}).listen(PORT, () => console.log(`gatekeeper agent on :${PORT}${AGENT_PATH} (store: ${store.kind})${process.env.AGENT_GAMES_HMAC_SECRET ? '' : ' WARNING: AGENT_GAMES_HMAC_SECRET not set'}`));
