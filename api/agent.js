// Vercel serverless entry. Body parsing is off so the HMAC is checked on the exact raw bytes.
const { handleRaw } = require('../src/core');

module.exports = async (req, res) => {
  if (req.method === 'GET') { res.setHeader('content-type', 'application/json'); return res.end('{"ok":true}'); }
  if (req.method !== 'POST') { res.statusCode = 405; return res.end(); }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const r = await handleRaw(Buffer.concat(chunks), req.headers['x-agent-games-signature']);
  res.statusCode = r.status;
  for (const [k, v] of Object.entries(r.headers)) res.setHeader(k, v);
  res.end(r.body);
};
module.exports.config = { api: { bodyParser: false } };
