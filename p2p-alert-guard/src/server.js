// Local dev server: node src/server.js  (serves the demo page and the same handlers as Vercel)
const http = require('http'); const fs = require('fs'); const path = require('path');
const h = require('./http');
const routes = { '/check': h.handleCheck, '/api/check': h.handleCheck, '/health': h.handleHealth, '/api/health': h.handleHealth, '/api/result': h.handleResult, '/api/zkverify': h.handleZkVerify, '/api/demo-payment': h.handleDemoPayment };
http.createServer((req, res) => {
  const p = req.url.split('?')[0];
  if (routes[p]) return routes[p](req, res);
  const f = path.join(__dirname, '../public', p === '/' ? 'index.html' : p);
  if (f.startsWith(path.join(__dirname, '../public')) && fs.existsSync(f)) { res.setHeader('content-type', f.endsWith('.html') ? 'text/html' : 'text/plain'); return res.end(fs.readFileSync(f)); }
  h.send(res, 404, { error: 'not found' });
}).listen(process.env.PORT || 3000, () => console.log('p2p-alert-guard on :' + (process.env.PORT || 3000)));
