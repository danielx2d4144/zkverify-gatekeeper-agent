import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { handle } from './handler.mjs';

// Local wrapper around the same core the Vercel function uses.
export function createAgentServer({ secret, handlers, now = Date.now, log = () => {} } = {}) {
  return http.createServer(async (request, response) => {
    if (request.method === 'GET' && request.url === '/health') {
      response.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
      return;
    }
    if (request.method !== 'POST' || !['/agent', '/api/agent'].includes(request.url)) {
      response.writeHead(404).end();
      return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const r = await handle(Buffer.concat(chunks), request.headers['x-agent-games-signature'], { secret, handlers, now: now(), log });
    response.writeHead(r.status, r.headers).end(r.body);
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { handlers } = await import('./handlers.mjs');
  createAgentServer({ secret: process.env.AGENT_GAMES_HMAC_SECRET, handlers, log: console.log })
    .listen(Number(process.env.PORT ?? 3107), '127.0.0.1', () => console.log('agent listening'));
}
