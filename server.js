import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { searchIntel, indexStats } from './intel-store.js';
import { startSync, syncStatus } from './intel-sync.js';
import { lookupAsset } from './asset-osint.js';

const root = path.dirname(fileURLToPath(import.meta.url));
const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml' };
const kinds = new Set(['all', 'cve', 'kev', 'attack', 'certin']);

function json(res, status, payload) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(payload));
}

async function readJson(req, maxBytes = 4096) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > maxBytes) throw Object.assign(new Error('Request is too large.'), { status: 413 });
  }
  try { return JSON.parse(body || '{}'); }
  catch { throw Object.assign(new Error('Request body must be valid JSON.'), { status: 400 }); }
}

export function createServer() {
  return http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname === '/api/search' && req.method === 'GET') {
      const query = (url.searchParams.get('q') || '').trim();
      if (!query || query.length > 300) return json(res, 400, { error: 'Enter a search up to 300 characters.' });
      const kind = url.searchParams.get('kind') || 'all';
      if (!kinds.has(kind)) return json(res, 400, { error: 'Choose a valid intelligence source.' });
      const severity = url.searchParams.get('severity') || '';
      const kev = url.searchParams.get('kev') === '1';
      const { results, total } = searchIntel({ query, kind, severity, kev, limit: 25, offset: 0 });
      return json(res, 200, { results, total, local: true });
    }
    if (url.pathname === '/api/sync/status' && req.method === 'GET') return json(res, 200, syncStatus());
    if (url.pathname === '/api/sync' && req.method === 'POST') {
      const started = startSync();
      return json(res, started ? 202 : 409, { started, status: syncStatus() });
    }
    if (url.pathname === '/api/assets/lookup' && req.method === 'POST') {
      const body = await readJson(req);
      if (body.confirmed !== true) return json(res, 400, { error: 'Confirm the passive lookup disclosure before continuing.' });
      const result = await lookupAsset(body.target);
      return json(res, 200, result);
    }

    if (req.method !== 'GET') return json(res, 405, { error: 'Method not allowed.' });
    const rel = url.pathname === '/' ? 'public/index.html' : `public${url.pathname}`;
    const file = path.resolve(root, rel);
    if (!file.startsWith(path.join(root, 'public') + path.sep)) {
      res.writeHead(404); return res.end('Not found');
    }
    const body = await readFile(file);
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    res.writeHead(200, { 'content-type': mime[path.extname(file)] || 'application/octet-stream', 'cache-control': 'no-cache' });
    res.end(body);
  } catch (error) {
    const status = Number.isInteger(error.status) ? error.status : 502;
    const message = status === 400 || status === 413 ? error.message : 'The request could not be completed. Please try again.';
    json(res, status, { error: message });
  }
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const server = createServer();
  const port = Number(process.env.PORT || 4173);
  server.listen(port, '127.0.0.1', () => {
    const address = server.address();
    console.log(`Bharat Cyber Search is running at http://127.0.0.1:${address.port}`);
  });
}
