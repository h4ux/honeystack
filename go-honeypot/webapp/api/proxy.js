// Relay for the honeypot control API.
//
// Browsers block plain ws:// and http:// from an https:// page, so the
// dashboard cannot talk to a bare Go daemon directly when hosted on
// Vercel. This function forwards REST calls server-side.

const BLOCKED_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1'
]);

function allowedPath(path) {
  return path === '/health' || path.startsWith('/v1/');
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type,authorization,x-auth-key');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  const query = req.query || {};
  const host = String(query.host || '').trim();
  const port = Number(query.port || 0);
  const path = String(query.path || '/v1/hello');
  const auth = req.headers.authorization || '';
  const token =
    req.headers['x-auth-key'] ||
    (auth.toLowerCase().startsWith('bearer ') ? auth.slice(7).trim() : '') ||
    query.token ||
    '';

  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    res.status(400).json({ error: 'host and port are required' });
    return;
  }
  if (BLOCKED_HOSTS.has(host.toLowerCase())) {
    res.status(400).json({ error: 'host not allowed' });
    return;
  }
  if (!allowedPath(path.split('?')[0])) {
    res.status(400).json({ error: 'path not allowed' });
    return;
  }

  const scheme = query.tls === '1' ? 'https' : 'http';
  const target = `${scheme}://${host}:${port}${path}`;
  const headers = { 'X-Auth-Key': token, Authorization: `Bearer ${token}` };
  if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type'];

  let body;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? {});
  }

  const timeout = AbortSignal.timeout ? AbortSignal.timeout(10000) : undefined;

  try {
    const upstream = await fetch(target, { method: req.method, headers, body, signal: timeout });
    const text = await upstream.text();
    res.status(upstream.status);
    res.setHeader('Content-Type', upstream.headers.get('content-type') || 'application/json');
    res.send(text);
  } catch (err) {
    res.status(502).json({ error: 'honeypot unreachable: ' + err.message });
  }
};
