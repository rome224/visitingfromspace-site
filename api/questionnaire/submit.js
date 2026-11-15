import { redis, K, send, body, requireClient } from '../_lib/q.js';

// POST {code} -> records the submitted time (every submit is kept) and returns it
export default async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'method' });
  const code = String(body(req).code || '');
  const s = await requireClient(req, res, code);
  if (!s) return;
  const at = new Date().toISOString();
  await redis.rpush(K.submits(code), JSON.stringify({ at, by: s.name }));
  const company = await redis.hget(K.client(code), 'company');
  return send(res, 200, { ok: true, at, by: s.name, company: company || '' });
}
