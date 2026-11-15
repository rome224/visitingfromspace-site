import { redis, K, send, validCode, clientSession } from '../_lib/q.js';

// GET ?c=CODE -> 200 {name} if this browser is signed in to CODE | 401 not signed in | 404 unknown link
export default async function handler(req, res) {
  if (req.method !== 'GET') return send(res, 405, { error: 'method' });
  const code = String(req.query.c || '');
  if (!validCode(code) || !(await redis.exists(K.client(code)))) return send(res, 404, { error: 'unknown' });
  const s = await clientSession(req);
  if (!s || s.code !== code) return send(res, 401, { error: 'not signed in' });
  return send(res, 200, { name: s.name });
}
