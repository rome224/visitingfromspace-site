import bcrypt from 'bcryptjs';
import { redis, K, send, body, validCode, isLocked, recordFailure, token, setCookie, CLIENT_COOKIE, SESSION_TTL } from '../_lib/q.js';

// POST {code, pin, name} -> 200 ok | 401 wrong PIN | 429 locked | 404 unknown link
export default async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'method' });
  const { code, pin, name } = body(req);
  if (!validCode(code)) return send(res, 404, { error: 'unknown' });
  const client = await redis.hgetall(K.client(code));
  if (!client || !client.pinHash) return send(res, 404, { error: 'unknown' });
  if (await isLocked(K.lock(code))) return send(res, 429, { error: 'locked' });

  const cleanName = String(name || '').trim().slice(0, 60);
  const ok = typeof pin === 'string' && /^\d{6}$/.test(pin) && await bcrypt.compare(pin, client.pinHash);
  if (!ok) {
    const nowLocked = await recordFailure(K.fail(code), K.lock(code));
    return send(res, nowLocked ? 429 : 401, { error: nowLocked ? 'locked' : 'wrong pin' });
  }
  if (!cleanName) return send(res, 400, { error: 'name required' });

  const t = token();
  await redis.set(K.sess(t), JSON.stringify({ code, name: cleanName, pinVer: String(client.pinVer) }), { ex: SESSION_TTL });
  setCookie(res, CLIENT_COOKIE, t, SESSION_TTL);
  return send(res, 200, { ok: true, name: cleanName });
}
