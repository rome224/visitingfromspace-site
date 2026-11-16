import bcrypt from 'bcryptjs';
import {
  redis, toObj, K, send, body, validCode, isLocked, recordFailure, token, setCookie, isAdmin, safeEqual,
  newCode, newPin, readCookie, ADMIN_COOKIE, SESSION_TTL,
} from '../../_lib/q.js';

// /api/questionnaire/admin/{login|me|logout|clients|reset-pin|delete}
export default async function handler(req, res) {
  const action = String(req.query.action || '');

  if (action === 'login') {
    if (req.method !== 'POST') return send(res, 405, { error: 'method' });
    const expected = process.env.ADMIN_PASSWORD;
    if (!expected) return send(res, 503, { error: 'ADMIN_PASSWORD is not set' });
    if (await isLocked(K.admLock)) return send(res, 429, { error: 'locked' });
    const { password } = body(req);
    if (typeof password !== 'string' || !safeEqual(password, expected)) {
      const nowLocked = await recordFailure(K.admFail, K.admLock);
      return send(res, nowLocked ? 429 : 401, { error: nowLocked ? 'locked' : 'wrong password' });
    }
    const t = token();
    await redis.set(K.admSess(t), '1', { ex: SESSION_TTL });
    setCookie(res, ADMIN_COOKIE, t, SESSION_TTL);
    return send(res, 200, { ok: true });
  }

  // Everything below needs the admin cookie.
  if (!(await isAdmin(req))) return send(res, 401, { error: 'not signed in' });

  if (action === 'me') return send(res, 200, { ok: true });

  if (action === 'logout') {
    const t = readCookie(req, ADMIN_COOKIE);
    if (t) await redis.del(K.admSess(t));
    setCookie(res, ADMIN_COOKIE, '', 0);
    return send(res, 200, { ok: true });
  }

  if (action === 'clients' && req.method === 'GET') {
    const codes = (await redis.smembers(K.clients)) || [];
    const out = [];
    if (codes.length) {
      const p = redis.pipeline();
      for (const c of codes) { p.hgetall(K.client(c)); p.hgetall(K.answers(c)); p.lrange(K.submits(c), 0, -1); }
      const r = await p.exec();
      codes.forEach((code, i) => {
        const c = toObj(r[i * 3]), answers = toObj(r[i * 3 + 1]), subs = r[i * 3 + 2] || [];
        if (!c.company) return;
        out.push({
          code, company: c.company, created: c.created, pin: c.pin || null,
          lastSaved: c.lastBy ? { by: c.lastBy, at: c.lastAt } : null,
          submits: subs.map(s => { try { return JSON.parse(s); } catch { return { at: s }; } }),
          answers,
        });
      });
    }
    out.sort((a, b) => String(b.created).localeCompare(String(a.created)));
    return send(res, 200, { clients: out });
  }

  if (action === 'clients' && req.method === 'POST') {
    const company = String(body(req).company || '').trim().slice(0, 120);
    if (!company) return send(res, 400, { error: 'company required' });
    let code;
    for (let i = 0; i < 5; i++) { code = newCode(); if (!(await redis.exists(K.client(code)))) break; }
    const pin = newPin();
    const pinHash = await bcrypt.hash(pin, 10);
    // pinHash checks sign-ins; pin is kept so the admin can look it up later (only admin routes return it)
    await redis.hset(K.client(code), { company, pinHash, pin, pinVer: '1', created: new Date().toISOString() });
    await redis.sadd(K.clients, code);
    return send(res, 200, { code, pin, company });
  }

  if (action === 'reset-pin' && req.method === 'POST') {
    const code = String(body(req).code || '');
    if (!validCode(code) || !(await redis.exists(K.client(code)))) return send(res, 404, { error: 'unknown' });
    const pin = newPin();
    const pinHash = await bcrypt.hash(pin, 10);
    await redis.hset(K.client(code), { pinHash, pin });
    await redis.hincrby(K.client(code), 'pinVer', 1); // signs out everyone using the old PIN
    await redis.del(K.fail(code), K.lock(code));
    return send(res, 200, { code, pin });
  }

  if (action === 'delete' && req.method === 'POST') {
    const code = String(body(req).code || '');
    if (!validCode(code)) return send(res, 404, { error: 'unknown' });
    await redis.del(K.client(code), K.answers(code), K.submits(code), K.fail(code), K.lock(code));
    await redis.srem(K.clients, code);
    return send(res, 200, { ok: true });
  }

  return send(res, 404, { error: 'not found' });
}
