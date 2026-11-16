import { redis, hgetall, K, send, body, requireClient } from '../_lib/q.js';

const FIELD_RE = /^[a-z0-9_]{1,40}$/;
const MAX_VALUE = 20000;   // characters per answer
const MAX_FIELDS = 300;    // per save

// GET ?c=CODE -> {answers:{field:value}, lastSaved:{by,at}}
// POST {code, answers:{changed fields}, by} -> merges into the saved answers
export default async function handler(req, res) {
  if (req.method === 'GET') {
    const code = String(req.query.c || '');
    if (!(await requireClient(req, res, code))) return;
    const [answers, client] = await Promise.all([hgetall(K.answers(code)), redis.hmget(K.client(code), 'lastBy', 'lastAt')]);
    const [lastBy, lastAt] = Array.isArray(client) ? client : [client && client.lastBy, client && client.lastAt];
    return send(res, 200, { answers: answers || {}, lastSaved: lastBy ? { by: lastBy, at: lastAt } : null });
  }
  if (req.method === 'POST') {
    const b = body(req);
    const code = String(b.code || '');
    const s = await requireClient(req, res, code);
    if (!s) return;
    const a = b.answers;
    if (!a || typeof a !== 'object' || Array.isArray(a)) return send(res, 400, { error: 'bad answers' });
    const clean = {};
    const keys = Object.keys(a);
    if (keys.length > MAX_FIELDS) return send(res, 400, { error: 'too many fields' });
    for (const k of keys) {
      if (!FIELD_RE.test(k)) return send(res, 400, { error: 'bad field' });
      const v = a[k] == null ? '' : String(a[k]);
      if (v.length > MAX_VALUE) return send(res, 400, { error: 'answer too long' });
      clean[k] = v;
    }
    const at = new Date().toISOString();
    const by = s.name; // the signed-in person's name, not whatever the request claims
    if (keys.length) await redis.hset(K.answers(code), clean);
    await redis.hset(K.client(code), { lastBy: by, lastAt: at });
    return send(res, 200, { ok: true, lastSaved: { by, at } });
  }
  return send(res, 405, { error: 'method' });
}
