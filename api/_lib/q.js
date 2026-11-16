// Shared helpers for the client questionnaire API.
import { Redis } from '@upstash/redis';
import crypto from 'node:crypto';

// Keep every value as a plain string (no automatic JSON parsing of answers like "25" or "true").
export const redis = Redis.fromEnv({ automaticDeserialization: false });

// With automatic deserialization off, HGETALL comes back as a flat [field, value, ...] list.
export function toObj(raw) {
  if (!raw) return {};
  if (!Array.isArray(raw)) return raw;
  const o = {};
  for (let i = 0; i + 1 < raw.length; i += 2) o[raw[i]] = raw[i + 1];
  return o;
}
export const hgetall = async key => toObj(await redis.hgetall(key));

export const DAY = 24 * 60 * 60;
export const SESSION_TTL = 30 * DAY;           // 30 days
export const LOCK_WINDOW = 15 * 60;            // 15 minutes
export const MAX_TRIES = 5;

export const CLIENT_COOKIE = 'vfs_q_session';
export const ADMIN_COOKIE = 'vfs_q_admin';

// Redis keys
export const K = {
  clients: 'q:clients',                         // set of client codes
  client: c => `q:client:${c}`,                 // hash: company, pinHash, pinVer, created, lastBy, lastAt
  answers: c => `q:ans:${c}`,                   // hash: field -> value
  submits: c => `q:submits:${c}`,               // list of ISO times
  sess: t => `q:sess:${t}`,                     // JSON {code, name, pinVer}
  fail: c => `q:fail:${c}`,                     // wrong-PIN counter
  lock: c => `q:lock:${c}`,                     // lock flag
  admSess: t => `q:adm:${t}`,
  admFail: 'q:admfail',
  admLock: 'q:admlock',
};

export const CODE_RE = /^[a-z0-9]{6,32}$/;
export const validCode = c => typeof c === 'string' && CODE_RE.test(c);

export function noindex(res) {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  res.setHeader('Cache-Control', 'no-store');
}

export function send(res, status, body) {
  noindex(res);
  res.status(status).json(body ?? {});
}

export function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return '';
}

export function setCookie(res, name, value, maxAge) {
  res.setHeader('Set-Cookie', `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`);
}

export const token = () => crypto.randomBytes(32).toString('base64url');

// Short random client code: 12 characters from an unambiguous alphabet (~59 bits).
const ALPHA = 'abcdefghjkmnpqrstuvwxyz23456789';
export function newCode() {
  let s = '';
  for (let i = 0; i < 12; i++) s += ALPHA[crypto.randomInt(ALPHA.length)];
  return s;
}
export const newPin = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');

export function body(req) {
  let b = req.body;
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch { b = {}; } }
  return b && typeof b === 'object' ? b : {};
}

// Five wrong tries inside 15 minutes locks for 15 minutes.
export async function isLocked(lockKey) {
  return !!(await redis.exists(lockKey));
}
export async function recordFailure(failKey, lockKey) {
  const n = await redis.incr(failKey);
  if (n === 1) await redis.expire(failKey, LOCK_WINDOW);
  if (n >= MAX_TRIES) {
    await redis.set(lockKey, '1', { ex: LOCK_WINDOW });
    await redis.del(failKey);
    return true; // now locked
  }
  return false;
}

// Returns the signed-in client session ({code,name}) or null. Checks the client still exists and
// the PIN hasn't been reset since this session was created.
export async function clientSession(req) {
  const t = readCookie(req, CLIENT_COOKIE);
  if (!t || t.length > 100) return null;
  const raw = await redis.get(K.sess(t));
  if (!raw) return null;
  let s; try { s = JSON.parse(raw); } catch { return null; }
  if (!s || !validCode(s.code)) return null;
  const pinVer = await redis.hget(K.client(s.code), 'pinVer');
  if (pinVer === null || pinVer === undefined || String(pinVer) !== String(s.pinVer)) return null;
  return s;
}

// Guard for client data routes. Returns the session, or sends 401/403/400 and returns null.
export async function requireClient(req, res, code) {
  if (!validCode(code)) { send(res, 400, { error: 'bad code' }); return null; }
  const s = await clientSession(req);
  if (!s) { send(res, 401, { error: 'not signed in' }); return null; }
  if (s.code !== code) { send(res, 403, { error: 'forbidden' }); return null; }
  return s;
}

export async function isAdmin(req) {
  const t = readCookie(req, ADMIN_COOKIE);
  if (!t || t.length > 100) return false;
  return !!(await redis.exists(K.admSess(t)));
}

export function safeEqual(a, b) {
  const h = x => crypto.createHash('sha256').update(String(x)).digest();
  return crypto.timingSafeEqual(h(a), h(b)) && String(a).length === String(b).length;
}
