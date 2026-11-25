import crypto from 'node:crypto';
import net from 'node:net';
import { z } from 'zod';
import { censorProfanity } from './profanity.js';

export const MAX_BODY_BYTES = 32 * 1024;
export const ADMIN_SESSION_COOKIE = 'lampor_admin_session';
export const ADMIN_CSRF_COOKIE = 'lampor_csrf';
export const ADMIN_CSRF_HEADER = 'x-lampor-csrf';
export const POW_DIFFICULTY = 3;
export const POW_TTL_MS = 5 * 60 * 1000;
export const ACCOUNT_LOCKOUT_MAX_ATTEMPTS = 5;
export const ACCOUNT_LOCKOUT_MINUTES = 15;
export const ALLOWED_ITEM_IDS = ['jamu', 'baterai', 'energy_drink', 'kentongan'];
export const ALLOWED_DIFFICULTIES = ['easy', 'normal', 'hard', 'nightmare'];

let warnedMissingSecret = false;

export function getAuthSecret() {
  const secret = process.env.AUTH_SECRET;
  if (secret && secret.trim().length >= 16) {
    return secret;
  }
  if (!warnedMissingSecret) {
    warnedMissingSecret = true;
    console.warn('[security] AUTH_SECRET is missing or short; using dev-only deterministic fallback secret.');
  }
  return 'lampor-dev-only-deterministic-fallback-secret-v1.3.0';
}

export function hashPassword(password) {
  const randomSaltHex16 = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(password), randomSaltHex16, 64).toString('hex');
  return `${randomSaltHex16}:${derived}`;
}

export function verifyPassword(password, storedHash) {
  if (typeof storedHash !== 'string' || !storedHash.includes(':')) {
    return false;
  }
  const parts = storedHash.split(':');
  if (parts.length !== 2) {
    return false;
  }
  const [salt, expectedHex] = parts;
  if (!salt || !/^[a-f0-9]{128}$/i.test(expectedHex)) {
    return false;
  }
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  const actualBuf = crypto.scryptSync(String(password), salt, 64);
  if (actualBuf.length !== expectedBuf.length) {
    return false;
  }
  return crypto.timingSafeEqual(actualBuf, expectedBuf);
}

export function hashToken(rawToken) {
  return crypto.createHash('sha256').update(String(rawToken)).digest('hex');
}

export function generateRandomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

export function timingSafeEqualStrings(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

export function signChallenge({ challengeId, salt, difficulty, expiresAt }) {
  const payload = `${challengeId}:${salt}:${difficulty}:${expiresAt}`;
  return crypto.createHmac('sha256', getAuthSecret()).update(payload).digest('hex');
}

export function createPowChallenge(difficulty = POW_DIFFICULTY) {
  const challengeId = crypto.randomUUID();
  const salt = crypto.randomBytes(16).toString('hex');
  const expiresAt = Date.now() + POW_TTL_MS;
  const signature = signChallenge({ challengeId, salt, difficulty, expiresAt });
  return {
    ok: true,
    challengeId,
    salt,
    difficulty,
    expiresAt,
    signature,
  };
}

const challengeSchema = z.strictObject({
  challengeId: z.string().min(8).max(128),
  salt: z.string().regex(/^[a-f0-9]{16,64}$/i),
  difficulty: z.number().int().min(POW_DIFFICULTY).max(6),
  expiresAt: z.number().finite().positive(),
  signature: z.string().regex(/^[a-f0-9]{64}$/i),
  nonce: z.union([
    z.number().int().min(0).max(100_000_000),
    z.string().regex(/^\d{1,9}$/),
  ]),
});

export function verifyPowChallenge(challenge) {
  const parsed = challengeSchema.safeParse(challenge);
  if (!parsed.success) {
    return { ok: false, reason: 'Format verifikasi anti-bot tidak valid.' };
  }
  const data = parsed.data;
  const now = Date.now();
  if (now > data.expiresAt || data.expiresAt > now + POW_TTL_MS * 2) {
    return { ok: false, reason: 'Tantangan anti-bot kedaluwarsa. Muat ulang tantangan.' };
  }
  const expectedSig = signChallenge({
    challengeId: data.challengeId,
    salt: data.salt,
    difficulty: data.difficulty,
    expiresAt: data.expiresAt,
  });
  if (!timingSafeEqualStrings(expectedSig, data.signature.toLowerCase())) {
    return { ok: false, reason: 'Tanda tangan anti-bot tidak sah.' };
  }
  const hash = crypto
    .createHash('sha256')
    .update(`${data.salt}:${String(data.nonce)}`)
    .digest('hex');
  if (!hash.startsWith('0'.repeat(data.difficulty))) {
    return { ok: false, reason: 'Bukti PoW anti-bot belum memenuhi target.' };
  }
  return { ok: true };
}

export function sanitizeText(value, maxLen = 200) {
  if (value === null || value === undefined) {
    return '';
  }
  let s = String(value);
  s = s.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  s = s.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');
  s = s.replace(/<[^>]*>/g, '');
  s = s.replace(/[<>"'&]/g, '');
  s = s.replace(/[\u0000-\u001F\u007F]/g, ' ');
  return s.trim().slice(0, maxLen);
}

export function sanitizeProfileText(value, maxLen = 200, allowNewlines = false) {
  if (value === null || value === undefined) {
    return '';
  }
  let s = String(value);
  s = s.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  s = s.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');
  s = s.replace(/<[^>]*>/g, '');
  s = s.replace(/[<>"`]/g, '');
  if (allowNewlines) {
    s = s.replace(/\r\n?/g, '\n');
    s = s.replace(/[\u0000-\u0009\u000B-\u001F\u007F]/g, ' ');
    s = s.replace(/\n{3,}/g, '\n\n');
  } else {
    s = s.replace(/[\u0000-\u001F\u007F]/g, ' ');
  }
  return s.trim().slice(0, maxLen);
}

function detectAvatarImageMime(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 16 || buf.length > 16384) {
    return null;
  }
  // JPEG: FF D8 FF
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return { mime: 'image/jpeg', ext: 'jpg' };
  }
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47 &&
    buf[4] === 0x0d &&
    buf[5] === 0x0a &&
    buf[6] === 0x1a &&
    buf[7] === 0x0a
  ) {
    return { mime: 'image/png', ext: 'png' };
  }
  // WEBP: RIFF....WEBP
  if (
    buf.length >= 16 &&
    buf.subarray(0, 4).toString('ascii') === 'RIFF' &&
    buf.subarray(8, 12).toString('ascii') === 'WEBP'
  ) {
    return { mime: 'image/webp', ext: 'webp' };
  }
  return null;
}

export function detectAvatarExtFromDataUrl(value) {
  if (typeof value !== 'string') return '';
  if (value.startsWith('data:image/jpeg;base64,')) return 'jpg';
  if (value.startsWith('data:image/png;base64,')) return 'png';
  if (value.startsWith('data:image/webp;base64,')) return 'webp';
  return '';
}

export function rewriteAvatarFilename(_rawFilename = '', mimeExt = 'jpg') {
  const safeExt = ['jpg', 'png', 'webp'].includes(mimeExt) ? mimeExt : 'jpg';
  return `avatar_${crypto.randomBytes(8).toString('hex')}.${safeExt}`;
}

export function sanitizeAvatarUrl(value) {
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value !== 'string') {
    return null;
  }
  const s = value.trim();
  if (!s) {
    return '';
  }
  if (/^preset:[a-z0-9_-]{1,24}$/.test(s)) {
    return s;
  }
  const match = /^data:image\/(png|jpeg|jpg|webp);base64,([A-Za-z0-9+/=]{16,19500})$/.exec(s);
  if (!match) {
    return null;
  }
  let buf;
  try {
    buf = Buffer.from(match[2], 'base64');
  } catch {
    return null;
  }
  const detected = detectAvatarImageMime(buf);
  if (!detected) {
    return null;
  }
  return `data:${detected.mime};base64,${buf.toString('base64')}`;
}

export function sanitizeDeepValue(value, depth = 0) {
  if (depth > 4) {
    return null;
  }
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value === 'string') {
    return sanitizeText(value, 300);
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : 0;
  }
  if (typeof value === 'boolean') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 50).map((item) => sanitizeDeepValue(item, depth + 1));
  }
  if (typeof value === 'object') {
    const out = {};
    const entries = Object.entries(value).slice(0, 40);
    for (const [rawKey, val] of entries) {
      if (rawKey === '__proto__' || rawKey === 'constructor' || rawKey === 'prototype') {
        continue;
      }
      const key = sanitizeText(rawKey, 48);
      if (key) {
        out[key] = sanitizeDeepValue(val, depth + 1);
      }
    }
    return out;
  }
  return null;
}

export function hasDangerousPrototypeKey(obj, depth = 0) {
  if (depth > 6 || obj === null || typeof obj !== 'object') {
    return false;
  }
  if (Array.isArray(obj)) {
    return obj.some((item) => hasDangerousPrototypeKey(item, depth + 1));
  }
  for (const key of Object.keys(obj)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return true;
    }
    if (hasDangerousPrototypeKey(obj[key], depth + 1)) {
      return true;
    }
  }
  return false;
}

export const usernameSchema = z
  .string()
  .regex(/^[a-zA-Z0-9_]{3,24}$/, 'Username harus 3-24 karakter (huruf, angka, atau underscore).');

export const strongPasswordSchema = z
  .string()
  .min(8, 'Password minimal 8 karakter.')
  .max(72, 'Password maksimal 72 karakter.')
  .regex(/[a-zA-Z]/, 'Password wajib mengandung minimal 1 huruf.')
  .regex(/[0-9]/, 'Password wajib mengandung minimal 1 angka.');

export const loginPasswordSchema = z
  .string()
  .min(1, 'Password wajib diisi.')
  .max(72, 'Password maksimal 72 karakter.');

export function isValidIpAddress(ip) {
  return typeof ip === 'string' && net.isIP(ip.trim()) !== 0;
}

export function getClientIp(req) {
  const forwarded = req.headers?.['x-forwarded-for'];
  let candidate = '';
  if (typeof forwarded === 'string' && forwarded.trim().length > 0) {
    candidate = forwarded.split(',')[0].trim();
  } else if (Array.isArray(forwarded) && forwarded.length > 0) {
    candidate = String(forwarded[0]).split(',')[0].trim();
  } else if (typeof req.headers?.['x-real-ip'] === 'string') {
    candidate = req.headers['x-real-ip'].trim();
  } else if (req.socket?.remoteAddress) {
    candidate = String(req.socket.remoteAddress).trim();
  }
  if (candidate.startsWith('::ffff:')) {
    candidate = candidate.slice(7);
  }
  if (candidate === '::1') {
    return '127.0.0.1';
  }
  return isValidIpAddress(candidate) ? candidate : '127.0.0.1';
}

export function parseCookies(req) {
  const header = req.headers?.cookie;
  const cookies = {};
  if (!header || typeof header !== 'string') {
    return cookies;
  }
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const name = part.slice(0, idx).trim();
    const rawVal = part.slice(idx + 1).trim();
    if (!name || name === '__proto__' || name === 'constructor' || name === 'prototype') continue;
    try {
      cookies[name] = decodeURIComponent(rawVal);
    } catch {
      cookies[name] = rawVal;
    }
  }
  return cookies;
}

export function getBearerToken(req) {
  const authHeader = req.headers?.authorization;
  if (typeof authHeader !== 'string') {
    return '';
  }
  const match = /^Bearer\s+([a-zA-Z0-9._-]+)$/i.exec(authHeader.trim());
  return match ? match[1] : '';
}

function isAllowedAdminOrigin(req, origin) {
  if (!origin || typeof origin !== 'string') {
    return false;
  }
  let parsedOrigin;
  try {
    parsedOrigin = new URL(origin);
  } catch {
    return false;
  }
  if (!['http:', 'https:'].includes(parsedOrigin.protocol)) {
    return false;
  }
  const reqHost = String(req.headers?.['x-forwarded-host'] || req.headers?.host || '').toLowerCase();
  if (reqHost && parsedOrigin.host.toLowerCase() === reqHost) {
    return true;
  }
  if (/^(localhost|127\.0\.0\.1)$/i.test(parsedOrigin.hostname)) {
    return true;
  }
  const extra = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const allowedDefaults = new Set([
    'https://lampor.vercel.app',
    'https://lampor-website.vercel.app',
    ...extra,
  ]);
  return allowedDefaults.has(parsedOrigin.origin.toLowerCase());
}

export function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
}

export function applyCorsHeaders(req, res, { allowCredentials = false } = {}) {
  const origin = req.headers?.origin;
  if (allowCredentials) {
    if (origin && isAllowedAdminOrigin(req, origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Vary', 'Origin');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-Lampor-CSRF, X-Lampor-Client-Version'
    );
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-Lampor-Client-Version'
    );
  }
}

export function sendJson(res, statusCode, payload) {
  res.status(statusCode).json(payload);
}

export function setAdminCookies(req, res, { sessionToken, csrfToken, maxAgeSec = 43200 }) {
  const isHttps =
    String(req.headers?.['x-forwarded-proto'] || '').includes('https') ||
    Boolean(req.socket?.encrypted);
  const secureFlag = isHttps ? '; Secure' : '';
  res.setHeader('Set-Cookie', [
    `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(sessionToken)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secureFlag}`,
    `${ADMIN_CSRF_COOKIE}=${encodeURIComponent(csrfToken)}; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secureFlag}`,
  ]);
}

export function clearAdminCookies(req, res) {
  const isHttps =
    String(req.headers?.['x-forwarded-proto'] || '').includes('https') ||
    Boolean(req.socket?.encrypted);
  const secureFlag = isHttps ? '; Secure' : '';
  const expired = 'Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
  res.setHeader('Set-Cookie', [
    `${ADMIN_SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; ${expired}${secureFlag}`,
    `${ADMIN_CSRF_COOKIE}=; SameSite=Strict; Path=/; ${expired}${secureFlag}`,
  ]);
}

export function verifyAdminCsrf(req, expectedCsrfToken) {
  const cookies = parseCookies(req);
  const cookieCsrf = cookies[ADMIN_CSRF_COOKIE];
  const headerRaw = req.headers?.[ADMIN_CSRF_HEADER];
  const headerCsrf = Array.isArray(headerRaw) ? headerRaw[0] : headerRaw;
  if (!cookieCsrf || !headerCsrf || typeof headerCsrf !== 'string') {
    return false;
  }
  if (!timingSafeEqualStrings(cookieCsrf, headerCsrf)) {
    return false;
  }
  if (expectedCsrfToken && !timingSafeEqualStrings(cookieCsrf, expectedCsrfToken)) {
    return false;
  }
  return true;
}

export async function readJsonBody(req, maxBytes = MAX_BODY_BYTES) {
  const contentLengthHeader = req.headers?.['content-length'];
  if (contentLengthHeader !== undefined) {
    const contentLen = Number(contentLengthHeader);
    if (Number.isFinite(contentLen) && contentLen > maxBytes) {
      return {
        ok: false,
        status: 413,
        error: 'Payload terlalu besar (maksimal 32KB).',
        code: 'PAYLOAD_TOO_LARGE',
      };
    }
  }

  let parsed = null;

  if (req.body !== undefined) {
    if (Buffer.isBuffer(req.body)) {
      if (req.body.length > maxBytes) {
        return {
          ok: false,
          status: 413,
          error: 'Payload terlalu besar (maksimal 32KB).',
          code: 'PAYLOAD_TOO_LARGE',
        };
      }
      const rawText = req.body.toString('utf8').trim();
      if (!rawText) {
        parsed = {};
      } else {
        try {
          parsed = JSON.parse(rawText);
        } catch {
          return { ok: false, status: 400, error: 'Format JSON tidak valid.', code: 'INVALID_JSON' };
        }
      }
    } else if (typeof req.body === 'string') {
      if (Buffer.byteLength(req.body, 'utf8') > maxBytes) {
        return {
          ok: false,
          status: 413,
          error: 'Payload terlalu besar (maksimal 32KB).',
          code: 'PAYLOAD_TOO_LARGE',
        };
      }
      const rawText = req.body.trim();
      if (!rawText) {
        parsed = {};
      } else {
        try {
          parsed = JSON.parse(rawText);
        } catch {
          return { ok: false, status: 400, error: 'Format JSON tidak valid.', code: 'INVALID_JSON' };
        }
      }
    } else if (typeof req.body === 'object' && req.body !== null) {
      const byteSize = Buffer.byteLength(JSON.stringify(req.body), 'utf8');
      if (byteSize > maxBytes) {
        return {
          ok: false,
          status: 413,
          error: 'Payload terlalu besar (maksimal 32KB).',
          code: 'PAYLOAD_TOO_LARGE',
        };
      }
      parsed = req.body;
    } else {
      return { ok: false, status: 400, error: 'Body permintaan harus berupa objek JSON.', code: 'INVALID_JSON' };
    }
  } else {
    const chunks = [];
    let totalBytes = 0;
    let tooLarge = false;
    await new Promise((resolve, reject) => {
      req.on('data', (chunk) => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalBytes += buf.length;
        if (totalBytes > maxBytes) {
          tooLarge = true;
          req.destroy();
          resolve();
          return;
        }
        chunks.push(buf);
      });
      req.on('end', resolve);
      req.on('error', (err) => {
        if (tooLarge) resolve();
        else reject(err);
      });
    });

    if (tooLarge) {
      return {
        ok: false,
        status: 413,
        error: 'Payload terlalu besar (maksimal 32KB).',
        code: 'PAYLOAD_TOO_LARGE',
      };
    }

    const raw = Buffer.concat(chunks).toString('utf8').trim();
    if (!raw) {
      parsed = {};
    } else {
      try {
        parsed = JSON.parse(raw);
      } catch {
        return { ok: false, status: 400, error: 'Format JSON tidak valid.', code: 'INVALID_JSON' };
      }
    }
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, status: 400, error: 'Body permintaan harus berupa objek JSON.', code: 'INVALID_JSON' };
  }
  if (hasDangerousPrototypeKey(parsed)) {
    return { ok: false, status: 400, error: 'Kunci objek tidak diizinkan.', code: 'UNSAFE_KEYS' };
  }
  return { ok: true, body: parsed };
}

export function checkHoneypot(body) {
  const val = body?.website;
  if (val === undefined || val === null) {
    return true;
  }
  return typeof val === 'string' && val.trim().length === 0;
}

export function formatZodError(zodError) {
  const first = zodError?.issues?.[0];
  if (!first) {
    return 'Data permintaan tidak valid.';
  }
  if (first.code === 'unrecognized_keys' && Array.isArray(first.keys)) {
    return `Field tidak dikenali: ${first.keys.join(', ')}`;
  }
  return first.message || 'Data permintaan tidak valid.';
}

export function normalizeItemStash(rawStash) {
  const out = { jamu: 0, baterai: 0, energy_drink: 0, kentongan: 0 };
  if (!rawStash || typeof rawStash !== 'object') {
    return out;
  }
  for (const key of ALLOWED_ITEM_IDS) {
    const num = Math.trunc(Number(rawStash[key] ?? 0));
    out[key] = Number.isFinite(num) ? Math.min(5, Math.max(0, num)) : 0;
  }
  return out;
}

export function normalizeRedeemedCodes(rawCodes) {
  if (!Array.isArray(rawCodes)) {
    return [];
  }
  const seen = new Set();
  const out = [];
  for (const entry of rawCodes) {
    if (typeof entry !== 'string') continue;
    const norm = entry.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (norm && !seen.has(norm)) {
      seen.add(norm);
      out.push(norm);
      if (out.length >= 50) break;
    }
  }
  return out;
}

export function serializePlayerUser(user) {
  return {
    id: user.id,
    username: censorProfanity(user.username || ''),
    displayName: censorProfanity(sanitizeProfileText(user.display_name || '', 32, false)),
    bio: censorProfanity(sanitizeProfileText(user.bio || '', 200, true)),
    avatarUrl: sanitizeAvatarUrl(user.avatar_url || '') ?? '',
    role: user.role,
    isVerified: Boolean(user.is_verified),
    isBanned: Boolean(user.is_banned),
    banReason: sanitizeText(user.ban_reason || '', 240),
    coins: Math.min(999999999, Math.max(0, Number(user.coins ?? 0))),
    totalWins: Math.max(0, Number(user.total_wins ?? 0)),
    extraLives: Math.min(5, Math.max(0, Number(user.extra_lives ?? 0))),
    itemStash: normalizeItemStash(user.item_stash),
    redeemedCodes: normalizeRedeemedCodes(user.redeemed_codes),
    saveSeq: Math.max(0, Number(user.save_seq ?? 0)),
    tutorialCompleted: Boolean(user.tutorial_completed),
    lastLoginAt: user.last_login_at ? new Date(user.last_login_at).toISOString() : null,
    createdAt: user.created_at ? new Date(user.created_at).toISOString() : null,
  };
}

export function serializeAdminUserRow(user) {
  return {
    ...serializePlayerUser(user),
    username: user.username,
    failedLoginAttempts: Number(user.failed_login_attempts ?? 0),
    lockedUntil: user.locked_until ? new Date(user.locked_until).toISOString() : null,
    lastLoginIp: user.last_login_ip || '',
    updatedAt: user.updated_at ? new Date(user.updated_at).toISOString() : null,
  };
}

export function serializeRoomPlayer(player) {
  return {
    userId: player.user_id,
    username: censorProfanity(player.username || ''),
    isHost: Boolean(player.is_host),
    isReady: Boolean(player.is_ready),
    isVerified: Boolean(player.is_verified),
    playerState: sanitizeDeepValue(player.player_state || {}) || {},
    joinedAt: player.joined_at ? new Date(player.joined_at).toISOString() : null,
    lastSeenAt: player.last_seen_at ? new Date(player.last_seen_at).toISOString() : null,
  };
}

export function serializeRoom(room, players = [], hostUsername = '') {
  const hostFromPlayers = players.find((p) => p.is_host || p.user_id === room.host_user_id);
  return {
    id: room.id,
    roomCode: room.room_code,
    name: censorProfanity(sanitizeText(room.name, 60)),
    hostUserId: room.host_user_id,
    hostUsername: censorProfanity(hostUsername || hostFromPlayers?.username || ''),
    hostIsVerified: Boolean(hostFromPlayers?.is_verified),
    mode: room.mode,
    status: room.status,
    difficulty: room.difficulty,
    maxPlayers: Number(room.max_players ?? 4),
    playerCount: players.length,
    hasPassword: Boolean(room.password_hash),
    canUseShopItems: Boolean(room.can_use_shop_items),
    allowLateJoin: Boolean(room.allow_late_join),
    settings: sanitizeDeepValue(room.settings || {}) || {},
    announcement: censorProfanity(sanitizeText(room.announcement || '', 240)),
    lastEventSeq: Number(room.last_event_seq ?? 0),
    createdAt: room.created_at ? new Date(room.created_at).toISOString() : null,
    lastActivityAt: room.last_activity_at ? new Date(room.last_activity_at).toISOString() : null,
  };
}

export function serializeRoomEvent(ev) {
  const payload = sanitizeDeepValue(ev.payload || {}) || {};
  if (ev.event_type === 'chat') {
    if (typeof payload.text === 'string') {
      payload.text = censorProfanity(payload.text);
    }
    if (typeof payload.message === 'string') {
      payload.message = censorProfanity(payload.message);
    }
  }
  return {
    id: ev.id,
    seq: Number(ev.seq),
    type: ev.event_type,
    eventType: ev.event_type,
    senderUserId: ev.sender_user_id || null,
    senderUsername: censorProfanity(sanitizeText(ev.sender_username || '', 32)),
    senderIsVerified: Boolean(payload.senderIsVerified || ev.sender_is_verified),
    payload,
    createdAt: ev.created_at ? new Date(ev.created_at).toISOString() : null,
  };
}

export function serializeServerSettings(row) {
  return {
    maintenanceMode: Boolean(row.maintenance_mode),
    maintenanceMessage: sanitizeText(row.maintenance_message || '', 300),
    allowRegistration: Boolean(row.allow_registration),
    allowMultiplayer: Boolean(row.allow_multiplayer),
    allowSandbox: Boolean(row.allow_sandbox),
    maxActiveRooms: Math.max(1, Number(row.max_active_rooms ?? 50)),
    globalAnnouncement: sanitizeText(row.global_announcement || '', 300),
    minClientVersion: sanitizeText(row.min_client_version || '1.3.0', 32),
    updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : null,
    updatedBy: sanitizeText(row.updated_by || 'system', 40),
  };
}

export function serializeSecurityLog(row) {
  return {
    id: row.id,
    eventType: row.event_type,
    severity: row.severity,
    username: row.username || '',
    ipAddress: row.ip_address || '',
    path: row.path || '',
    details: sanitizeDeepValue(row.details || {}) || {},
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
  };
}

export function serializeAuditLog(row) {
  return {
    id: row.id,
    adminUserId: row.admin_user_id || null,
    adminUsername: row.admin_username,
    action: row.action,
    targetType: row.target_type || '',
    targetId: row.target_id || '',
    details: sanitizeDeepValue(row.details || {}) || {},
    ipAddress: row.ip_address || '',
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
  };
}

export function serializeIpBlock(row) {
  const expiresAt = row.expires_at ? new Date(row.expires_at) : null;
  const isActive = !expiresAt || expiresAt.getTime() > Date.now();
  return {
    id: row.id,
    ipAddress: row.ip_address,
    reason: sanitizeText(row.reason || '', 240),
    blockedBy: row.blocked_by || 'admin',
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
    isActive,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
  };
}

export function serializeRedeemCode(row) {
  return {
    code: row.code,
    rewardType: row.reward_type,
    itemId: row.item_id || '',
    quantity: Number(row.quantity ?? 0),
    maxUses: row.max_uses === null || row.max_uses === undefined ? null : Number(row.max_uses),
    usesCount: Number(row.uses_count ?? 0),
    descriptionId: sanitizeText(row.description_id || '', 200),
    descriptionEn: sanitizeText(row.description_en || '', 200),
    isActive: Boolean(row.is_active),
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
    updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : null,
  };
}

export function getRouteAction(req) {
  const qAction = req.query?.action;
  if (typeof qAction === 'string' && qAction.trim()) {
    return qAction.trim().toLowerCase();
  }
  if (Array.isArray(qAction) && qAction[0]) {
    return String(qAction[0]).trim().toLowerCase();
  }
  const urlPath = String(req.url || '').split('?')[0];
  const segments = urlPath.split('/').filter(Boolean);
  return (segments[segments.length - 1] || '').toLowerCase();
}

export async function runSecurityPreflight(
  req,
  res,
  db,
  {
    allowCredentials = false,
    rateCategory = 'general',
    rateLimit = null,
    windowMs = 60_000,
    parseBody = false,
    enforceHoneypot = false,
  } = {}
) {
  applySecurityHeaders(res);
  applyCorsHeaders(req, res, { allowCredentials });

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return { handled: true };
  }

  const ip = getClientIp(req);
  const pathStr = String(req.url || '').split('?')[0] || '/';

  const blocked = await db.isIpBlocked(ip);
  if (blocked) {
    await db.addSecurityLog({
      eventType: 'ip_blocked_attempt',
      severity: 'high',
      ipAddress: ip,
      path: pathStr,
      details: { reason: blocked.reason || '' },
    });
    sendJson(res, 403, {
      ok: false,
      error: 'Akses ditolak: alamat IP diblokir.',
      code: 'IP_BLOCKED',
    });
    return { handled: true };
  }

  let effectiveLimit = rateLimit;
  if (!effectiveLimit) {
    if (rateCategory === 'auth') {
      effectiveLimit = Number(process.env.LAMPOR_RATE_LIMIT_AUTH || 40);
    } else if (rateCategory === 'sync') {
      effectiveLimit = Number(process.env.LAMPOR_RATE_LIMIT_SYNC || 420);
    } else {
      effectiveLimit = Number(process.env.LAMPOR_RATE_LIMIT_GENERAL || 300);
    }
  }

  const rl = await db.checkAndConsumeRateLimit({
    bucketKey: `${rateCategory}:${ip}`,
    limit: effectiveLimit,
    windowMs,
  });
  if (!rl.allowed) {
    res.setHeader('Retry-After', String(rl.retryAfterSec));
    await db.addSecurityLog({
      eventType: 'rate_limit_hit',
      severity: 'warn',
      ipAddress: ip,
      path: pathStr,
      details: { category: rateCategory, retryAfterSec: rl.retryAfterSec },
    });
    sendJson(res, 429, {
      ok: false,
      error: 'Terlalu banyak permintaan. Silakan coba lagi sebentar.',
      code: 'RATE_LIMITED',
      retryAfterSec: rl.retryAfterSec,
    });
    return { handled: true };
  }

  let body = {};
  if (parseBody) {
    const parsed = await readJsonBody(req);
    if (!parsed.ok) {
      sendJson(res, parsed.status, {
        ok: false,
        error: parsed.error,
        code: parsed.code,
      });
      return { handled: true };
    }
    body = parsed.body;
    if (enforceHoneypot && !checkHoneypot(body)) {
      await db.addSecurityLog({
        eventType: 'honeypot_triggered',
        severity: 'high',
        ipAddress: ip,
        path: pathStr,
        details: { username: typeof body.username === 'string' ? body.username.slice(0, 32) : '' },
      });
      sendJson(res, 400, {
        ok: false,
        error: 'Permintaan tidak valid.',
        code: 'HONEYPOT_TRIGGERED',
      });
      return { handled: true };
    }
  }

  return { handled: false, ip, pathStr, body };
}

export async function requirePlayerSession(req, res, db) {
  const rawToken = getBearerToken(req);
  if (!rawToken) {
    sendJson(res, 401, {
      ok: false,
      error: 'Autentikasi akun diperlukan.',
      code: 'UNAUTHORIZED',
    });
    return null;
  }
  const tokenHash = hashToken(rawToken);
  const found = await db.getSessionWithUser(tokenHash, 'player');
  if (!found) {
    sendJson(res, 401, {
      ok: false,
      error: 'Sesi tidak valid atau telah berakhir.',
      code: 'SESSION_EXPIRED',
    });
    return null;
  }
  if (found.user.is_banned) {
    sendJson(res, 403, {
      ok: false,
      error: 'Akun ini diblokir.',
      reason: sanitizeText(found.user.ban_reason || '', 240),
      code: 'ACCOUNT_BANNED',
    });
    return null;
  }
  return { ...found, tokenHash };
}

export async function requireAdminSession(req, res, db, ip, { requireCsrf = false } = {}) {
  const cookies = parseCookies(req);
  const rawToken = cookies[ADMIN_SESSION_COOKIE];
  if (!rawToken) {
    sendJson(res, 401, {
      ok: false,
      error: 'Login admin diperlukan.',
      code: 'ADMIN_UNAUTHORIZED',
    });
    return null;
  }
  const tokenHash = hashToken(rawToken);
  const found = await db.getSessionWithUser(tokenHash, 'admin');
  if (!found) {
    sendJson(res, 401, {
      ok: false,
      error: 'Sesi admin tidak valid atau kedaluwarsa.',
      code: 'ADMIN_SESSION_EXPIRED',
    });
    return null;
  }
  if (found.user.role !== 'admin' || found.user.is_banned) {
    sendJson(res, 403, {
      ok: false,
      error: 'Akses ditolak.',
      code: 'ADMIN_FORBIDDEN',
    });
    return null;
  }
  if (requireCsrf && !verifyAdminCsrf(req, found.session.csrf_token)) {
    await db.addSecurityLog({
      eventType: 'csrf_invalid',
      severity: 'high',
      username: found.user.username,
      ipAddress: ip,
      path: String(req.url || '').split('?')[0] || '/api/admin',
      details: { userId: found.user.id },
    });
    sendJson(res, 403, {
      ok: false,
      error: 'CSRF token tidak valid atau hilang.',
      code: 'CSRF_INVALID',
    });
    return null;
  }
  return { ...found, tokenHash };
}

