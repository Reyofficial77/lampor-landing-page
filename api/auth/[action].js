import { z } from 'zod';
import * as db from '../_lib/db.js';
import {
  ACCOUNT_LOCKOUT_MINUTES,
  ACCOUNT_LOCKOUT_MAX_ATTEMPTS,
  createPowChallenge,
  formatZodError,
  generateRandomToken,
  getBearerToken,
  getRouteAction,
  hashPassword,
  hashToken,
  loginPasswordSchema,
  requirePlayerSession,
  runSecurityPreflight,
  sanitizeText,
  sendJson,
  serializePlayerUser,
  strongPasswordSchema,
  usernameSchema,
  verifyPassword,
  verifyPowChallenge,
} from '../_lib/security.js';

const registerSchema = z.strictObject({
  username: usernameSchema,
  password: strongPasswordSchema,
  challenge: z.unknown(),
  website: z.string().optional(),
});

const loginSchema = z.strictObject({
  username: usernameSchema,
  password: loginPasswordSchema,
  challenge: z.unknown(),
  website: z.string().optional(),
});

const syncSchema = z.strictObject({
  coins: z.number().finite().optional(),
  totalWins: z.number().finite().optional(),
  extraLives: z.number().finite().optional(),
  itemStash: z.record(z.string(), z.number().finite()).optional(),
  redeemedCodes: z.array(z.string().max(40)).max(100).optional(),
  saveSeq: z.number().finite().optional(),
  tutorialCompleted: z.boolean().optional(),
});

const PLAYER_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export default async function handler(req, res) {
  const action = getRouteAction(req);

  if (action === 'challenge') {
    const pre = await runSecurityPreflight(req, res, db, { rateCategory: 'general' });
    if (pre.handled) return;
    if (req.method !== 'GET') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    return sendJson(res, 200, createPowChallenge());
  }

  if (action === 'register') {
    const pre = await runSecurityPreflight(req, res, db, {
      rateCategory: 'auth',
      parseBody: true,
      enforceHoneypot: true,
    });
    if (pre.handled) return;
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }

    const parsed = registerSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }

    const pow = verifyPowChallenge(parsed.data.challenge);
    if (!pow.ok) {
      await db.addSecurityLog({
        eventType: 'invalid_pow',
        severity: 'warn',
        username: parsed.data.username,
        ipAddress: pre.ip,
        path: pre.pathStr,
        details: { reason: pow.reason },
      });
      return sendJson(res, 400, { ok: false, error: pow.reason, code: 'INVALID_POW' });
    }

    const settings = await db.getServerSettings();
    if (!settings.allow_registration) {
      return sendJson(res, 403, {
        ok: false,
        error: 'Pendaftaran akun baru sedang dinonaktifkan.',
        code: 'REGISTRATION_DISABLED',
      });
    }

    const existing = await db.findUserByUsername(parsed.data.username);
    if (existing) {
      return sendJson(res, 409, {
        ok: false,
        error: 'Username sudah digunakan.',
        code: 'USERNAME_TAKEN',
      });
    }

    let user;
    try {
      user = await db.createUser({
        username: parsed.data.username,
        passwordHash: hashPassword(parsed.data.password),
        role: 'player',
      });
    } catch (err) {
      if (err?.code === '23505') {
        return sendJson(res, 409, {
          ok: false,
          error: 'Username sudah digunakan.',
          code: 'USERNAME_TAKEN',
        });
      }
      throw err;
    }

    const rawToken = generateRandomToken(32);
    const expiresAt = new Date(Date.now() + PLAYER_SESSION_TTL_MS);
    await db.createSession({
      userId: user.id,
      tokenHash: hashToken(rawToken),
      sessionType: 'player',
      ipAddress: pre.ip,
      userAgent: req.headers?.['user-agent'] || '',
      expiresAt,
    });

    return sendJson(res, 201, {
      ok: true,
      token: rawToken,
      expiresAt: expiresAt.toISOString(),
      user: serializePlayerUser(user),
    });
  }

  if (action === 'login') {
    const pre = await runSecurityPreflight(req, res, db, {
      rateCategory: 'auth',
      parseBody: true,
      enforceHoneypot: true,
    });
    if (pre.handled) return;
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }

    const parsed = loginSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }

    const pow = verifyPowChallenge(parsed.data.challenge);
    if (!pow.ok) {
      await db.addSecurityLog({
        eventType: 'invalid_pow',
        severity: 'warn',
        username: parsed.data.username,
        ipAddress: pre.ip,
        path: pre.pathStr,
        details: { reason: pow.reason },
      });
      return sendJson(res, 400, { ok: false, error: pow.reason, code: 'INVALID_POW' });
    }

    const user = await db.findUserByUsername(parsed.data.username);
    if (!user) {
      await db.addSecurityLog({
        eventType: 'login_failed',
        severity: 'warn',
        username: parsed.data.username,
        ipAddress: pre.ip,
        path: pre.pathStr,
        details: { reason: 'unknown_user' },
      });
      return sendJson(res, 401, {
        ok: false,
        error: 'Username atau password salah.',
        code: 'INVALID_CREDENTIALS',
      });
    }

    if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
      await db.addSecurityLog({
        eventType: 'locked_login_attempt',
        severity: 'warn',
        username: user.username,
        ipAddress: pre.ip,
        path: pre.pathStr,
      });
      return sendJson(res, 429, {
        ok: false,
        error: 'Akun terkunci sementara karena terlalu banyak percobaan gagal. Coba lagi nanti.',
        code: 'ACCOUNT_LOCKED',
        lockedUntil: new Date(user.locked_until).toISOString(),
      });
    }

    if (!verifyPassword(parsed.data.password, user.password_hash)) {
      const lockState = await db.recordFailedLogin({
        userId: user.id,
        maxAttempts: ACCOUNT_LOCKOUT_MAX_ATTEMPTS,
        lockMinutes: ACCOUNT_LOCKOUT_MINUTES,
      });
      await db.addSecurityLog({
        eventType: lockState.justLocked ? 'account_locked' : 'login_failed',
        severity: lockState.justLocked ? 'high' : 'warn',
        username: user.username,
        ipAddress: pre.ip,
        path: pre.pathStr,
        details: { failedAttempts: lockState.failedAttempts },
      });
      return sendJson(res, 401, {
        ok: false,
        error: 'Username atau password salah.',
        code: 'INVALID_CREDENTIALS',
      });
    }

    if (user.is_banned) {
      await db.addSecurityLog({
        eventType: 'banned_login_attempt',
        severity: 'warn',
        username: user.username,
        ipAddress: pre.ip,
        path: pre.pathStr,
      });
      return sendJson(res, 403, {
        ok: false,
        error: 'Akun ini diblokir.',
        reason: sanitizeText(user.ban_reason || '', 240),
        code: 'ACCOUNT_BANNED',
      });
    }

    const updatedUser = await db.updateUserLoginSuccess({ userId: user.id, ipAddress: pre.ip });
    const rawToken = generateRandomToken(32);
    const expiresAt = new Date(Date.now() + PLAYER_SESSION_TTL_MS);
    await db.createSession({
      userId: user.id,
      tokenHash: hashToken(rawToken),
      sessionType: 'player',
      ipAddress: pre.ip,
      userAgent: req.headers?.['user-agent'] || '',
      expiresAt,
    });

    return sendJson(res, 200, {
      ok: true,
      token: rawToken,
      expiresAt: expiresAt.toISOString(),
      user: serializePlayerUser(updatedUser),
    });
  }

  if (action === 'logout') {
    const pre = await runSecurityPreflight(req, res, db, { rateCategory: 'general' });
    if (pre.handled) return;
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const rawToken = getBearerToken(req);
    if (rawToken) {
      await db.revokeSessionByTokenHash(hashToken(rawToken));
    }
    return sendJson(res, 200, { ok: true });
  }

  if (action === 'me') {
    const pre = await runSecurityPreflight(req, res, db, { rateCategory: 'general' });
    if (pre.handled) return;
    if (req.method !== 'GET') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const auth = await requirePlayerSession(req, res, db);
    if (!auth) return;
    return sendJson(res, 200, { ok: true, user: serializePlayerUser(auth.user) });
  }

  if (action === 'sync') {
    const pre = await runSecurityPreflight(req, res, db, {
      rateCategory: 'sync',
      parseBody: true,
    });
    if (pre.handled) return;
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const auth = await requirePlayerSession(req, res, db);
    if (!auth) return;

    const parsed = syncSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }

    const updated = await db.syncUserProfile({
      userId: auth.user.id,
      coins: parsed.data.coins ?? auth.user.coins,
      totalWins: parsed.data.totalWins,
      extraLives: parsed.data.extraLives ?? auth.user.extra_lives,
      itemStash: parsed.data.itemStash ?? auth.user.item_stash,
      redeemedCodes: parsed.data.redeemedCodes ?? [],
      saveSeq: parsed.data.saveSeq ?? auth.user.save_seq,
      tutorialCompleted: parsed.data.tutorialCompleted,
    });

    return sendJson(res, 200, {
      ok: true,
      user: serializePlayerUser(updated),
    });
  }

  const pre = await runSecurityPreflight(req, res, db, { rateCategory: 'general' });
  if (pre.handled) return;
  return sendJson(res, 404, { ok: false, error: 'Endpoint auth tidak ditemukan.', code: 'NOT_FOUND' });
}
