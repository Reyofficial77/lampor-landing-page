import { z } from 'zod';
import * as db from '../_lib/db.js';
import {
  ACCOUNT_LOCKOUT_MINUTES,
  ACCOUNT_LOCKOUT_MAX_ATTEMPTS,
  ALLOWED_ITEM_IDS,
  clearAdminCookies,
  formatZodError,
  generateRandomToken,
  getRouteAction,
  hashPassword,
  hashToken,
  isValidIpAddress,
  loginPasswordSchema,
  requireAdminSession,
  runSecurityPreflight,
  sanitizeText,
  sendJson,
  serializeAdminUserRow,
  serializeAuditLog,
  serializeIpBlock,
  serializeRedeemCode,
  serializeRoom,
  serializeRoomPlayer,
  serializeSecurityLog,
  serializeServerSettings,
  setAdminCookies,
  strongPasswordSchema,
  usernameSchema,
  verifyPassword,
  verifyPowChallenge,
} from '../_lib/security.js';

const ADMIN_SESSION_TTL_SEC = 12 * 3600;

const adminLoginSchema = z.strictObject({
  username: usernameSchema,
  password: loginPasswordSchema,
  challenge: z.unknown(),
  website: z.string().optional(),
});

const usersActionSchema = z.strictObject({
  action: z.enum(['create', 'update', 'ban', 'unban', 'reset_password', 'force_logout', 'delete']),
  userId: z.string().uuid().optional(),
  username: usernameSchema.optional(),
  password: z.string().max(72).optional(),
  coins: z.number().finite().optional(),
  totalWins: z.number().finite().optional(),
  extraLives: z.number().finite().optional(),
  role: z.enum(['player', 'admin']).optional(),
  reason: z.string().max(300).optional(),
});

const roomsActionSchema = z.strictObject({
  action: z.enum(['close_room', 'kick_player', 'broadcast_room', 'cleanup_stale']),
  roomId: z.string().uuid().optional(),
  targetUserId: z.string().uuid().optional(),
  message: z.string().max(300).optional(),
});

const serverSettingsSchema = z.strictObject({
  maintenanceMode: z.boolean().optional(),
  maintenance_mode: z.boolean().optional(),
  maintenanceMessage: z.string().max(400).optional(),
  maintenance_message: z.string().max(400).optional(),
  allowRegistration: z.boolean().optional(),
  allow_registration: z.boolean().optional(),
  allowMultiplayer: z.boolean().optional(),
  allow_multiplayer: z.boolean().optional(),
  allowSandbox: z.boolean().optional(),
  allow_sandbox: z.boolean().optional(),
  maxActiveRooms: z.number().int().min(1).max(500).optional(),
  max_active_rooms: z.number().int().min(1).max(500).optional(),
  globalAnnouncement: z.string().max(400).optional(),
  global_announcement: z.string().max(400).optional(),
  minClientVersion: z.string().max(32).optional(),
  min_client_version: z.string().max(32).optional(),
});

const securityActionSchema = z.strictObject({
  action: z.enum(['block_ip', 'unblock_ip', 'clear_rate_limits']),
  ipAddress: z.string().trim().max(64).optional(),
  reason: z.string().max(300).optional(),
  expiresHours: z.number().finite().min(0).max(8760).nullable().optional(),
});

const redeemActionSchema = z.strictObject({
  action: z.enum(['create', 'toggle', 'delete']),
  code: z.string().trim().min(1).max(40).optional(),
  rewardType: z.enum(['coins', 'lives', 'item']).optional(),
  itemId: z.string().max(40).optional(),
  quantity: z.number().int().min(1).max(999999999).optional(),
  maxUses: z.number().int().min(1).max(1000000).nullable().optional(),
  descriptionId: z.string().max(240).optional(),
  descriptionEn: z.string().max(240).optional(),
  isActive: z.boolean().optional(),
});

export default async function handler(req, res) {
  const action = getRouteAction(req);
  const isLogin = action === 'login';

  const pre = await runSecurityPreflight(req, res, db, {
    allowCredentials: true,
    rateCategory: isLogin ? 'auth' : req.method === 'GET' ? 'sync' : 'general',
    parseBody: req.method === 'POST',
    enforceHoneypot: isLogin && req.method === 'POST',
  });
  if (pre.handled) return;

  if (action === 'login') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = adminLoginSchema.safeParse(pre.body);
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
        eventType: 'admin_login_failed',
        severity: 'warn',
        username: parsed.data.username,
        ipAddress: pre.ip,
        path: pre.pathStr,
        details: { reason: 'unknown_user' },
      });
      return sendJson(res, 401, {
        ok: false,
        error: 'Kredensial admin tidak valid.',
        code: 'INVALID_CREDENTIALS',
      });
    }

    if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
      await db.addSecurityLog({
        eventType: 'locked_admin_login_attempt',
        severity: 'high',
        username: user.username,
        ipAddress: pre.ip,
        path: pre.pathStr,
      });
      return sendJson(res, 429, {
        ok: false,
        error: 'Akun admin terkunci sementara karena terlalu banyak percobaan gagal.',
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
        eventType: lockState.justLocked ? 'account_locked' : 'admin_login_failed',
        severity: lockState.justLocked ? 'high' : 'warn',
        username: user.username,
        ipAddress: pre.ip,
        path: pre.pathStr,
        details: { failedAttempts: lockState.failedAttempts },
      });
      return sendJson(res, 401, {
        ok: false,
        error: 'Kredensial admin tidak valid.',
        code: 'INVALID_CREDENTIALS',
      });
    }

    if (user.role !== 'admin') {
      await db.addSecurityLog({
        eventType: 'admin_login_non_admin',
        severity: 'high',
        username: user.username,
        ipAddress: pre.ip,
        path: pre.pathStr,
      });
      return sendJson(res, 403, {
        ok: false,
        error: 'Akun ini tidak memiliki hak akses admin.',
        code: 'ADMIN_FORBIDDEN',
      });
    }

    if (user.is_banned) {
      return sendJson(res, 403, {
        ok: false,
        error: 'Akun admin ini diblokir.',
        code: 'ACCOUNT_BANNED',
      });
    }

    const updatedAdmin = await db.updateUserLoginSuccess({ userId: user.id, ipAddress: pre.ip });
    const rawToken = generateRandomToken(32);
    const csrfToken = generateRandomToken(32);
    const expiresAt = new Date(Date.now() + ADMIN_SESSION_TTL_SEC * 1000);

    await db.createSession({
      userId: user.id,
      tokenHash: hashToken(rawToken),
      sessionType: 'admin',
      csrfToken,
      ipAddress: pre.ip,
      userAgent: req.headers?.['user-agent'] || '',
      expiresAt,
    });

    await db.addAuditLog({
      adminUserId: user.id,
      adminUsername: user.username,
      action: 'admin_login',
      targetType: 'session',
      targetId: user.id,
      ipAddress: pre.ip,
    });

    setAdminCookies(req, res, {
      sessionToken: rawToken,
      csrfToken,
      maxAgeSec: ADMIN_SESSION_TTL_SEC,
    });

    return sendJson(res, 200, {
      ok: true,
      csrfToken,
      admin: serializeAdminUserRow(updatedAdmin),
    });
  }

  if (action === 'session') {
    if (req.method !== 'GET') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const auth = await requireAdminSession(req, res, db, pre.ip, { requireCsrf: false });
    if (!auth) return;
    return sendJson(res, 200, {
      ok: true,
      csrfToken: auth.session.csrf_token,
      admin: serializeAdminUserRow(auth.user),
    });
  }

  if (action === 'logout') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const auth = await requireAdminSession(req, res, db, pre.ip, { requireCsrf: true });
    if (!auth) return;

    await db.revokeSessionByTokenHash(auth.tokenHash);
    clearAdminCookies(req, res);
    await db.addAuditLog({
      adminUserId: auth.user.id,
      adminUsername: auth.user.username,
      action: 'admin_logout',
      targetType: 'session',
      targetId: auth.user.id,
      ipAddress: pre.ip,
    });
    return sendJson(res, 200, { ok: true });
  }

  // All remaining admin routes require valid admin session AND CSRF on POST
  const auth = await requireAdminSession(req, res, db, pre.ip, {
    requireCsrf: req.method === 'POST',
  });
  if (!auth) return;

  if (action === 'overview') {
    if (req.method !== 'GET') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const [dbLatencyMs, stats, settings] = await Promise.all([
      db.pingDb(),
      db.getOverviewStats(),
      db.getServerSettings(),
    ]);
    return sendJson(res, 200, {
      ok: true,
      stats: { ...stats, dbLatencyMs },
      serverSettings: serializeServerSettings(settings),
    });
  }

  if (action === 'users') {
    if (req.method !== 'GET') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const search = String(req.query?.search || '').slice(0, 64);
    const status = String(req.query?.status || 'all').toLowerCase();
    const page = Number(req.query?.page || 1);
    const result = await db.listUsersAdmin({ search, status, page, pageSize: 20 });
    return sendJson(res, 200, {
      ok: true,
      users: result.users.map(serializeAdminUserRow),
      total: result.total,
      page: result.page,
      pageSize: result.pageSize,
    });
  }

  if (action === 'users-action') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = usersActionSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }
    const data = parsed.data;

    if (data.action === 'create') {
      if (!data.username || !data.password) {
        return sendJson(res, 400, {
          ok: false,
          error: 'Username dan password wajib diisi.',
          code: 'VALIDATION_ERROR',
        });
      }
      const passCheck = strongPasswordSchema.safeParse(data.password);
      if (!passCheck.success) {
        return sendJson(res, 400, {
          ok: false,
          error: formatZodError(passCheck.error),
          code: 'VALIDATION_ERROR',
        });
      }
      const exists = await db.findUserByUsername(data.username);
      if (exists) {
        return sendJson(res, 409, {
          ok: false,
          error: 'Username sudah digunakan.',
          code: 'USERNAME_TAKEN',
        });
      }
      let created;
      try {
        created = await db.createUser({
          username: data.username,
          passwordHash: hashPassword(data.password),
          role: data.role || 'player',
          coins: data.coins ?? 0,
          totalWins: data.totalWins ?? 0,
          extraLives: data.extraLives ?? 0,
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
      await db.addAuditLog({
        adminUserId: auth.user.id,
        adminUsername: auth.user.username,
        action: 'create_user',
        targetType: 'user',
        targetId: created.id,
        details: { username: created.username, role: created.role },
        ipAddress: pre.ip,
      });
      return sendJson(res, 201, { ok: true, user: serializeAdminUserRow(created) });
    }

    if (!data.userId) {
      return sendJson(res, 400, {
        ok: false,
        error: 'userId wajib diisi.',
        code: 'VALIDATION_ERROR',
      });
    }
    const target = await db.findUserById(data.userId);
    if (!target) {
      return sendJson(res, 404, { ok: false, error: 'Akun tidak ditemukan.', code: 'USER_NOT_FOUND' });
    }

    if (data.action === 'update') {
      if (data.role && data.role !== 'admin' && target.id === auth.user.id) {
        return sendJson(res, 400, {
          ok: false,
          error: 'Tidak dapat menurunkan role akun Anda sendiri.',
          code: 'CANNOT_DEMOTE_SELF',
        });
      }
      const updated = await db.adminUpdateUser(target.id, {
        coins: data.coins,
        totalWins: data.totalWins,
        extraLives: data.extraLives,
        role: data.role,
      });
      await db.addAuditLog({
        adminUserId: auth.user.id,
        adminUsername: auth.user.username,
        action: 'update_user',
        targetType: 'user',
        targetId: target.id,
        details: {
          username: target.username,
          coins: updated.coins,
          totalWins: updated.total_wins,
          extraLives: updated.extra_lives,
          role: updated.role,
        },
        ipAddress: pre.ip,
      });
      return sendJson(res, 200, { ok: true, user: serializeAdminUserRow(updated) });
    }

    if (data.action === 'ban') {
      if (target.id === auth.user.id) {
        return sendJson(res, 400, {
          ok: false,
          error: 'Tidak dapat memblokir akun Anda sendiri.',
          code: 'CANNOT_BAN_SELF',
        });
      }
      const cleanReason = sanitizeText(data.reason || 'Melanggar ketentuan server.', 240);
      const updated = await db.adminUpdateUser(target.id, {
        isBanned: true,
        banReason: cleanReason,
      });
      await db.revokeUserSessions(target.id);
      await db.addAuditLog({
        adminUserId: auth.user.id,
        adminUsername: auth.user.username,
        action: 'ban_user',
        targetType: 'user',
        targetId: target.id,
        details: { username: target.username, reason: cleanReason },
        ipAddress: pre.ip,
      });
      return sendJson(res, 200, { ok: true, user: serializeAdminUserRow(updated) });
    }

    if (data.action === 'unban') {
      const updated = await db.adminUpdateUser(target.id, {
        isBanned: false,
        banReason: '',
        clearLockout: true,
      });
      await db.addAuditLog({
        adminUserId: auth.user.id,
        adminUsername: auth.user.username,
        action: 'unban_user',
        targetType: 'user',
        targetId: target.id,
        details: { username: target.username },
        ipAddress: pre.ip,
      });
      return sendJson(res, 200, { ok: true, user: serializeAdminUserRow(updated) });
    }

    if (data.action === 'reset_password') {
      const passCheck = strongPasswordSchema.safeParse(data.password);
      if (!passCheck.success) {
        return sendJson(res, 400, {
          ok: false,
          error: formatZodError(passCheck.error),
          code: 'VALIDATION_ERROR',
        });
      }
      const updated = await db.adminUpdateUser(target.id, {
        passwordHash: hashPassword(passCheck.data),
        clearLockout: true,
      });
      await db.revokeUserSessions(target.id);
      await db.addAuditLog({
        adminUserId: auth.user.id,
        adminUsername: auth.user.username,
        action: 'reset_password',
        targetType: 'user',
        targetId: target.id,
        details: { username: target.username },
        ipAddress: pre.ip,
      });
      return sendJson(res, 200, { ok: true, user: serializeAdminUserRow(updated) });
    }

    if (data.action === 'force_logout') {
      await db.revokeUserSessions(target.id);
      await db.addAuditLog({
        adminUserId: auth.user.id,
        adminUsername: auth.user.username,
        action: 'force_logout',
        targetType: 'user',
        targetId: target.id,
        details: { username: target.username },
        ipAddress: pre.ip,
      });
      return sendJson(res, 200, { ok: true });
    }

    if (data.action === 'delete') {
      if (target.id === auth.user.id) {
        return sendJson(res, 400, {
          ok: false,
          error: 'Tidak dapat menghapus akun Anda sendiri.',
          code: 'CANNOT_DELETE_SELF',
        });
      }
      await db.adminDeleteUser(target.id);
      await db.addAuditLog({
        adminUserId: auth.user.id,
        adminUsername: auth.user.username,
        action: 'delete_user',
        targetType: 'user',
        targetId: target.id,
        details: { username: target.username },
        ipAddress: pre.ip,
      });
      return sendJson(res, 200, { ok: true });
    }
  }

  if (action === 'rooms') {
    if (req.method !== 'GET') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    await db.cleanupStaleRooms(15);
    const entries = await db.listActiveRooms('all');
    const rooms = entries.map(({ room, players }) => ({
      ...serializeRoom(room, players),
      players: players.map(serializeRoomPlayer),
    }));
    return sendJson(res, 200, { ok: true, rooms });
  }

  if (action === 'rooms-action') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = roomsActionSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }
    const data = parsed.data;

    if (data.action === 'cleanup_stale') {
      const closedCount = await db.cleanupStaleRooms(15);
      await db.addAuditLog({
        adminUserId: auth.user.id,
        adminUsername: auth.user.username,
        action: 'cleanup_stale_rooms',
        targetType: 'rooms',
        details: { closedCount },
        ipAddress: pre.ip,
      });
      return sendJson(res, 200, { ok: true, closedCount });
    }

    if (!data.roomId) {
      return sendJson(res, 400, {
        ok: false,
        error: 'roomId wajib diisi.',
        code: 'VALIDATION_ERROR',
      });
    }

    if (data.action === 'close_room') {
      const closed = await db.closeRoomAdmin({
        roomId: data.roomId,
        message: data.message || '',
        adminUsername: auth.user.username,
      });
      if (!closed) {
        return sendJson(res, 404, { ok: false, error: 'Room tidak ditemukan.', code: 'ROOM_NOT_FOUND' });
      }
      await db.addAuditLog({
        adminUserId: auth.user.id,
        adminUsername: auth.user.username,
        action: 'close_room',
        targetType: 'room',
        targetId: data.roomId,
        details: { roomCode: closed.room_code, message: sanitizeText(data.message || '', 200) },
        ipAddress: pre.ip,
      });
      return sendJson(res, 200, { ok: true });
    }

    if (data.action === 'kick_player') {
      if (!data.targetUserId) {
        return sendJson(res, 400, {
          ok: false,
          error: 'targetUserId wajib diisi.',
          code: 'VALIDATION_ERROR',
        });
      }
      const kicked = await db.kickPlayerFromRoom({
        roomId: data.roomId,
        targetUserId: data.targetUserId,
        kickedByUserId: auth.user.id,
        kickedByUsername: auth.user.username,
        isAdmin: true,
      });
      if (!kicked) {
        return sendJson(res, 404, {
          ok: false,
          error: 'Room atau pemain tidak ditemukan.',
          code: 'PLAYER_NOT_IN_ROOM',
        });
      }
      await db.addAuditLog({
        adminUserId: auth.user.id,
        adminUsername: auth.user.username,
        action: 'admin_kick_player',
        targetType: 'room',
        targetId: data.roomId,
        details: { targetUserId: data.targetUserId },
        ipAddress: pre.ip,
      });
      return sendJson(res, 200, { ok: true });
    }

    if (data.action === 'broadcast_room') {
      const cleanMsg = sanitizeText(data.message || '', 240);
      if (!cleanMsg) {
        return sendJson(res, 400, {
          ok: false,
          error: 'Pesan siaran wajib diisi.',
          code: 'VALIDATION_ERROR',
        });
      }
      const room = await db.broadcastRoomAdmin({
        roomId: data.roomId,
        message: cleanMsg,
        adminUsername: auth.user.username,
      });
      if (!room) {
        return sendJson(res, 404, { ok: false, error: 'Room tidak ditemukan.', code: 'ROOM_NOT_FOUND' });
      }
      await db.addAuditLog({
        adminUserId: auth.user.id,
        adminUsername: auth.user.username,
        action: 'broadcast_room',
        targetType: 'room',
        targetId: data.roomId,
        details: { message: cleanMsg },
        ipAddress: pre.ip,
      });
      return sendJson(res, 200, { ok: true });
    }
  }

  if (action === 'server') {
    if (req.method === 'GET') {
      const settings = await db.getServerSettings();
      return sendJson(res, 200, { ok: true, serverSettings: serializeServerSettings(settings) });
    }
    if (req.method === 'POST') {
      const parsed = serverSettingsSchema.safeParse(pre.body);
      if (!parsed.success) {
        return sendJson(res, 400, {
          ok: false,
          error: formatZodError(parsed.error),
          code: 'VALIDATION_ERROR',
        });
      }
      const d = parsed.data;
      const patch = {
        maintenanceMode: d.maintenanceMode ?? d.maintenance_mode,
        maintenanceMessage: d.maintenanceMessage ?? d.maintenance_message,
        allowRegistration: d.allowRegistration ?? d.allow_registration,
        allowMultiplayer: d.allowMultiplayer ?? d.allow_multiplayer,
        allowSandbox: d.allowSandbox ?? d.allow_sandbox,
        maxActiveRooms: d.maxActiveRooms ?? d.max_active_rooms,
        globalAnnouncement: d.globalAnnouncement ?? d.global_announcement,
        minClientVersion: d.minClientVersion ?? d.min_client_version,
      };
      const updated = await db.updateServerSettings(patch, auth.user.username);
      await db.addAuditLog({
        adminUserId: auth.user.id,
        adminUsername: auth.user.username,
        action: 'update_server_settings',
        targetType: 'server_settings',
        targetId: '1',
        details: serializeServerSettings(updated),
        ipAddress: pre.ip,
      });
      return sendJson(res, 200, { ok: true, serverSettings: serializeServerSettings(updated) });
    }
    return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
  }

  if (action === 'security') {
    if (req.method === 'GET') {
      const [securityLogs, auditLogs, ipBlocks] = await Promise.all([
        db.listSecurityLogs(100),
        db.listAuditLogs(100),
        db.listIpBlocks(),
      ]);
      return sendJson(res, 200, {
        ok: true,
        securityLogs: securityLogs.map(serializeSecurityLog),
        auditLogs: auditLogs.map(serializeAuditLog),
        ipBlocks: ipBlocks.map(serializeIpBlock),
      });
    }
    if (req.method === 'POST') {
      const parsed = securityActionSchema.safeParse(pre.body);
      if (!parsed.success) {
        return sendJson(res, 400, {
          ok: false,
          error: formatZodError(parsed.error),
          code: 'VALIDATION_ERROR',
        });
      }
      const data = parsed.data;

      if (data.action === 'clear_rate_limits') {
        await db.clearRateLimits();
        await db.addAuditLog({
          adminUserId: auth.user.id,
          adminUsername: auth.user.username,
          action: 'clear_rate_limits',
          targetType: 'rate_limits',
          ipAddress: pre.ip,
        });
        return sendJson(res, 200, { ok: true });
      }

      if (!data.ipAddress || !isValidIpAddress(data.ipAddress)) {
        return sendJson(res, 400, {
          ok: false,
          error: 'Alamat IP tidak valid.',
          code: 'INVALID_IP',
        });
      }
      const cleanIp = data.ipAddress.trim();

      if (data.action === 'block_ip') {
        const expiresAt =
          data.expiresHours && data.expiresHours > 0
            ? new Date(Date.now() + data.expiresHours * 3600_000)
            : null;
        const block = await db.upsertIpBlock({
          ipAddress: cleanIp,
          reason: data.reason || 'Diblokir oleh admin.',
          blockedBy: auth.user.username,
          expiresAt,
        });
        await db.addAuditLog({
          adminUserId: auth.user.id,
          adminUsername: auth.user.username,
          action: 'block_ip',
          targetType: 'ip_block',
          targetId: cleanIp,
          details: { reason: block.reason, expiresHours: data.expiresHours ?? null },
          ipAddress: pre.ip,
        });
        const ipBlocks = await db.listIpBlocks();
        return sendJson(res, 200, {
          ok: true,
          ipBlock: serializeIpBlock(block),
          ipBlocks: ipBlocks.map(serializeIpBlock),
        });
      }

      if (data.action === 'unblock_ip') {
        await db.deleteIpBlock(cleanIp);
        await db.addAuditLog({
          adminUserId: auth.user.id,
          adminUsername: auth.user.username,
          action: 'unblock_ip',
          targetType: 'ip_block',
          targetId: cleanIp,
          ipAddress: pre.ip,
        });
        const ipBlocks = await db.listIpBlocks();
        return sendJson(res, 200, {
          ok: true,
          ipBlocks: ipBlocks.map(serializeIpBlock),
        });
      }
    }
    return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
  }

  if (action === 'redeem') {
    if (req.method === 'GET') {
      const codes = await db.listRedeemCodes();
      return sendJson(res, 200, { ok: true, codes: codes.map(serializeRedeemCode) });
    }
    if (req.method === 'POST') {
      const parsed = redeemActionSchema.safeParse(pre.body);
      if (!parsed.success) {
        return sendJson(res, 400, {
          ok: false,
          error: formatZodError(parsed.error),
          code: 'VALIDATION_ERROR',
        });
      }
      const data = parsed.data;
      const cleanCode = String(data.code || '')
        .trim()
        .toUpperCase()
        .replace(/[^A-Z0-9]/g, '');
      if (cleanCode.length < 3 || cleanCode.length > 32) {
        return sendJson(res, 400, {
          ok: false,
          error: 'Kode redeem harus 3-32 karakter alfanumerik.',
          code: 'INVALID_CODE_FORMAT',
        });
      }

      if (data.action === 'create') {
        if (!data.rewardType || !data.quantity) {
          return sendJson(res, 400, {
            ok: false,
            error: 'rewardType dan quantity wajib diisi.',
            code: 'VALIDATION_ERROR',
          });
        }
        if (data.rewardType === 'item' && !ALLOWED_ITEM_IDS.includes(data.itemId || '')) {
          return sendJson(res, 400, {
            ok: false,
            error: `itemId harus salah satu dari: ${ALLOWED_ITEM_IDS.join(', ')}`,
            code: 'INVALID_ITEM_ID',
          });
        }
        try {
          const created = await db.createRedeemCode({
            code: cleanCode,
            rewardType: data.rewardType,
            itemId: data.itemId || '',
            quantity: data.quantity,
            maxUses: data.maxUses ?? null,
            descriptionId: data.descriptionId || '',
            descriptionEn: data.descriptionEn || '',
            isActive: data.isActive ?? true,
          });
          await db.addAuditLog({
            adminUserId: auth.user.id,
            adminUsername: auth.user.username,
            action: 'create_redeem_code',
            targetType: 'redeem_code',
            targetId: cleanCode,
            details: { rewardType: created.reward_type, quantity: created.quantity },
            ipAddress: pre.ip,
          });
          const codes = await db.listRedeemCodes();
          return sendJson(res, 201, {
            ok: true,
            code: serializeRedeemCode(created),
            codes: codes.map(serializeRedeemCode),
          });
        } catch (err) {
          if (err?.code === '23505') {
            return sendJson(res, 409, {
              ok: false,
              error: 'Kode redeem sudah ada.',
              code: 'CODE_EXISTS',
            });
          }
          throw err;
        }
      }

      if (data.action === 'toggle') {
        const updated = await db.toggleRedeemCode(cleanCode, data.isActive);
        if (!updated) {
          return sendJson(res, 404, { ok: false, error: 'Kode tidak ditemukan.', code: 'NOT_FOUND' });
        }
        await db.addAuditLog({
          adminUserId: auth.user.id,
          adminUsername: auth.user.username,
          action: 'toggle_redeem_code',
          targetType: 'redeem_code',
          targetId: cleanCode,
          details: { isActive: updated.is_active },
          ipAddress: pre.ip,
        });
        const codes = await db.listRedeemCodes();
        return sendJson(res, 200, {
          ok: true,
          code: serializeRedeemCode(updated),
          codes: codes.map(serializeRedeemCode),
        });
      }

      if (data.action === 'delete') {
        const deleted = await db.deleteRedeemCode(cleanCode);
        if (!deleted) {
          return sendJson(res, 404, { ok: false, error: 'Kode tidak ditemukan.', code: 'NOT_FOUND' });
        }
        await db.addAuditLog({
          adminUserId: auth.user.id,
          adminUsername: auth.user.username,
          action: 'delete_redeem_code',
          targetType: 'redeem_code',
          targetId: cleanCode,
          ipAddress: pre.ip,
        });
        const codes = await db.listRedeemCodes();
        return sendJson(res, 200, {
          ok: true,
          codes: codes.map(serializeRedeemCode),
        });
      }
    }
    return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
  }

  return sendJson(res, 404, { ok: false, error: 'Endpoint admin tidak ditemukan.', code: 'NOT_FOUND' });
}
