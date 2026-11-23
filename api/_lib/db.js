import crypto from 'node:crypto';
import { neon } from '@neondatabase/serverless';
import {
  hashPassword,
  normalizeItemStash,
  normalizeRedeemedCodes,
  sanitizeDeepValue,
  sanitizeText,
} from './security.js';

let sqlClient = null;
let neonSchemaPromise = null;
let warnedMemoryFallback = false;

const INITIAL_REDEEM_CODES = [
  {
    code: 'LAMPORGIFT',
    reward_type: 'coins',
    item_id: '',
    quantity: 2500,
    max_uses: null,
    uses_count: 0,
    description_id: 'hadiah untuk kalian!',
    description_en: 'A gift for you!',
    is_active: true,
  },
  {
    code: 'FOREVERYONE',
    reward_type: 'coins',
    item_id: '',
    quantity: 5000,
    max_uses: null,
    uses_count: 0,
    description_id: 'Hadiah untuk semua pemain!',
    description_en: 'A gift for everyone!',
    is_active: true,
  },
  {
    code: 'LAMPORLOVER',
    reward_type: 'coins',
    item_id: '',
    quantity: 10000,
    max_uses: null,
    uses_count: 0,
    description_id: 'Hadiah spesial pecinta Lampor!',
    description_en: 'Special gift for Lampor fans!',
    is_active: true,
  },
];

function createInitialMemoryState() {
  const now = new Date();
  return {
    initialized: false,
    users: new Map(),
    sessions: new Map(),
    rooms: new Map(),
    roomPlayers: new Map(),
    roomEvents: [],
    serverSettings: {
      id: 1,
      maintenance_mode: false,
      maintenance_message: '',
      allow_registration: true,
      allow_multiplayer: true,
      allow_sandbox: true,
      max_active_rooms: 50,
      global_announcement: '',
      min_client_version: '1.3.0',
      updated_at: now,
      updated_by: 'system',
    },
    securityLogs: [],
    auditLogs: [],
    ipBlocks: new Map(),
    rateLimits: new Map(),
    redeemCodes: new Map(),
  };
}

let mem = createInitialMemoryState();

export function isMemoryMode() {
  if (process.env.LAMPOR_TEST_DB === 'memory') {
    return true;
  }
  if (!process.env.DATABASE_URL) {
    if (process.env.VERCEL === '1') {
      throw new Error('DATABASE_URL environment variable is required in production.');
    }
    if (!warnedMemoryFallback) {
      warnedMemoryFallback = true;
      console.warn('[db] DATABASE_URL is not set; using in-memory fallback store.');
    }
    return true;
  }
  return false;
}

function getSql() {
  if (!sqlClient) {
    sqlClient = neon(process.env.DATABASE_URL);
  }
  return sqlClient;
}

function parseJsonField(val, fallback) {
  if (val === null || val === undefined) {
    return fallback;
  }
  if (typeof val === 'string') {
    try {
      return JSON.parse(val);
    } catch {
      return fallback;
    }
  }
  return val;
}

function normalizeUserRow(row) {
  if (!row) return null;
  return {
    ...row,
    coins: Number(row.coins ?? 0),
    total_wins: Number(row.total_wins ?? 0),
    extra_lives: Number(row.extra_lives ?? 0),
    save_seq: Number(row.save_seq ?? 0),
    failed_login_attempts: Number(row.failed_login_attempts ?? 0),
    item_stash: normalizeItemStash(parseJsonField(row.item_stash, {})),
    redeemed_codes: normalizeRedeemedCodes(parseJsonField(row.redeemed_codes, [])),
  };
}

function normalizeRoomRow(row) {
  if (!row) return null;
  return {
    ...row,
    max_players: Number(row.max_players ?? 4),
    last_event_seq: Number(row.last_event_seq ?? 0),
    settings: parseJsonField(row.settings, {}),
    world_state: parseJsonField(row.world_state, {}),
  };
}

function escapeLikePattern(str) {
  return String(str).replace(/[!%_]/g, (m) => `!${m}`);
}

function seedMemoryDefaults() {
  if (mem.redeemCodes.size === 0) {
    const now = new Date();
    for (const item of INITIAL_REDEEM_CODES) {
      mem.redeemCodes.set(item.code, {
        ...item,
        created_at: now,
        updated_at: now,
      });
    }
  }
  const hasAdmin = Array.from(mem.users.values()).some((u) => u.role === 'admin');
  const adminUser = process.env.ADMIN_USERNAME?.trim();
  const adminPass = process.env.ADMIN_PASSWORD;
  if (!hasAdmin && adminUser && adminPass) {
    const lower = adminUser.toLowerCase();
    const existing = Array.from(mem.users.values()).find((u) => u.username_lower === lower);
    if (!existing) {
      const now = new Date();
      const id = crypto.randomUUID();
      mem.users.set(id, {
        id,
        username: adminUser,
        username_lower: lower,
        password_hash: hashPassword(adminPass),
        role: 'admin',
        is_banned: false,
        ban_reason: '',
        coins: 0,
        total_wins: 0,
        extra_lives: 0,
        item_stash: { jamu: 0, baterai: 0, energy_drink: 0, kentongan: 0 },
        redeemed_codes: [],
        save_seq: 0,
        tutorial_completed: true,
        failed_login_attempts: 0,
        locked_until: null,
        last_login_at: null,
        last_login_ip: '',
        created_at: now,
        updated_at: now,
      });
    }
  }
  mem.initialized = true;
}

export function resetMemoryDb() {
  mem = createInitialMemoryState();
  seedMemoryDefaults();
}

export async function ensureSchema() {
  if (isMemoryMode()) {
    seedMemoryDefaults();
    return;
  }
  if (!neonSchemaPromise) {
    neonSchemaPromise = runNeonSchemaInit().catch((err) => {
      neonSchemaPromise = null;
      throw err;
    });
  }
  await neonSchemaPromise;
}

async function runNeonSchemaInit() {
  const sql = getSql();
  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      username TEXT NOT NULL,
      username_lower TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'player' CHECK (role IN ('player', 'admin')),
      is_banned BOOLEAN NOT NULL DEFAULT FALSE,
      ban_reason TEXT NOT NULL DEFAULT '',
      coins BIGINT NOT NULL DEFAULT 0 CHECK (coins >= 0 AND coins <= 999999999),
      total_wins INTEGER NOT NULL DEFAULT 0 CHECK (total_wins >= 0),
      extra_lives INTEGER NOT NULL DEFAULT 0 CHECK (extra_lives >= 0 AND extra_lives <= 5),
      item_stash JSONB NOT NULL DEFAULT '{"jamu":0,"baterai":0,"energy_drink":0,"kentongan":0}'::jsonb,
      redeemed_codes JSONB NOT NULL DEFAULT '[]'::jsonb,
      save_seq INTEGER NOT NULL DEFAULT 0 CHECK (save_seq >= 0),
      tutorial_completed BOOLEAN NOT NULL DEFAULT FALSE,
      failed_login_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
      locked_until TIMESTAMPTZ NULL,
      last_login_at TIMESTAMPTZ NULL,
      last_login_ip TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;
  await sql`CREATE INDEX IF NOT EXISTS idx_users_role ON users (role)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_users_banned ON users (is_banned)`;

  await sql`
    CREATE TABLE IF NOT EXISTS sessions (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      session_type TEXT NOT NULL DEFAULT 'player' CHECK (session_type IN ('player', 'admin')),
      csrf_token TEXT NOT NULL DEFAULT '',
      ip_address TEXT NOT NULL DEFAULT '',
      user_agent TEXT NOT NULL DEFAULT '',
      expires_at TIMESTAMPTZ NOT NULL,
      revoked_at TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;
  await sql`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at)`;

  await sql`
    CREATE TABLE IF NOT EXISTS rooms (
      id UUID PRIMARY KEY,
      room_code TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      host_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      mode TEXT NOT NULL DEFAULT 'multiplayer' CHECK (mode IN ('multiplayer', 'sandbox')),
      status TEXT NOT NULL DEFAULT 'lobby' CHECK (status IN ('lobby', 'playing', 'closed')),
      difficulty TEXT NOT NULL DEFAULT 'normal',
      max_players INTEGER NOT NULL DEFAULT 4 CHECK (max_players BETWEEN 1 AND 4),
      password_hash TEXT NULL,
      can_use_shop_items BOOLEAN NOT NULL DEFAULT TRUE,
      allow_late_join BOOLEAN NOT NULL DEFAULT FALSE,
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      world_state JSONB NOT NULL DEFAULT '{}'::jsonb,
      last_event_seq INTEGER NOT NULL DEFAULT 0,
      announcement TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;
  await sql`CREATE INDEX IF NOT EXISTS idx_rooms_status_mode ON rooms (status, mode)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_rooms_last_activity ON rooms (last_activity_at)`;

  await sql`
    CREATE TABLE IF NOT EXISTS room_players (
      room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      username TEXT NOT NULL,
      is_host BOOLEAN NOT NULL DEFAULT FALSE,
      is_ready BOOLEAN NOT NULL DEFAULT FALSE,
      player_state JSONB NOT NULL DEFAULT '{}'::jsonb,
      joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (room_id, user_id)
    )
  `;
  await sql`CREATE INDEX IF NOT EXISTS idx_room_players_last_seen ON room_players (room_id, last_seen_at)`;

  await sql`
    CREATE TABLE IF NOT EXISTS room_events (
      id UUID PRIMARY KEY,
      room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      seq INTEGER NOT NULL,
      sender_user_id UUID NULL,
      sender_username TEXT NOT NULL DEFAULT '',
      event_type TEXT NOT NULL,
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (room_id, seq)
    )
  `;
  await sql`CREATE INDEX IF NOT EXISTS idx_room_events_room_seq ON room_events (room_id, seq)`;

  await sql`
    CREATE TABLE IF NOT EXISTS server_settings (
      id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      maintenance_mode BOOLEAN NOT NULL DEFAULT FALSE,
      maintenance_message TEXT NOT NULL DEFAULT '',
      allow_registration BOOLEAN NOT NULL DEFAULT TRUE,
      allow_multiplayer BOOLEAN NOT NULL DEFAULT TRUE,
      allow_sandbox BOOLEAN NOT NULL DEFAULT TRUE,
      max_active_rooms INTEGER NOT NULL DEFAULT 50 CHECK (max_active_rooms >= 1),
      global_announcement TEXT NOT NULL DEFAULT '',
      min_client_version TEXT NOT NULL DEFAULT '1.3.0',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_by TEXT NOT NULL DEFAULT 'system'
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS security_logs (
      id UUID PRIMARY KEY,
      event_type TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'info',
      username TEXT NOT NULL DEFAULT '',
      ip_address TEXT NOT NULL DEFAULT '',
      path TEXT NOT NULL DEFAULT '',
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;
  await sql`CREATE INDEX IF NOT EXISTS idx_security_logs_created ON security_logs (created_at DESC)`;

  await sql`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id UUID PRIMARY KEY,
      admin_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
      admin_username TEXT NOT NULL,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL DEFAULT '',
      target_id TEXT NOT NULL DEFAULT '',
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      ip_address TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;
  await sql`CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs (created_at DESC)`;

  await sql`
    CREATE TABLE IF NOT EXISTS ip_blocks (
      id UUID PRIMARY KEY,
      ip_address TEXT NOT NULL UNIQUE,
      reason TEXT NOT NULL DEFAULT '',
      blocked_by TEXT NOT NULL DEFAULT 'admin',
      expires_at TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS rate_limits (
      bucket_key TEXT PRIMARY KEY,
      window_start TIMESTAMPTZ NOT NULL,
      count INTEGER NOT NULL DEFAULT 1,
      timestamps JSONB NOT NULL DEFAULT '[]'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS redeem_codes (
      code TEXT PRIMARY KEY,
      reward_type TEXT NOT NULL CHECK (reward_type IN ('coins', 'lives', 'item')),
      item_id TEXT NOT NULL DEFAULT '',
      quantity INTEGER NOT NULL CHECK (quantity > 0),
      max_uses INTEGER NULL,
      uses_count INTEGER NOT NULL DEFAULT 0 CHECK (uses_count >= 0),
      description_id TEXT NOT NULL DEFAULT '',
      description_en TEXT NOT NULL DEFAULT '',
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;

  await sql`
    INSERT INTO server_settings (
      id, maintenance_mode, maintenance_message, allow_registration,
      allow_multiplayer, allow_sandbox, max_active_rooms,
      global_announcement, min_client_version, updated_by
    ) VALUES (
      1, FALSE, '', TRUE, TRUE, TRUE, 50, '', '1.3.0', 'system'
    ) ON CONFLICT (id) DO NOTHING
  `;

  for (const item of INITIAL_REDEEM_CODES) {
    await sql`
      INSERT INTO redeem_codes (
        code, reward_type, item_id, quantity, max_uses,
        description_id, description_en, is_active
      ) VALUES (
        ${item.code}, ${item.reward_type}, ${item.item_id}, ${item.quantity}, ${item.max_uses},
        ${item.description_id}, ${item.description_en}, ${item.is_active}
      ) ON CONFLICT (code) DO NOTHING
    `;
  }

  const admins = await sql`SELECT id FROM users WHERE role = 'admin' LIMIT 1`;
  const adminUser = process.env.ADMIN_USERNAME?.trim();
  const adminPass = process.env.ADMIN_PASSWORD;
  if (admins.length === 0 && adminUser && adminPass) {
    const id = crypto.randomUUID();
    const passHash = hashPassword(adminPass);
    await sql`
      INSERT INTO users (
        id, username, username_lower, password_hash, role, tutorial_completed
      ) VALUES (
        ${id}, ${adminUser}, ${adminUser.toLowerCase()}, ${passHash}, 'admin', TRUE
      ) ON CONFLICT (username_lower) DO NOTHING
    `;
  }
}

export async function pingDb() {
  const start = performance.now();
  await ensureSchema();
  if (!isMemoryMode()) {
    const sql = getSql();
    await sql`SELECT 1 AS ok`;
  }
  return Math.max(1, Math.round(performance.now() - start));
}

export async function isIpBlocked(ipAddress) {
  await ensureSchema();
  if (isMemoryMode()) {
    const entry = mem.ipBlocks.get(ipAddress);
    if (!entry) return null;
    if (entry.expires_at && new Date(entry.expires_at).getTime() <= Date.now()) {
      mem.ipBlocks.delete(ipAddress);
      return null;
    }
    return entry;
  }
  const sql = getSql();
  const rows = await sql`
    SELECT * FROM ip_blocks
    WHERE ip_address = ${ipAddress}
      AND (expires_at IS NULL OR expires_at > NOW())
    LIMIT 1
  `;
  return rows[0] || null;
}

export async function listIpBlocks() {
  await ensureSchema();
  if (isMemoryMode()) {
    return Array.from(mem.ipBlocks.values()).sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
  }
  const sql = getSql();
  return sql`SELECT * FROM ip_blocks ORDER BY created_at DESC LIMIT 200`;
}

export async function upsertIpBlock({ ipAddress, reason = '', blockedBy = 'admin', expiresAt = null }) {
  await ensureSchema();
  const cleanReason = sanitizeText(reason, 240);
  if (isMemoryMode()) {
    const existing = mem.ipBlocks.get(ipAddress);
    const row = {
      id: existing?.id || crypto.randomUUID(),
      ip_address: ipAddress,
      reason: cleanReason,
      blocked_by: blockedBy,
      expires_at: expiresAt ? new Date(expiresAt) : null,
      created_at: existing?.created_at || new Date(),
    };
    mem.ipBlocks.set(ipAddress, row);
    return row;
  }
  const sql = getSql();
  const id = crypto.randomUUID();
  const expIso = expiresAt ? new Date(expiresAt).toISOString() : null;
  const rows = await sql`
    INSERT INTO ip_blocks (id, ip_address, reason, blocked_by, expires_at)
    VALUES (${id}, ${ipAddress}, ${cleanReason}, ${blockedBy}, ${expIso}::timestamptz)
    ON CONFLICT (ip_address) DO UPDATE SET
      reason = EXCLUDED.reason,
      blocked_by = EXCLUDED.blocked_by,
      expires_at = EXCLUDED.expires_at,
      created_at = NOW()
    RETURNING *
  `;
  return rows[0];
}

export async function deleteIpBlock(ipAddress) {
  await ensureSchema();
  if (isMemoryMode()) {
    return mem.ipBlocks.delete(ipAddress);
  }
  const sql = getSql();
  const rows = await sql`DELETE FROM ip_blocks WHERE ip_address = ${ipAddress} RETURNING id`;
  return rows.length > 0;
}

export async function checkAndConsumeRateLimit({ bucketKey, limit, windowMs }) {
  await ensureSchema();
  const now = Date.now();
  const cutoff = now - windowMs;

  if (isMemoryMode()) {
    const prev = mem.rateLimits.get(bucketKey);
    const recent = (prev?.timestamps || []).filter((ts) => ts > cutoff);
    if (recent.length >= limit) {
      const oldest = recent[0] ?? now;
      return {
        allowed: false,
        remaining: 0,
        retryAfterSec: Math.max(1, Math.ceil((oldest + windowMs - now) / 1000)),
      };
    }
    recent.push(now);
    mem.rateLimits.set(bucketKey, {
      bucket_key: bucketKey,
      window_start: new Date(recent[0]),
      count: recent.length,
      timestamps: recent,
      updated_at: new Date(now),
    });
    return { allowed: true, remaining: Math.max(0, limit - recent.length), retryAfterSec: 0 };
  }

  const sql = getSql();
  const existing = await sql`SELECT timestamps FROM rate_limits WHERE bucket_key = ${bucketKey} LIMIT 1`;
  const prevArr = Array.isArray(existing[0]?.timestamps)
    ? existing[0].timestamps
    : parseJsonField(existing[0]?.timestamps, []);
  const recent = prevArr.filter((ts) => typeof ts === 'number' && ts > cutoff);
  if (recent.length >= limit) {
    const oldest = recent[0] ?? now;
    return {
      allowed: false,
      remaining: 0,
      retryAfterSec: Math.max(1, Math.ceil((oldest + windowMs - now) / 1000)),
    };
  }
  recent.push(now);
  const windowStartIso = new Date(recent[0]).toISOString();
  await sql`
    INSERT INTO rate_limits (bucket_key, window_start, count, timestamps, updated_at)
    VALUES (${bucketKey}, ${windowStartIso}::timestamptz, ${recent.length}, ${JSON.stringify(recent)}::jsonb, NOW())
    ON CONFLICT (bucket_key) DO UPDATE SET
      window_start = EXCLUDED.window_start,
      count = EXCLUDED.count,
      timestamps = EXCLUDED.timestamps,
      updated_at = NOW()
  `;
  return { allowed: true, remaining: Math.max(0, limit - recent.length), retryAfterSec: 0 };
}

export async function clearRateLimits() {
  await ensureSchema();
  if (isMemoryMode()) {
    mem.rateLimits.clear();
    return;
  }
  const sql = getSql();
  await sql`DELETE FROM rate_limits`;
}

export async function addSecurityLog({
  eventType,
  severity = 'info',
  username = '',
  ipAddress = '',
  path = '',
  details = {},
}) {
  await ensureSchema();
  const id = crypto.randomUUID();
  const cleanDetails = sanitizeDeepValue(details) || {};
  if (isMemoryMode()) {
    const row = {
      id,
      event_type: eventType,
      severity,
      username: sanitizeText(username, 40),
      ip_address: sanitizeText(ipAddress, 64),
      path: sanitizeText(path, 120),
      details: cleanDetails,
      created_at: new Date(),
    };
    mem.securityLogs.unshift(row);
    if (mem.securityLogs.length > 500) {
      mem.securityLogs.length = 500;
    }
    return row;
  }
  const sql = getSql();
  const rows = await sql`
    INSERT INTO security_logs (id, event_type, severity, username, ip_address, path, details)
    VALUES (
      ${id},
      ${eventType},
      ${severity},
      ${sanitizeText(username, 40)},
      ${sanitizeText(ipAddress, 64)},
      ${sanitizeText(path, 120)},
      ${JSON.stringify(cleanDetails)}::jsonb
    )
    RETURNING *
  `;
  return rows[0];
}

export async function listSecurityLogs(limit = 100) {
  await ensureSchema();
  const safeLimit = Math.min(200, Math.max(1, Number(limit) || 100));
  if (isMemoryMode()) {
    return mem.securityLogs.slice(0, safeLimit);
  }
  const sql = getSql();
  return sql`SELECT * FROM security_logs ORDER BY created_at DESC LIMIT ${safeLimit}`;
}

export async function addAuditLog({
  adminUserId = null,
  adminUsername,
  action,
  targetType = '',
  targetId = '',
  details = {},
  ipAddress = '',
}) {
  await ensureSchema();
  const id = crypto.randomUUID();
  const cleanDetails = sanitizeDeepValue(details) || {};
  if (isMemoryMode()) {
    const row = {
      id,
      admin_user_id: adminUserId,
      admin_username: sanitizeText(adminUsername, 40),
      action: sanitizeText(action, 64),
      target_type: sanitizeText(targetType, 40),
      target_id: sanitizeText(String(targetId || ''), 80),
      details: cleanDetails,
      ip_address: sanitizeText(ipAddress, 64),
      created_at: new Date(),
    };
    mem.auditLogs.unshift(row);
    if (mem.auditLogs.length > 500) {
      mem.auditLogs.length = 500;
    }
    return row;
  }
  const sql = getSql();
  const rows = await sql`
    INSERT INTO audit_logs (
      id, admin_user_id, admin_username, action, target_type, target_id, details, ip_address
    ) VALUES (
      ${id},
      ${adminUserId},
      ${sanitizeText(adminUsername, 40)},
      ${sanitizeText(action, 64)},
      ${sanitizeText(targetType, 40)},
      ${sanitizeText(String(targetId || ''), 80)},
      ${JSON.stringify(cleanDetails)}::jsonb,
      ${sanitizeText(ipAddress, 64)}
    )
    RETURNING *
  `;
  return rows[0];
}

export async function listAuditLogs(limit = 100) {
  await ensureSchema();
  const safeLimit = Math.min(200, Math.max(1, Number(limit) || 100));
  if (isMemoryMode()) {
    return mem.auditLogs.slice(0, safeLimit);
  }
  const sql = getSql();
  return sql`SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ${safeLimit}`;
}

export async function getServerSettings() {
  await ensureSchema();
  if (isMemoryMode()) {
    return { ...mem.serverSettings };
  }
  const sql = getSql();
  const rows = await sql`SELECT * FROM server_settings WHERE id = 1 LIMIT 1`;
  if (rows[0]) {
    return rows[0];
  }
  const inserted = await sql`
    INSERT INTO server_settings (id) VALUES (1)
    ON CONFLICT (id) DO UPDATE SET id = 1
    RETURNING *
  `;
  return inserted[0];
}

export async function updateServerSettings(patch, updatedBy = 'admin') {
  await ensureSchema();
  const current = await getServerSettings();
  const next = {
    maintenance_mode:
      patch.maintenanceMode !== undefined ? Boolean(patch.maintenanceMode) : current.maintenance_mode,
    maintenance_message:
      patch.maintenanceMessage !== undefined
        ? sanitizeText(patch.maintenanceMessage, 300)
        : current.maintenance_message,
    allow_registration:
      patch.allowRegistration !== undefined
        ? Boolean(patch.allowRegistration)
        : current.allow_registration,
    allow_multiplayer:
      patch.allowMultiplayer !== undefined ? Boolean(patch.allowMultiplayer) : current.allow_multiplayer,
    allow_sandbox:
      patch.allowSandbox !== undefined ? Boolean(patch.allowSandbox) : current.allow_sandbox,
    max_active_rooms:
      patch.maxActiveRooms !== undefined
        ? Math.min(500, Math.max(1, Math.trunc(Number(patch.maxActiveRooms) || 50)))
        : current.max_active_rooms,
    global_announcement:
      patch.globalAnnouncement !== undefined
        ? sanitizeText(patch.globalAnnouncement, 300)
        : current.global_announcement,
    min_client_version:
      patch.minClientVersion !== undefined
        ? sanitizeText(patch.minClientVersion, 32) || '1.3.0'
        : current.min_client_version,
  };

  if (isMemoryMode()) {
    mem.serverSettings = {
      ...mem.serverSettings,
      ...next,
      updated_at: new Date(),
      updated_by: updatedBy,
    };
    return { ...mem.serverSettings };
  }

  const sql = getSql();
  const rows = await sql`
    UPDATE server_settings SET
      maintenance_mode = ${next.maintenance_mode},
      maintenance_message = ${next.maintenance_message},
      allow_registration = ${next.allow_registration},
      allow_multiplayer = ${next.allow_multiplayer},
      allow_sandbox = ${next.allow_sandbox},
      max_active_rooms = ${next.max_active_rooms},
      global_announcement = ${next.global_announcement},
      min_client_version = ${next.min_client_version},
      updated_at = NOW(),
      updated_by = ${updatedBy}
    WHERE id = 1
    RETURNING *
  `;
  return rows[0];
}

export async function findUserById(userId) {
  await ensureSchema();
  if (isMemoryMode()) {
    return normalizeUserRow(mem.users.get(userId) || null);
  }
  const sql = getSql();
  const rows = await sql`SELECT * FROM users WHERE id = ${userId} LIMIT 1`;
  return normalizeUserRow(rows[0] || null);
}

export async function findUserByUsername(username) {
  await ensureSchema();
  const lower = String(username || '').trim().toLowerCase();
  if (!lower) return null;
  if (isMemoryMode()) {
    for (const u of mem.users.values()) {
      if (u.username_lower === lower) {
        return normalizeUserRow(u);
      }
    }
    return null;
  }
  const sql = getSql();
  const rows = await sql`SELECT * FROM users WHERE username_lower = ${lower} LIMIT 1`;
  return normalizeUserRow(rows[0] || null);
}

export async function createUser({
  username,
  passwordHash,
  role = 'player',
  coins = 0,
  totalWins = 0,
  extraLives = 0,
}) {
  await ensureSchema();
  const cleanUsername = String(username).trim();
  const lower = cleanUsername.toLowerCase();
  const clampedCoins = Math.min(999999999, Math.max(0, Math.trunc(Number(coins) || 0)));
  const clampedWins = Math.max(0, Math.trunc(Number(totalWins) || 0));
  const clampedLives = Math.min(5, Math.max(0, Math.trunc(Number(extraLives) || 0)));
  const id = crypto.randomUUID();
  const defaultStash = { jamu: 0, baterai: 0, energy_drink: 0, kentongan: 0 };

  if (isMemoryMode()) {
    for (const u of mem.users.values()) {
      if (u.username_lower === lower) {
        const err = new Error('Username already exists');
        err.code = '23505';
        throw err;
      }
    }
    const now = new Date();
    const row = {
      id,
      username: cleanUsername,
      username_lower: lower,
      password_hash: passwordHash,
      role,
      is_banned: false,
      ban_reason: '',
      coins: clampedCoins,
      total_wins: clampedWins,
      extra_lives: clampedLives,
      item_stash: defaultStash,
      redeemed_codes: [],
      save_seq: 0,
      tutorial_completed: false,
      failed_login_attempts: 0,
      locked_until: null,
      last_login_at: null,
      last_login_ip: '',
      created_at: now,
      updated_at: now,
    };
    mem.users.set(id, row);
    return normalizeUserRow(row);
  }

  const sql = getSql();
  const rows = await sql`
    INSERT INTO users (
      id, username, username_lower, password_hash, role,
      coins, total_wins, extra_lives, item_stash, redeemed_codes
    ) VALUES (
      ${id}, ${cleanUsername}, ${lower}, ${passwordHash}, ${role},
      ${clampedCoins}, ${clampedWins}, ${clampedLives},
      ${JSON.stringify(defaultStash)}::jsonb, '[]'::jsonb
    )
    RETURNING *
  `;
  return normalizeUserRow(rows[0]);
}

export async function recordFailedLogin({ userId, maxAttempts = 5, lockMinutes = 15 }) {
  await ensureSchema();
  if (isMemoryMode()) {
    const user = mem.users.get(userId);
    if (!user) return { failedAttempts: 0, lockedUntil: null, justLocked: false };
    const nextAttempts = Number(user.failed_login_attempts || 0) + 1;
    let lockedUntil = user.locked_until;
    let justLocked = false;
    if (nextAttempts >= maxAttempts) {
      lockedUntil = new Date(Date.now() + lockMinutes * 60_000);
      justLocked = true;
    }
    user.failed_login_attempts = nextAttempts;
    user.locked_until = lockedUntil;
    user.updated_at = new Date();
    return { failedAttempts: nextAttempts, lockedUntil, justLocked };
  }

  const sql = getSql();
  const current = await findUserById(userId);
  if (!current) return { failedAttempts: 0, lockedUntil: null, justLocked: false };
  const nextAttempts = current.failed_login_attempts + 1;
  const justLocked = nextAttempts >= maxAttempts;
  const lockedUntil = justLocked ? new Date(Date.now() + lockMinutes * 60_000).toISOString() : null;
  const rows = await sql`
    UPDATE users SET
      failed_login_attempts = ${nextAttempts},
      locked_until = CASE WHEN ${justLocked} THEN ${lockedUntil}::timestamptz ELSE locked_until END,
      updated_at = NOW()
    WHERE id = ${userId}
    RETURNING failed_login_attempts, locked_until
  `;
  return {
    failedAttempts: Number(rows[0]?.failed_login_attempts ?? nextAttempts),
    lockedUntil: rows[0]?.locked_until || null,
    justLocked,
  };
}

export async function updateUserLoginSuccess({ userId, ipAddress }) {
  await ensureSchema();
  if (isMemoryMode()) {
    const user = mem.users.get(userId);
    if (!user) return null;
    user.failed_login_attempts = 0;
    user.locked_until = null;
    user.last_login_at = new Date();
    user.last_login_ip = ipAddress;
    user.updated_at = new Date();
    return normalizeUserRow(user);
  }
  const sql = getSql();
  const rows = await sql`
    UPDATE users SET
      failed_login_attempts = 0,
      locked_until = NULL,
      last_login_at = NOW(),
      last_login_ip = ${ipAddress},
      updated_at = NOW()
    WHERE id = ${userId}
    RETURNING *
  `;
  return normalizeUserRow(rows[0]);
}

export async function syncUserProfile({
  userId,
  coins,
  totalWins,
  extraLives,
  itemStash,
  redeemedCodes,
  saveSeq,
  tutorialCompleted,
}) {
  await ensureSchema();
  const current = await findUserById(userId);
  if (!current) return null;

  const mergedCodes = normalizeRedeemedCodes([
    ...(current.redeemed_codes || []),
    ...(redeemedCodes || []),
  ]);

  const incomingSeq = Math.max(0, Math.trunc(Number(saveSeq) || 0));
  const shouldOverwriteProgress = incomingSeq >= current.save_seq;

  const nextCoins = shouldOverwriteProgress
    ? Math.min(999999999, Math.max(0, Math.trunc(Number(coins) || 0)))
    : current.coins;
  const nextWins =
    shouldOverwriteProgress && totalWins !== undefined
      ? Math.max(0, Math.trunc(Number(totalWins) || 0))
      : current.total_wins;
  const nextLives = shouldOverwriteProgress
    ? Math.min(5, Math.max(0, Math.trunc(Number(extraLives) || 0)))
    : current.extra_lives;
  const nextStash = shouldOverwriteProgress
    ? normalizeItemStash(itemStash)
    : current.item_stash;
  const nextSeq = shouldOverwriteProgress ? incomingSeq : current.save_seq;
  const nextTutorial =
    shouldOverwriteProgress && tutorialCompleted !== undefined
      ? Boolean(tutorialCompleted)
      : current.tutorial_completed;

  if (isMemoryMode()) {
    const user = mem.users.get(userId);
    user.coins = nextCoins;
    user.total_wins = nextWins;
    user.extra_lives = nextLives;
    user.item_stash = nextStash;
    user.redeemed_codes = mergedCodes;
    user.save_seq = nextSeq;
    user.tutorial_completed = nextTutorial;
    user.updated_at = new Date();
    return normalizeUserRow(user);
  }

  const sql = getSql();
  const rows = await sql`
    UPDATE users SET
      coins = ${nextCoins},
      total_wins = ${nextWins},
      extra_lives = ${nextLives},
      item_stash = ${JSON.stringify(nextStash)}::jsonb,
      redeemed_codes = ${JSON.stringify(mergedCodes)}::jsonb,
      save_seq = ${nextSeq},
      tutorial_completed = ${nextTutorial},
      updated_at = NOW()
    WHERE id = ${userId}
    RETURNING *
  `;
  return normalizeUserRow(rows[0]);
}

export async function createSession({
  userId,
  tokenHash,
  sessionType = 'player',
  csrfToken = '',
  ipAddress = '',
  userAgent = '',
  expiresAt,
}) {
  await ensureSchema();
  const id = crypto.randomUUID();
  const cleanUa = sanitizeText(userAgent, 200);
  if (isMemoryMode()) {
    const now = new Date();
    const row = {
      id,
      user_id: userId,
      token_hash: tokenHash,
      session_type: sessionType,
      csrf_token: csrfToken,
      ip_address: ipAddress,
      user_agent: cleanUa,
      expires_at: new Date(expiresAt),
      revoked_at: null,
      created_at: now,
      last_seen_at: now,
    };
    mem.sessions.set(tokenHash, row);
    return row;
  }
  const sql = getSql();
  const rows = await sql`
    INSERT INTO sessions (
      id, user_id, token_hash, session_type, csrf_token, ip_address, user_agent, expires_at
    ) VALUES (
      ${id}, ${userId}, ${tokenHash}, ${sessionType}, ${csrfToken}, ${ipAddress}, ${cleanUa}, ${new Date(expiresAt).toISOString()}::timestamptz
    )
    RETURNING *
  `;
  return rows[0];
}

export async function getSessionWithUser(tokenHash, expectedType = null) {
  await ensureSchema();
  if (!tokenHash) return null;

  if (isMemoryMode()) {
    const session = mem.sessions.get(tokenHash);
    if (!session || session.revoked_at) return null;
    if (new Date(session.expires_at).getTime() <= Date.now()) return null;
    if (expectedType && session.session_type !== expectedType) return null;
    const user = mem.users.get(session.user_id);
    if (!user) return null;
    session.last_seen_at = new Date();
    return { session: { ...session }, user: normalizeUserRow(user) };
  }

  const sql = getSql();
  const rows = expectedType
    ? await sql`
        SELECT
          s.id AS s_id, s.user_id AS s_user_id, s.token_hash AS s_token_hash,
          s.session_type AS s_session_type, s.csrf_token AS s_csrf_token,
          s.expires_at AS s_expires_at, s.revoked_at AS s_revoked_at,
          u.*
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ${tokenHash}
          AND s.session_type = ${expectedType}
          AND s.revoked_at IS NULL
          AND s.expires_at > NOW()
        LIMIT 1
      `
    : await sql`
        SELECT
          s.id AS s_id, s.user_id AS s_user_id, s.token_hash AS s_token_hash,
          s.session_type AS s_session_type, s.csrf_token AS s_csrf_token,
          s.expires_at AS s_expires_at, s.revoked_at AS s_revoked_at,
          u.*
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ${tokenHash}
          AND s.revoked_at IS NULL
          AND s.expires_at > NOW()
        LIMIT 1
      `;

  if (!rows[0]) return null;
  const r = rows[0];
  await sql`UPDATE sessions SET last_seen_at = NOW() WHERE id = ${r.s_id}`;
  const session = {
    id: r.s_id,
    user_id: r.s_user_id,
    token_hash: r.s_token_hash,
    session_type: r.s_session_type,
    csrf_token: r.s_csrf_token,
    expires_at: r.s_expires_at,
    revoked_at: r.s_revoked_at,
  };
  return { session, user: normalizeUserRow(r) };
}

export async function revokeSessionByTokenHash(tokenHash) {
  await ensureSchema();
  if (!tokenHash) return;
  if (isMemoryMode()) {
    const session = mem.sessions.get(tokenHash);
    if (session && !session.revoked_at) {
      session.revoked_at = new Date();
    }
    return;
  }
  const sql = getSql();
  await sql`UPDATE sessions SET revoked_at = NOW() WHERE token_hash = ${tokenHash} AND revoked_at IS NULL`;
}

export async function revokeUserSessions(userId) {
  await ensureSchema();
  if (isMemoryMode()) {
    const now = new Date();
    for (const s of mem.sessions.values()) {
      if (s.user_id === userId && !s.revoked_at) {
        s.revoked_at = now;
      }
    }
    return;
  }
  const sql = getSql();
  await sql`UPDATE sessions SET revoked_at = NOW() WHERE user_id = ${userId} AND revoked_at IS NULL`;
}

export async function listUsersAdmin({ search = '', status = 'all', page = 1, pageSize = 20 }) {
  await ensureSchema();
  const safePage = Math.max(1, Math.trunc(Number(page) || 1));
  const safeSize = Math.min(50, Math.max(1, Math.trunc(Number(pageSize) || 20)));
  const cleanSearch = String(search || '').trim().toLowerCase();

  if (isMemoryMode()) {
    const nowMs = Date.now();
    let list = Array.from(mem.users.values()).map(normalizeUserRow);
    if (cleanSearch) {
      list = list.filter((u) => u.username_lower.includes(cleanSearch));
    }
    if (status === 'active') {
      list = list.filter((u) => !u.is_banned);
    } else if (status === 'banned') {
      list = list.filter((u) => u.is_banned);
    } else if (status === 'admin') {
      list = list.filter((u) => u.role === 'admin');
    } else if (status === 'locked') {
      list = list.filter((u) => u.locked_until && new Date(u.locked_until).getTime() > nowMs);
    }
    list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    const total = list.length;
    const offset = (safePage - 1) * safeSize;
    return { users: list.slice(offset, offset + safeSize), total, page: safePage, pageSize: safeSize };
  }

  const sql = getSql();
  const like = `%${escapeLikePattern(cleanSearch)}%`;
  const hasSearch = cleanSearch.length > 0;
  const offset = (safePage - 1) * safeSize;

  const countRows = await sql`
    SELECT COUNT(*)::int AS total FROM users
    WHERE (${!hasSearch} OR username_lower LIKE ${like} ESCAPE '!')
      AND (
        ${status === 'all'}
        OR (${status === 'active'} AND is_banned = FALSE)
        OR (${status === 'banned'} AND is_banned = TRUE)
        OR (${status === 'admin'} AND role = 'admin')
        OR (${status === 'locked'} AND locked_until IS NOT NULL AND locked_until > NOW())
      )
  `;
  const rows = await sql`
    SELECT * FROM users
    WHERE (${!hasSearch} OR username_lower LIKE ${like} ESCAPE '!')
      AND (
        ${status === 'all'}
        OR (${status === 'active'} AND is_banned = FALSE)
        OR (${status === 'banned'} AND is_banned = TRUE)
        OR (${status === 'admin'} AND role = 'admin')
        OR (${status === 'locked'} AND locked_until IS NOT NULL AND locked_until > NOW())
      )
    ORDER BY created_at DESC
    LIMIT ${safeSize} OFFSET ${offset}
  `;

  return {
    users: rows.map(normalizeUserRow),
    total: Number(countRows[0]?.total ?? 0),
    page: safePage,
    pageSize: safeSize,
  };
}

export async function adminUpdateUser(userId, patch) {
  await ensureSchema();
  const current = await findUserById(userId);
  if (!current) return null;

  const next = {
    coins:
      patch.coins !== undefined
        ? Math.min(999999999, Math.max(0, Math.trunc(Number(patch.coins) || 0)))
        : current.coins,
    total_wins:
      patch.totalWins !== undefined
        ? Math.max(0, Math.trunc(Number(patch.totalWins) || 0))
        : current.total_wins,
    extra_lives:
      patch.extraLives !== undefined
        ? Math.min(5, Math.max(0, Math.trunc(Number(patch.extraLives) || 0)))
        : current.extra_lives,
    role: patch.role !== undefined ? patch.role : current.role,
    is_banned: patch.isBanned !== undefined ? Boolean(patch.isBanned) : current.is_banned,
    ban_reason:
      patch.banReason !== undefined ? sanitizeText(patch.banReason, 240) : current.ban_reason,
    password_hash: patch.passwordHash !== undefined ? patch.passwordHash : current.password_hash,
    failed_login_attempts: patch.clearLockout ? 0 : current.failed_login_attempts,
    locked_until: patch.clearLockout ? null : current.locked_until,
  };

  if (isMemoryMode()) {
    const user = mem.users.get(userId);
    Object.assign(user, next, { updated_at: new Date() });
    return normalizeUserRow(user);
  }

  const sql = getSql();
  const lockVal = next.locked_until ? new Date(next.locked_until).toISOString() : null;
  const rows = await sql`
    UPDATE users SET
      coins = ${next.coins},
      total_wins = ${next.total_wins},
      extra_lives = ${next.extra_lives},
      role = ${next.role},
      is_banned = ${next.is_banned},
      ban_reason = ${next.ban_reason},
      password_hash = ${next.password_hash},
      failed_login_attempts = ${next.failed_login_attempts},
      locked_until = ${lockVal}::timestamptz,
      updated_at = NOW()
    WHERE id = ${userId}
    RETURNING *
  `;
  return normalizeUserRow(rows[0] || null);
}

export async function adminDeleteUser(userId) {
  await ensureSchema();
  if (isMemoryMode()) {
    const existed = mem.users.delete(userId);
    for (const [tokenHash, s] of mem.sessions.entries()) {
      if (s.user_id === userId) mem.sessions.delete(tokenHash);
    }
    for (const [roomId, playersMap] of mem.roomPlayers.entries()) {
      playersMap.delete(userId);
      const room = mem.rooms.get(roomId);
      if (room && room.host_user_id === userId) {
        room.status = 'closed';
      }
    }
    return existed;
  }
  const sql = getSql();
  const rows = await sql`DELETE FROM users WHERE id = ${userId} RETURNING id`;
  return rows.length > 0;
}

export async function listRedeemCodes() {
  await ensureSchema();
  if (isMemoryMode()) {
    return Array.from(mem.redeemCodes.values()).sort((a, b) => a.code.localeCompare(b.code));
  }
  const sql = getSql();
  return sql`SELECT * FROM redeem_codes ORDER BY code ASC`;
}

export async function getRedeemCode(code) {
  await ensureSchema();
  const norm = String(code || '').trim().toUpperCase();
  if (isMemoryMode()) {
    return mem.redeemCodes.get(norm) || null;
  }
  const sql = getSql();
  const rows = await sql`SELECT * FROM redeem_codes WHERE code = ${norm} LIMIT 1`;
  return rows[0] || null;
}

export async function createRedeemCode({
  code,
  rewardType,
  itemId = '',
  quantity,
  maxUses = null,
  descriptionId = '',
  descriptionEn = '',
  isActive = true,
}) {
  await ensureSchema();
  const normCode = String(code).trim().toUpperCase();
  const cleanItem = rewardType === 'item' ? String(itemId || '') : '';
  const cleanQty = Math.max(1, Math.trunc(Number(quantity) || 1));
  const cleanMaxUses =
    maxUses === null || maxUses === undefined || maxUses === ''
      ? null
      : Math.max(1, Math.trunc(Number(maxUses)));
  const cleanDescId = sanitizeText(descriptionId, 200);
  const cleanDescEn = sanitizeText(descriptionEn, 200);

  if (isMemoryMode()) {
    if (mem.redeemCodes.has(normCode)) {
      const err = new Error('Redeem code exists');
      err.code = '23505';
      throw err;
    }
    const now = new Date();
    const row = {
      code: normCode,
      reward_type: rewardType,
      item_id: cleanItem,
      quantity: cleanQty,
      max_uses: cleanMaxUses,
      uses_count: 0,
      description_id: cleanDescId,
      description_en: cleanDescEn,
      is_active: Boolean(isActive),
      created_at: now,
      updated_at: now,
    };
    mem.redeemCodes.set(normCode, row);
    return row;
  }

  const sql = getSql();
  const rows = await sql`
    INSERT INTO redeem_codes (
      code, reward_type, item_id, quantity, max_uses, description_id, description_en, is_active
    ) VALUES (
      ${normCode}, ${rewardType}, ${cleanItem}, ${cleanQty}, ${cleanMaxUses},
      ${cleanDescId}, ${cleanDescEn}, ${Boolean(isActive)}
    )
    RETURNING *
  `;
  return rows[0];
}

export async function toggleRedeemCode(code, explicitActive) {
  await ensureSchema();
  const norm = String(code || '').trim().toUpperCase();
  if (isMemoryMode()) {
    const row = mem.redeemCodes.get(norm);
    if (!row) return null;
    row.is_active = explicitActive !== undefined ? Boolean(explicitActive) : !row.is_active;
    row.updated_at = new Date();
    return row;
  }
  const sql = getSql();
  const rows =
    explicitActive !== undefined
      ? await sql`
          UPDATE redeem_codes SET is_active = ${Boolean(explicitActive)}, updated_at = NOW()
          WHERE code = ${norm} RETURNING *
        `
      : await sql`
          UPDATE redeem_codes SET is_active = NOT is_active, updated_at = NOW()
          WHERE code = ${norm} RETURNING *
        `;
  return rows[0] || null;
}

export async function deleteRedeemCode(code) {
  await ensureSchema();
  const norm = String(code || '').trim().toUpperCase();
  if (isMemoryMode()) {
    return mem.redeemCodes.delete(norm);
  }
  const sql = getSql();
  const rows = await sql`DELETE FROM redeem_codes WHERE code = ${norm} RETURNING code`;
  return rows.length > 0;
}

export async function redeemCodeForUser({ userId, rawCode }) {
  await ensureSchema();
  const normCode = String(rawCode || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  const user = await findUserById(userId);
  if (!user) {
    return { ok: false, status: 404, error: 'Akun tidak ditemukan.', code: 'USER_NOT_FOUND' };
  }
  if (user.redeemed_codes.includes(normCode)) {
    return { ok: false, status: 409, error: 'Kode redeem sudah pernah diklaim.', code: 'ALREADY_REDEEMED' };
  }

  let rewardRow = null;
  if (isMemoryMode()) {
    const row = mem.redeemCodes.get(normCode);
    if (!row || !row.is_active) {
      return {
        ok: false,
        status: 404,
        error: 'Kode redeem tidak ditemukan atau sudah tidak aktif.',
        code: 'INVALID_CODE',
      };
    }
    if (row.max_uses !== null && row.uses_count >= row.max_uses) {
      return {
        ok: false,
        status: 409,
        error: 'Batas pemakaian kode redeem sudah habis.',
        code: 'CODE_EXHAUSTED',
      };
    }
    row.uses_count += 1;
    row.updated_at = new Date();
    rewardRow = { ...row };
  } else {
    const sql = getSql();
    const existing = await getRedeemCode(normCode);
    if (!existing || !existing.is_active) {
      return {
        ok: false,
        status: 404,
        error: 'Kode redeem tidak ditemukan atau sudah tidak aktif.',
        code: 'INVALID_CODE',
      };
    }
    const updated = await sql`
      UPDATE redeem_codes
      SET uses_count = uses_count + 1, updated_at = NOW()
      WHERE code = ${normCode}
        AND is_active = TRUE
        AND (max_uses IS NULL OR uses_count < max_uses)
      RETURNING *
    `;
    if (!updated[0]) {
      return {
        ok: false,
        status: 409,
        error: 'Batas pemakaian kode redeem sudah habis.',
        code: 'CODE_EXHAUSTED',
      };
    }
    rewardRow = updated[0];
  }

  const nextCodes = [...user.redeemed_codes, normCode];
  let nextCoins = user.coins;
  let nextLives = user.extra_lives;
  const nextStash = { ...user.item_stash };

  if (rewardRow.reward_type === 'coins') {
    nextCoins = Math.min(999999999, user.coins + Number(rewardRow.quantity));
  } else if (rewardRow.reward_type === 'lives') {
    nextLives = Math.min(5, user.extra_lives + Number(rewardRow.quantity));
  } else if (rewardRow.reward_type === 'item' && rewardRow.item_id) {
    nextStash[rewardRow.item_id] = Math.min(
      5,
      Number(nextStash[rewardRow.item_id] || 0) + Number(rewardRow.quantity)
    );
  }
  const nextSeq = user.save_seq + 1;

  let updatedUser = null;
  if (isMemoryMode()) {
    const memUser = mem.users.get(userId);
    memUser.coins = nextCoins;
    memUser.extra_lives = nextLives;
    memUser.item_stash = nextStash;
    memUser.redeemed_codes = nextCodes;
    memUser.save_seq = nextSeq;
    memUser.updated_at = new Date();
    updatedUser = normalizeUserRow(memUser);
  } else {
    const sql = getSql();
    const rows = await sql`
      UPDATE users SET
        coins = ${nextCoins},
        extra_lives = ${nextLives},
        item_stash = ${JSON.stringify(nextStash)}::jsonb,
        redeemed_codes = ${JSON.stringify(nextCodes)}::jsonb,
        save_seq = ${nextSeq},
        updated_at = NOW()
      WHERE id = ${userId}
      RETURNING *
    `;
    updatedUser = normalizeUserRow(rows[0]);
  }

  return {
    ok: true,
    reward: {
      code: rewardRow.code,
      type: rewardRow.reward_type,
      itemId: rewardRow.item_id || '',
      quantity: Number(rewardRow.quantity),
      descriptionId: sanitizeText(rewardRow.description_id || '', 200),
      descriptionEn: sanitizeText(rewardRow.description_en || '', 200),
    },
    user: updatedUser,
  };
}

export async function cleanupStaleRooms(idleMinutes = 15) {
  await ensureSchema();
  const cutoffMs = Date.now() - idleMinutes * 60_000;
  if (isMemoryMode()) {
    let closedCount = 0;
    for (const room of mem.rooms.values()) {
      if (room.status !== 'closed' && new Date(room.last_activity_at).getTime() < cutoffMs) {
        room.status = 'closed';
        room.updated_at = new Date();
        mem.roomPlayers.delete(room.id);
        closedCount += 1;
      }
    }
    return closedCount;
  }
  const sql = getSql();
  const cutoffIso = new Date(cutoffMs).toISOString();
  const rows = await sql`
    UPDATE rooms SET status = 'closed', updated_at = NOW()
    WHERE status IN ('lobby', 'playing')
      AND last_activity_at < ${cutoffIso}::timestamptz
    RETURNING id
  `;
  if (rows.length > 0) {
    for (const r of rows) {
      await sql`DELETE FROM room_players WHERE room_id = ${r.id}`;
    }
  }
  return rows.length;
}

export async function countActiveRooms() {
  await ensureSchema();
  if (isMemoryMode()) {
    let count = 0;
    for (const r of mem.rooms.values()) {
      if (r.status === 'lobby' || r.status === 'playing') count += 1;
    }
    return count;
  }
  const sql = getSql();
  const rows = await sql`SELECT COUNT(*)::int AS cnt FROM rooms WHERE status IN ('lobby', 'playing')`;
  return Number(rows[0]?.cnt ?? 0);
}

export async function getOverviewStats() {
  await ensureSchema();
  await cleanupStaleRooms(15);

  if (isMemoryMode()) {
    const nowMs = Date.now();
    const dayAgo = nowMs - 24 * 3600_000;
    let totalUsers = 0;
    let bannedUsers = 0;
    for (const u of mem.users.values()) {
      totalUsers += 1;
      if (u.is_banned) bannedUsers += 1;
    }
    let activeSessions = 0;
    for (const s of mem.sessions.values()) {
      if (!s.revoked_at && new Date(s.expires_at).getTime() > nowMs) activeSessions += 1;
    }
    let activeMultiplayerRooms = 0;
    let activeSandboxRooms = 0;
    for (const r of mem.rooms.values()) {
      if (r.status === 'lobby' || r.status === 'playing') {
        if (r.mode === 'sandbox') activeSandboxRooms += 1;
        else activeMultiplayerRooms += 1;
      }
    }
    let blockedIps = 0;
    for (const b of mem.ipBlocks.values()) {
      if (!b.expires_at || new Date(b.expires_at).getTime() > nowMs) blockedIps += 1;
    }
    const securityEvents24h = mem.securityLogs.filter(
      (l) => new Date(l.created_at).getTime() >= dayAgo
    ).length;
    return {
      totalUsers,
      bannedUsers,
      activeSessions,
      activeMultiplayerRooms,
      activeSandboxRooms,
      blockedIps,
      securityEvents24h,
    };
  }

  const sql = getSql();
  const [uStats] = await sql`
    SELECT
      COUNT(*)::int AS total_users,
      COUNT(*) FILTER (WHERE is_banned = TRUE)::int AS banned_users
    FROM users
  `;
  const [sStats] = await sql`
    SELECT COUNT(*)::int AS active_sessions
    FROM sessions
    WHERE revoked_at IS NULL AND expires_at > NOW()
  `;
  const [rStats] = await sql`
    SELECT
      COUNT(*) FILTER (WHERE mode = 'multiplayer')::int AS mp_rooms,
      COUNT(*) FILTER (WHERE mode = 'sandbox')::int AS sb_rooms
    FROM rooms
    WHERE status IN ('lobby', 'playing')
  `;
  const [bStats] = await sql`
    SELECT COUNT(*)::int AS blocked_ips
    FROM ip_blocks
    WHERE expires_at IS NULL OR expires_at > NOW()
  `;
  const [secStats] = await sql`
    SELECT COUNT(*)::int AS sec_24h
    FROM security_logs
    WHERE created_at >= NOW() - INTERVAL '24 hours'
  `;

  return {
    totalUsers: Number(uStats?.total_users ?? 0),
    bannedUsers: Number(uStats?.banned_users ?? 0),
    activeSessions: Number(sStats?.active_sessions ?? 0),
    activeMultiplayerRooms: Number(rStats?.mp_rooms ?? 0),
    activeSandboxRooms: Number(rStats?.sb_rooms ?? 0),
    blockedIps: Number(bStats?.blocked_ips ?? 0),
    securityEvents24h: Number(secStats?.sec_24h ?? 0),
  };
}

function getMemRoomPlayersArray(roomId) {
  const map = mem.roomPlayers.get(roomId);
  if (!map) return [];
  return Array.from(map.values()).sort(
    (a, b) => new Date(a.joined_at).getTime() - new Date(b.joined_at).getTime()
  );
}

async function appendRoomEvent({ roomId, senderUserId = null, senderUsername = '', eventType, payload = {} }) {
  const cleanPayload = sanitizeDeepValue(payload) || {};
  const id = crypto.randomUUID();
  const cleanSender = sanitizeText(senderUsername, 32);

  if (isMemoryMode()) {
    const room = mem.rooms.get(roomId);
    if (!room) return null;
    room.last_event_seq += 1;
    room.last_activity_at = new Date();
    room.updated_at = new Date();
    const ev = {
      id,
      room_id: roomId,
      seq: room.last_event_seq,
      sender_user_id: senderUserId,
      sender_username: cleanSender,
      event_type: eventType,
      payload: cleanPayload,
      created_at: new Date(),
    };
    mem.roomEvents.push(ev);
    return ev;
  }

  const sql = getSql();
  const seqRows = await sql`
    UPDATE rooms
    SET last_event_seq = last_event_seq + 1, last_activity_at = NOW(), updated_at = NOW()
    WHERE id = ${roomId}
    RETURNING last_event_seq
  `;
  if (!seqRows[0]) return null;
  const seq = Number(seqRows[0].last_event_seq);
  const rows = await sql`
    INSERT INTO room_events (id, room_id, seq, sender_user_id, sender_username, event_type, payload)
    VALUES (
      ${id}, ${roomId}, ${seq}, ${senderUserId}, ${cleanSender}, ${eventType},
      ${JSON.stringify(cleanPayload)}::jsonb
    )
    RETURNING *
  `;
  return rows[0];
}

export async function findRoomById(roomId) {
  await ensureSchema();
  if (isMemoryMode()) {
    return normalizeRoomRow(mem.rooms.get(roomId) || null);
  }
  const sql = getSql();
  const rows = await sql`SELECT * FROM rooms WHERE id = ${roomId} LIMIT 1`;
  return normalizeRoomRow(rows[0] || null);
}

export async function findRoomByCode(roomCode) {
  await ensureSchema();
  const code = String(roomCode || '').trim().toUpperCase();
  if (isMemoryMode()) {
    for (const r of mem.rooms.values()) {
      if (r.room_code === code && r.status !== 'closed') {
        return normalizeRoomRow(r);
      }
    }
    for (const r of mem.rooms.values()) {
      if (r.room_code === code) {
        return normalizeRoomRow(r);
      }
    }
    return null;
  }
  const sql = getSql();
  const rows = await sql`SELECT * FROM rooms WHERE room_code = ${code} LIMIT 1`;
  return normalizeRoomRow(rows[0] || null);
}

export async function getRoomPlayers(roomId) {
  await ensureSchema();
  if (isMemoryMode()) {
    return getMemRoomPlayersArray(roomId);
  }
  const sql = getSql();
  const rows = await sql`
    SELECT * FROM room_players
    WHERE room_id = ${roomId}
    ORDER BY joined_at ASC
  `;
  return rows.map((p) => ({
    ...p,
    player_state: parseJsonField(p.player_state, {}),
  }));
}

export async function listActiveRooms(mode = 'all') {
  await ensureSchema();
  if (isMemoryMode()) {
    const rooms = Array.from(mem.rooms.values())
      .filter((r) => (r.status === 'lobby' || r.status === 'playing') && (mode === 'all' || r.mode === mode))
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return rooms.map((r) => ({
      room: normalizeRoomRow(r),
      players: getMemRoomPlayersArray(r.id),
    }));
  }

  const sql = getSql();
  const roomRows =
    mode === 'all'
      ? await sql`
          SELECT * FROM rooms
          WHERE status IN ('lobby', 'playing')
          ORDER BY created_at DESC
          LIMIT 100
        `
      : await sql`
          SELECT * FROM rooms
          WHERE status IN ('lobby', 'playing') AND mode = ${mode}
          ORDER BY created_at DESC
          LIMIT 100
        `;

  if (roomRows.length === 0) return [];
  const results = [];
  for (const r of roomRows) {
    const players = await getRoomPlayers(r.id);
    results.push({ room: normalizeRoomRow(r), players });
  }
  return results;
}

export async function createRoom({
  roomCode,
  name,
  hostUserId,
  hostUsername,
  mode,
  difficulty,
  maxPlayers,
  passwordHash,
  canUseShopItems,
  allowLateJoin,
  settings,
}) {
  await ensureSchema();
  const id = crypto.randomUUID();
  const cleanName = sanitizeText(name, 60);
  const cleanSettings = sanitizeDeepValue(settings) || {};

  if (isMemoryMode()) {
    const now = new Date();
    const room = {
      id,
      room_code: roomCode,
      name: cleanName,
      host_user_id: hostUserId,
      mode,
      status: 'lobby',
      difficulty,
      max_players: maxPlayers,
      password_hash: passwordHash || null,
      can_use_shop_items: Boolean(canUseShopItems),
      allow_late_join: Boolean(allowLateJoin),
      settings: cleanSettings,
      world_state: {},
      last_event_seq: 0,
      announcement: '',
      created_at: now,
      updated_at: now,
      last_activity_at: now,
    };
    mem.rooms.set(id, room);
    const playersMap = new Map();
    playersMap.set(hostUserId, {
      room_id: id,
      user_id: hostUserId,
      username: hostUsername,
      is_host: true,
      is_ready: true,
      player_state: {},
      joined_at: now,
      last_seen_at: now,
    });
    mem.roomPlayers.set(id, playersMap);
    return { room: normalizeRoomRow(room), players: getMemRoomPlayersArray(id) };
  }

  const sql = getSql();
  const roomRows = await sql`
    INSERT INTO rooms (
      id, room_code, name, host_user_id, mode, status, difficulty,
      max_players, password_hash, can_use_shop_items, allow_late_join, settings
    ) VALUES (
      ${id}, ${roomCode}, ${cleanName}, ${hostUserId}, ${mode}, 'lobby', ${difficulty},
      ${maxPlayers}, ${passwordHash || null}, ${Boolean(canUseShopItems)}, ${Boolean(allowLateJoin)},
      ${JSON.stringify(cleanSettings)}::jsonb
    )
    RETURNING *
  `;
  await sql`
    INSERT INTO room_players (room_id, user_id, username, is_host, is_ready)
    VALUES (${id}, ${hostUserId}, ${hostUsername}, TRUE, TRUE)
  `;
  const players = await getRoomPlayers(id);
  return { room: normalizeRoomRow(roomRows[0]), players };
}

export async function joinRoom({ roomId, userId, username }) {
  await ensureSchema();
  if (isMemoryMode()) {
    const room = mem.rooms.get(roomId);
    if (!room) return null;
    let playersMap = mem.roomPlayers.get(roomId);
    if (!playersMap) {
      playersMap = new Map();
      mem.roomPlayers.set(roomId, playersMap);
    }
    const existing = playersMap.get(userId);
    if (existing) {
      existing.last_seen_at = new Date();
      room.last_activity_at = new Date();
      return { room: normalizeRoomRow(room), players: getMemRoomPlayersArray(roomId) };
    }
    const now = new Date();
    playersMap.set(userId, {
      room_id: roomId,
      user_id: userId,
      username,
      is_host: false,
      is_ready: false,
      player_state: {},
      joined_at: now,
      last_seen_at: now,
    });
    await appendRoomEvent({
      roomId,
      senderUserId: userId,
      senderUsername: username,
      eventType: 'player_joined',
      payload: { userId, username },
    });
    return { room: normalizeRoomRow(room), players: getMemRoomPlayersArray(roomId) };
  }

  const sql = getSql();
  const existing = await sql`
    SELECT * FROM room_players WHERE room_id = ${roomId} AND user_id = ${userId} LIMIT 1
  `;
  if (existing[0]) {
    await sql`
      UPDATE room_players SET last_seen_at = NOW() WHERE room_id = ${roomId} AND user_id = ${userId}
    `;
    await sql`UPDATE rooms SET last_activity_at = NOW() WHERE id = ${roomId}`;
  } else {
    await sql`
      INSERT INTO room_players (room_id, user_id, username, is_host, is_ready)
      VALUES (${roomId}, ${userId}, ${username}, FALSE, FALSE)
    `;
    await appendRoomEvent({
      roomId,
      senderUserId: userId,
      senderUsername: username,
      eventType: 'player_joined',
      payload: { userId, username },
    });
  }
  const room = await findRoomById(roomId);
  const players = await getRoomPlayers(roomId);
  return { room, players };
}

export async function leaveRoom({ roomId, userId, username }) {
  await ensureSchema();
  if (isMemoryMode()) {
    const room = mem.rooms.get(roomId);
    if (!room) return;
    const playersMap = mem.roomPlayers.get(roomId);
    if (playersMap) {
      playersMap.delete(userId);
    }
    const remaining = getMemRoomPlayersArray(roomId);
    if (remaining.length === 0) {
      room.status = 'closed';
      room.updated_at = new Date();
      return;
    }
    await appendRoomEvent({
      roomId,
      senderUserId: userId,
      senderUsername: username,
      eventType: 'player_left',
      payload: { userId, username },
    });
    if (room.host_user_id === userId) {
      const nextHost = remaining[0];
      nextHost.is_host = true;
      nextHost.is_ready = true;
      room.host_user_id = nextHost.user_id;
      await appendRoomEvent({
        roomId,
        senderUserId: nextHost.user_id,
        senderUsername: nextHost.username,
        eventType: 'host_changed',
        payload: { newHostUserId: nextHost.user_id, newHostUsername: nextHost.username },
      });
    }
    return;
  }

  const sql = getSql();
  const room = await findRoomById(roomId);
  if (!room) return;
  await sql`DELETE FROM room_players WHERE room_id = ${roomId} AND user_id = ${userId}`;
  const remaining = await getRoomPlayers(roomId);
  if (remaining.length === 0) {
    await sql`UPDATE rooms SET status = 'closed', updated_at = NOW() WHERE id = ${roomId}`;
    return;
  }
  await appendRoomEvent({
    roomId,
    senderUserId: userId,
    senderUsername: username,
    eventType: 'player_left',
    payload: { userId, username },
  });
  if (room.host_user_id === userId) {
    const nextHost = remaining[0];
    await sql`
      UPDATE room_players SET is_host = TRUE, is_ready = TRUE
      WHERE room_id = ${roomId} AND user_id = ${nextHost.user_id}
    `;
    await sql`
      UPDATE rooms SET host_user_id = ${nextHost.user_id}, updated_at = NOW()
      WHERE id = ${roomId}
    `;
    await appendRoomEvent({
      roomId,
      senderUserId: nextHost.user_id,
      senderUsername: nextHost.username,
      eventType: 'host_changed',
      payload: { newHostUserId: nextHost.user_id, newHostUsername: nextHost.username },
    });
  }
}

export async function setPlayerReady({ roomId, userId, isReady }) {
  await ensureSchema();
  if (isMemoryMode()) {
    const room = mem.rooms.get(roomId);
    const playersMap = mem.roomPlayers.get(roomId);
    const player = playersMap?.get(userId);
    if (!room || !player) return null;
    player.is_ready = Boolean(isReady);
    player.last_seen_at = new Date();
    room.last_activity_at = new Date();
    return { room: normalizeRoomRow(room), players: getMemRoomPlayersArray(roomId) };
  }
  const sql = getSql();
  const updated = await sql`
    UPDATE room_players SET is_ready = ${Boolean(isReady)}, last_seen_at = NOW()
    WHERE room_id = ${roomId} AND user_id = ${userId}
    RETURNING user_id
  `;
  if (!updated[0]) return null;
  await sql`UPDATE rooms SET last_activity_at = NOW(), updated_at = NOW() WHERE id = ${roomId}`;
  return { room: await findRoomById(roomId), players: await getRoomPlayers(roomId) };
}

export async function startRoom({ roomId, hostUserId, hostUsername, initialWorldState }) {
  await ensureSchema();
  const cleanState = sanitizeDeepValue(initialWorldState) || {};
  if (isMemoryMode()) {
    const room = mem.rooms.get(roomId);
    if (!room) return null;
    room.status = 'playing';
    room.world_state = cleanState;
    room.updated_at = new Date();
    room.last_activity_at = new Date();
    await appendRoomEvent({
      roomId,
      senderUserId: hostUserId,
      senderUsername: hostUsername,
      eventType: 'game_started',
      payload: { startedBy: hostUsername },
    });
    return { room: normalizeRoomRow(room), players: getMemRoomPlayersArray(roomId) };
  }
  const sql = getSql();
  await sql`
    UPDATE rooms SET
      status = 'playing',
      world_state = ${JSON.stringify(cleanState)}::jsonb,
      updated_at = NOW(),
      last_activity_at = NOW()
    WHERE id = ${roomId}
  `;
  await appendRoomEvent({
    roomId,
    senderUserId: hostUserId,
    senderUsername: hostUsername,
    eventType: 'game_started',
    payload: { startedBy: hostUsername },
  });
  return { room: await findRoomById(roomId), players: await getRoomPlayers(roomId) };
}

export async function kickPlayerFromRoom({
  roomId,
  targetUserId,
  kickedByUserId = null,
  kickedByUsername = 'admin',
  isAdmin = false,
}) {
  await ensureSchema();
  if (isMemoryMode()) {
    const room = mem.rooms.get(roomId);
    const playersMap = mem.roomPlayers.get(roomId);
    const target = playersMap?.get(targetUserId);
    if (!room || !target) return null;
    playersMap.delete(targetUserId);
    await appendRoomEvent({
      roomId,
      senderUserId: kickedByUserId,
      senderUsername: kickedByUsername,
      eventType: 'player_kicked',
      payload: {
        targetUserId,
        targetUsername: target.username,
        kickedBy: kickedByUsername,
        isAdmin,
      },
    });
    const remaining = getMemRoomPlayersArray(roomId);
    if (remaining.length === 0) {
      room.status = 'closed';
    } else if (room.host_user_id === targetUserId) {
      const nextHost = remaining[0];
      nextHost.is_host = true;
      nextHost.is_ready = true;
      room.host_user_id = nextHost.user_id;
      await appendRoomEvent({
        roomId,
        senderUserId: nextHost.user_id,
        senderUsername: nextHost.username,
        eventType: 'host_changed',
        payload: { newHostUserId: nextHost.user_id, newHostUsername: nextHost.username },
      });
    }
    return { room: normalizeRoomRow(room), players: remaining };
  }

  const sql = getSql();
  const targetRows = await sql`
    DELETE FROM room_players
    WHERE room_id = ${roomId} AND user_id = ${targetUserId}
    RETURNING username
  `;
  if (!targetRows[0]) return null;
  await appendRoomEvent({
    roomId,
    senderUserId: kickedByUserId,
    senderUsername: kickedByUsername,
    eventType: 'player_kicked',
    payload: {
      targetUserId,
      targetUsername: targetRows[0].username,
      kickedBy: kickedByUsername,
      isAdmin,
    },
  });
  const remaining = await getRoomPlayers(roomId);
  const room = await findRoomById(roomId);
  if (remaining.length === 0) {
    await sql`UPDATE rooms SET status = 'closed', updated_at = NOW() WHERE id = ${roomId}`;
  } else if (room && room.host_user_id === targetUserId) {
    const nextHost = remaining[0];
    await sql`
      UPDATE room_players SET is_host = TRUE, is_ready = TRUE
      WHERE room_id = ${roomId} AND user_id = ${nextHost.user_id}
    `;
    await sql`UPDATE rooms SET host_user_id = ${nextHost.user_id}, updated_at = NOW() WHERE id = ${roomId}`;
    await appendRoomEvent({
      roomId,
      senderUserId: nextHost.user_id,
      senderUsername: nextHost.username,
      eventType: 'host_changed',
      payload: { newHostUserId: nextHost.user_id, newHostUsername: nextHost.username },
    });
  }
  return { room: await findRoomById(roomId), players: await getRoomPlayers(roomId) };
}

export async function wasUserKickedFromRoom(roomId, userId) {
  await ensureSchema();
  if (isMemoryMode()) {
    return mem.roomEvents.some(
      (ev) =>
        ev.room_id === roomId &&
        ev.event_type === 'player_kicked' &&
        ev.payload?.targetUserId === userId
    );
  }
  const sql = getSql();
  const rows = await sql`
    SELECT id FROM room_events
    WHERE room_id = ${roomId}
      AND event_type = 'player_kicked'
      AND payload->>'targetUserId' = ${userId}
    LIMIT 1
  `;
  return rows.length > 0;
}

export async function syncRoom({
  roomId,
  userId,
  username,
  lastEventSeq,
  playerState,
  worldState,
  events = [],
}) {
  await ensureSchema();
  const peerCutoffMs = Date.now() - 25_000;

  if (isMemoryMode()) {
    const room = mem.rooms.get(roomId);
    const playersMap = mem.roomPlayers.get(roomId);
    const selfPlayer = playersMap?.get(userId);
    if (!room || !selfPlayer) return null;

    selfPlayer.last_seen_at = new Date();
    if (playerState !== undefined) {
      selfPlayer.player_state = sanitizeDeepValue(playerState) || {};
    }

    // Drop unseen peers >25s
    const dropped = [];
    for (const [pid, p] of playersMap.entries()) {
      if (pid !== userId && new Date(p.last_seen_at).getTime() < peerCutoffMs) {
        playersMap.delete(pid);
        dropped.push(p);
      }
    }
    for (const d of dropped) {
      await appendRoomEvent({
        roomId,
        senderUserId: d.user_id,
        senderUsername: d.username,
        eventType: 'player_timeout',
        payload: { userId: d.user_id, username: d.username },
      });
    }

    const remaining = getMemRoomPlayersArray(roomId);
    if (!remaining.some((p) => p.user_id === room.host_user_id) && remaining.length > 0) {
      const nextHost = remaining[0];
      nextHost.is_host = true;
      nextHost.is_ready = true;
      room.host_user_id = nextHost.user_id;
      await appendRoomEvent({
        roomId,
        senderUserId: nextHost.user_id,
        senderUsername: nextHost.username,
        eventType: 'host_changed',
        payload: { newHostUserId: nextHost.user_id, newHostUsername: nextHost.username },
      });
    }

    if (room.host_user_id === userId && worldState !== undefined) {
      room.world_state = sanitizeDeepValue(worldState) || {};
    }

    for (const ev of events.slice(0, 10)) {
      await appendRoomEvent({
        roomId,
        senderUserId: userId,
        senderUsername: username,
        eventType: ev.type,
        payload: ev.payload,
      });
    }

    room.last_activity_at = new Date();
    room.updated_at = new Date();

    const sinceSeq = Math.max(0, Math.trunc(Number(lastEventSeq) || 0));
    const newEvents = mem.roomEvents
      .filter((e) => e.room_id === roomId && e.seq > sinceSeq)
      .sort((a, b) => a.seq - b.seq);

    return {
      room: normalizeRoomRow(room),
      players: getMemRoomPlayersArray(roomId),
      events: newEvents,
    };
  }

  const sql = getSql();
  const roomBefore = await findRoomById(roomId);
  if (!roomBefore) return null;

  const cleanPlayerState = playerState !== undefined ? sanitizeDeepValue(playerState) || {} : null;
  if (cleanPlayerState !== null) {
    const upd = await sql`
      UPDATE room_players
      SET last_seen_at = NOW(), player_state = ${JSON.stringify(cleanPlayerState)}::jsonb
      WHERE room_id = ${roomId} AND user_id = ${userId}
      RETURNING user_id
    `;
    if (!upd[0]) return null;
  } else {
    const upd = await sql`
      UPDATE room_players
      SET last_seen_at = NOW()
      WHERE room_id = ${roomId} AND user_id = ${userId}
      RETURNING user_id
    `;
    if (!upd[0]) return null;
  }

  const cutoffIso = new Date(peerCutoffMs).toISOString();
  const dropped = await sql`
    DELETE FROM room_players
    WHERE room_id = ${roomId}
      AND user_id <> ${userId}
      AND last_seen_at < ${cutoffIso}::timestamptz
    RETURNING user_id, username
  `;
  for (const d of dropped) {
    await appendRoomEvent({
      roomId,
      senderUserId: d.user_id,
      senderUsername: d.username,
      eventType: 'player_timeout',
      payload: { userId: d.user_id, username: d.username },
    });
  }

  let currentPlayers = await getRoomPlayers(roomId);
  let effectiveHostId = roomBefore.host_user_id;
  if (
    currentPlayers.length > 0 &&
    !currentPlayers.some((p) => p.user_id === effectiveHostId)
  ) {
    const nextHost = currentPlayers[0];
    effectiveHostId = nextHost.user_id;
    await sql`
      UPDATE room_players SET is_host = TRUE, is_ready = TRUE
      WHERE room_id = ${roomId} AND user_id = ${nextHost.user_id}
    `;
    await sql`
      UPDATE rooms SET host_user_id = ${nextHost.user_id}, updated_at = NOW()
      WHERE id = ${roomId}
    `;
    await appendRoomEvent({
      roomId,
      senderUserId: nextHost.user_id,
      senderUsername: nextHost.username,
      eventType: 'host_changed',
      payload: { newHostUserId: nextHost.user_id, newHostUsername: nextHost.username },
    });
    currentPlayers = await getRoomPlayers(roomId);
  }

  if (effectiveHostId === userId && worldState !== undefined) {
    const cleanWorld = sanitizeDeepValue(worldState) || {};
    await sql`
      UPDATE rooms SET
        world_state = ${JSON.stringify(cleanWorld)}::jsonb,
        last_activity_at = NOW(),
        updated_at = NOW()
      WHERE id = ${roomId}
    `;
  } else {
    await sql`UPDATE rooms SET last_activity_at = NOW(), updated_at = NOW() WHERE id = ${roomId}`;
  }

  for (const ev of events.slice(0, 10)) {
    await appendRoomEvent({
      roomId,
      senderUserId: userId,
      senderUsername: username,
      eventType: ev.type,
      payload: ev.payload,
    });
  }

  const sinceSeq = Math.max(0, Math.trunc(Number(lastEventSeq) || 0));
  const eventRows = await sql`
    SELECT * FROM room_events
    WHERE room_id = ${roomId} AND seq > ${sinceSeq}
    ORDER BY seq ASC
    LIMIT 100
  `;

  return {
    room: await findRoomById(roomId),
    players: currentPlayers,
    events: eventRows.map((e) => ({ ...e, payload: parseJsonField(e.payload, {}) })),
  };
}

export async function closeRoomAdmin({ roomId, message = '', adminUsername = 'admin' }) {
  await ensureSchema();
  const cleanMsg = sanitizeText(message, 240);
  if (isMemoryMode()) {
    const room = mem.rooms.get(roomId);
    if (!room) return null;
    await appendRoomEvent({
      roomId,
      senderUsername: adminUsername,
      eventType: 'room_closed',
      payload: { message: cleanMsg || 'Room ditutup oleh admin.' },
    });
    room.status = 'closed';
    room.updated_at = new Date();
    mem.roomPlayers.delete(roomId);
    return normalizeRoomRow(room);
  }
  const sql = getSql();
  const room = await findRoomById(roomId);
  if (!room) return null;
  await appendRoomEvent({
    roomId,
    senderUsername: adminUsername,
    eventType: 'room_closed',
    payload: { message: cleanMsg || 'Room ditutup oleh admin.' },
  });
  await sql`UPDATE rooms SET status = 'closed', updated_at = NOW() WHERE id = ${roomId}`;
  await sql`DELETE FROM room_players WHERE room_id = ${roomId}`;
  return findRoomById(roomId);
}

export async function broadcastRoomAdmin({ roomId, message, adminUsername = 'admin' }) {
  await ensureSchema();
  const cleanMsg = sanitizeText(message, 240);
  if (isMemoryMode()) {
    const room = mem.rooms.get(roomId);
    if (!room) return null;
    room.announcement = cleanMsg;
    await appendRoomEvent({
      roomId,
      senderUsername: adminUsername,
      eventType: 'admin_broadcast',
      payload: { message: cleanMsg, sender: adminUsername },
    });
    return normalizeRoomRow(room);
  }
  const sql = getSql();
  const rows = await sql`
    UPDATE rooms SET announcement = ${cleanMsg}, updated_at = NOW(), last_activity_at = NOW()
    WHERE id = ${roomId}
    RETURNING *
  `;
  if (!rows[0]) return null;
  await appendRoomEvent({
    roomId,
    senderUsername: adminUsername,
    eventType: 'admin_broadcast',
    payload: { message: cleanMsg, sender: adminUsername },
  });
  return normalizeRoomRow(rows[0]);
}
