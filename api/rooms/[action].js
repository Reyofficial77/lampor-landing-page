import crypto from 'node:crypto';
import { z } from 'zod';
import * as db from '../_lib/db.js';
import {
  ALLOWED_DIFFICULTIES,
  formatZodError,
  getRouteAction,
  hashPassword,
  requirePlayerSession,
  runSecurityPreflight,
  sanitizeDeepValue,
  sanitizeText,
  sendJson,
  serializeRoom,
  serializeRoomEvent,
  serializeRoomPlayer,
  verifyPassword,
} from '../_lib/security.js';

const ROOM_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function generateRoomCode() {
  let code = '';
  for (let i = 0; i < 6; i += 1) {
    code += ROOM_CODE_ALPHABET[crypto.randomInt(0, ROOM_CODE_ALPHABET.length)];
  }
  return code;
}

const createRoomSchema = z.strictObject({
  name: z.string().min(1, 'Nama room wajib diisi.').max(80),
  password: z.string().max(72).optional(),
  mode: z.enum(['multiplayer', 'sandbox']).default('multiplayer'),
  maxPlayers: z.number().int().min(1).max(4).default(4),
  difficulty: z.string().min(1).max(24).default('normal'),
  canUseShopItems: z.boolean().default(true),
  allowLateJoin: z.boolean().optional(),
  settings: z.record(z.string(), z.unknown()).optional(),
});

const joinRoomSchema = z
  .strictObject({
    roomId: z.string().uuid().optional(),
    roomCode: z.string().trim().min(4).max(12).optional(),
    password: z.string().max(72).optional(),
  })
  .refine((data) => Boolean(data.roomId || data.roomCode), {
    message: 'roomId atau roomCode wajib diisi.',
  });

const roomIdSchema = z.strictObject({
  roomId: z.string().uuid('roomId tidak valid.'),
});

const readySchema = z.strictObject({
  roomId: z.string().uuid('roomId tidak valid.'),
  isReady: z.boolean(),
});

const kickSchema = z.strictObject({
  roomId: z.string().uuid('roomId tidak valid.'),
  targetUserId: z.string().uuid('targetUserId tidak valid.'),
});

const rawEventSchema = z.strictObject({
  type: z.string().regex(/^[a-zA-Z0-9_:-]{1,48}$/).optional(),
  eventType: z.string().regex(/^[a-zA-Z0-9_:-]{1,48}$/).optional(),
  payload: z.record(z.string(), z.unknown()).optional(),
  data: z.record(z.string(), z.unknown()).optional(),
});

const syncRoomSchema = z.strictObject({
  roomId: z.string().uuid('roomId tidak valid.'),
  lastEventSeq: z.number().int().min(0).default(0),
  playerState: z.record(z.string(), z.unknown()).optional(),
  worldState: z.record(z.string(), z.unknown()).optional(),
  events: z.array(rawEventSchema).max(10).optional(),
});

export default async function handler(req, res) {
  const action = getRouteAction(req);
  const pre = await runSecurityPreflight(req, res, db, {
    rateCategory: action === 'sync' ? 'sync' : 'general',
    parseBody: req.method === 'POST',
  });
  if (pre.handled) return;

  const auth = await requirePlayerSession(req, res, db);
  if (!auth) return;

  const settings = await db.getServerSettings();
  if (settings.maintenance_mode) {
    return sendJson(res, 503, {
      ok: false,
      error:
        sanitizeText(settings.maintenance_message || '', 300) ||
        'Server sedang dalam pemeliharaan.',
      code: 'MAINTENANCE_MODE',
    });
  }

  if (action === 'list') {
    if (req.method !== 'GET') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const rawMode = String(req.query?.mode || 'all').toLowerCase();
    const modeFilter = ['multiplayer', 'sandbox', 'all'].includes(rawMode) ? rawMode : 'all';

    await db.cleanupStaleRooms(15);
    const entries = await db.listActiveRooms(modeFilter);
    const rooms = entries.map(({ room, players }) => serializeRoom(room, players));
    return sendJson(res, 200, { ok: true, rooms });
  }

  if (action === 'create') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = createRoomSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }

    const cleanName = sanitizeText(parsed.data.name, 60);
    if (cleanName.length < 2) {
      return sendJson(res, 400, {
        ok: false,
        error: 'Nama room minimal 2 karakter yang valid.',
        code: 'INVALID_ROOM_NAME',
      });
    }

    const mode = parsed.data.mode;
    if (mode === 'multiplayer' && !settings.allow_multiplayer) {
      return sendJson(res, 403, {
        ok: false,
        error: 'Mode Multiplayer sedang dinonaktifkan oleh admin.',
        code: 'MULTIPLAYER_DISABLED',
      });
    }
    if (mode === 'sandbox' && !settings.allow_sandbox) {
      return sendJson(res, 403, {
        ok: false,
        error: 'Mode Sandbox sedang dinonaktifkan oleh admin.',
        code: 'SANDBOX_DISABLED',
      });
    }

    const difficulty = parsed.data.difficulty.trim().toLowerCase();
    if (!ALLOWED_DIFFICULTIES.includes(difficulty)) {
      return sendJson(res, 400, {
        ok: false,
        error: 'Tingkat kesulitan tidak valid.',
        code: 'INVALID_DIFFICULTY',
      });
    }

    await db.cleanupStaleRooms(15);
    const activeCount = await db.countActiveRooms();
    if (activeCount >= settings.max_active_rooms) {
      return sendJson(res, 429, {
        ok: false,
        error: 'Batas maksimal room aktif telah tercapai.',
        code: 'MAX_ROOMS_REACHED',
      });
    }

    let roomCode = generateRoomCode();
    for (let i = 0; i < 5; i += 1) {
      const existing = await db.findRoomByCode(roomCode);
      if (!existing) break;
      roomCode = generateRoomCode();
    }

    const passwordHash =
      parsed.data.password && parsed.data.password.length > 0
        ? hashPassword(parsed.data.password)
        : null;

    const created = await db.createRoom({
      roomCode,
      name: cleanName,
      hostUserId: auth.user.id,
      hostUsername: auth.user.username,
      mode,
      difficulty,
      maxPlayers: parsed.data.maxPlayers,
      passwordHash,
      canUseShopItems: parsed.data.canUseShopItems,
      allowLateJoin: Boolean(parsed.data.allowLateJoin),
      settings: sanitizeDeepValue(parsed.data.settings || {}) || {},
    });

    return sendJson(res, 201, {
      ok: true,
      room: serializeRoom(created.room, created.players),
      players: created.players.map(serializeRoomPlayer),
    });
  }

  if (action === 'join') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = joinRoomSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }

    const room = parsed.data.roomId
      ? await db.findRoomById(parsed.data.roomId)
      : await db.findRoomByCode(parsed.data.roomCode);

    if (!room) {
      return sendJson(res, 404, { ok: false, error: 'Room tidak ditemukan.', code: 'ROOM_NOT_FOUND' });
    }
    if (room.status === 'closed') {
      return sendJson(res, 410, { ok: false, error: 'Room sudah ditutup.', code: 'ROOM_CLOSED' });
    }
    if (room.status === 'playing' && !room.allow_late_join) {
      return sendJson(res, 409, {
        ok: false,
        error: 'Permainan sudah berlangsung dan tidak menerima pemain baru.',
        code: 'GAME_ALREADY_STARTED',
      });
    }
    if (room.password_hash) {
      if (!parsed.data.password || !verifyPassword(parsed.data.password, room.password_hash)) {
        return sendJson(res, 403, {
          ok: false,
          error: 'Password room salah.',
          code: 'INVALID_ROOM_PASSWORD',
        });
      }
    }

    const currentPlayers = await db.getRoomPlayers(room.id);
    const alreadyIn = currentPlayers.some((p) => p.user_id === auth.user.id);
    if (!alreadyIn && currentPlayers.length >= room.max_players) {
      return sendJson(res, 409, { ok: false, error: 'Room sudah penuh.', code: 'ROOM_FULL' });
    }

    const joined = await db.joinRoom({
      roomId: room.id,
      userId: auth.user.id,
      username: auth.user.username,
    });

    return sendJson(res, 200, {
      ok: true,
      room: serializeRoom(joined.room, joined.players),
      players: joined.players.map(serializeRoomPlayer),
    });
  }

  if (action === 'leave') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = roomIdSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }
    await db.leaveRoom({
      roomId: parsed.data.roomId,
      userId: auth.user.id,
      username: auth.user.username,
    });
    return sendJson(res, 200, { ok: true });
  }

  if (action === 'ready') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = readySchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }
    const room = await db.findRoomById(parsed.data.roomId);
    if (!room) {
      return sendJson(res, 404, { ok: false, error: 'Room tidak ditemukan.', code: 'ROOM_NOT_FOUND' });
    }
    if (room.status === 'closed') {
      return sendJson(res, 410, { ok: false, error: 'Room sudah ditutup.', code: 'ROOM_CLOSED' });
    }
    const updated = await db.setPlayerReady({
      roomId: room.id,
      userId: auth.user.id,
      isReady: parsed.data.isReady,
    });
    if (!updated) {
      return sendJson(res, 403, {
        ok: false,
        error: 'Anda bukan anggota room ini.',
        code: 'NOT_A_MEMBER',
      });
    }
    return sendJson(res, 200, {
      ok: true,
      room: serializeRoom(updated.room, updated.players),
      players: updated.players.map(serializeRoomPlayer),
    });
  }

  if (action === 'start') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = roomIdSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }
    const room = await db.findRoomById(parsed.data.roomId);
    if (!room) {
      return sendJson(res, 404, { ok: false, error: 'Room tidak ditemukan.', code: 'ROOM_NOT_FOUND' });
    }
    if (room.status === 'closed') {
      return sendJson(res, 410, { ok: false, error: 'Room sudah ditutup.', code: 'ROOM_CLOSED' });
    }
    if (room.host_user_id !== auth.user.id) {
      return sendJson(res, 403, {
        ok: false,
        error: 'Hanya host room yang dapat memulai permainan.',
        code: 'HOST_ONLY',
      });
    }
    if (room.status === 'playing') {
      return sendJson(res, 409, {
        ok: false,
        error: 'Permainan sudah dimulai.',
        code: 'ALREADY_STARTED',
      });
    }

    const initialWorldState = {
      startedAt: new Date().toISOString(),
      hour: 1,
      minute: 0,
      act: 1,
      torchesLit: 0,
      doorsBarricaded: 0,
      furnaceBurning: false,
      furnaceTimeLeft: 45.0,
      ritualItems: {},
      difficulty: room.difficulty,
      mode: room.mode,
    };

    const started = await db.startRoom({
      roomId: room.id,
      hostUserId: auth.user.id,
      hostUsername: auth.user.username,
      initialWorldState,
    });

    return sendJson(res, 200, {
      ok: true,
      room: serializeRoom(started.room, started.players),
      players: started.players.map(serializeRoomPlayer),
    });
  }

  if (action === 'kick') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = kickSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }
    const room = await db.findRoomById(parsed.data.roomId);
    if (!room) {
      return sendJson(res, 404, { ok: false, error: 'Room tidak ditemukan.', code: 'ROOM_NOT_FOUND' });
    }
    if (room.status === 'closed') {
      return sendJson(res, 410, { ok: false, error: 'Room sudah ditutup.', code: 'ROOM_CLOSED' });
    }
    if (room.host_user_id !== auth.user.id) {
      return sendJson(res, 403, {
        ok: false,
        error: 'Hanya host room yang dapat mengeluarkan pemain.',
        code: 'HOST_ONLY',
      });
    }
    if (parsed.data.targetUserId === auth.user.id) {
      return sendJson(res, 400, {
        ok: false,
        error: 'Host tidak dapat mengeluarkan dirinya sendiri.',
        code: 'CANNOT_KICK_SELF',
      });
    }

    const kicked = await db.kickPlayerFromRoom({
      roomId: room.id,
      targetUserId: parsed.data.targetUserId,
      kickedByUserId: auth.user.id,
      kickedByUsername: auth.user.username,
      isAdmin: false,
    });
    if (!kicked) {
      return sendJson(res, 404, {
        ok: false,
        error: 'Pemain target tidak ada di room.',
        code: 'PLAYER_NOT_IN_ROOM',
      });
    }

    return sendJson(res, 200, {
      ok: true,
      room: serializeRoom(kicked.room, kicked.players),
      players: kicked.players.map(serializeRoomPlayer),
    });
  }

  if (action === 'sync') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = syncRoomSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }

    const room = await db.findRoomById(parsed.data.roomId);
    if (!room) {
      return sendJson(res, 404, { ok: false, error: 'Room tidak ditemukan.', code: 'ROOM_NOT_FOUND' });
    }
    if (room.status === 'closed') {
      return sendJson(res, 410, { ok: false, error: 'Room sudah ditutup.', code: 'ROOM_CLOSED' });
    }

    const currentPlayers = await db.getRoomPlayers(room.id);
    const isMember = currentPlayers.some((p) => p.user_id === auth.user.id);
    if (!isMember) {
      const wasKicked = await db.wasUserKickedFromRoom(room.id, auth.user.id);
      return sendJson(res, 403, {
        ok: false,
        error: wasKicked ? 'Anda dikeluarkan dari room.' : 'Anda bukan anggota room ini.',
        code: wasKicked ? 'PLAYER_KICKED' : 'NOT_A_MEMBER',
      });
    }

    const normalizedEvents = (parsed.data.events || [])
      .map((ev) => ({
        type: ev.type || ev.eventType || 'custom',
        payload: sanitizeDeepValue(ev.payload || ev.data || {}) || {},
      }))
      .slice(0, 10);

    const synced = await db.syncRoom({
      roomId: room.id,
      userId: auth.user.id,
      username: auth.user.username,
      lastEventSeq: parsed.data.lastEventSeq,
      playerState: parsed.data.playerState,
      worldState: parsed.data.worldState,
      events: normalizedEvents,
    });

    if (!synced) {
      return sendJson(res, 403, {
        ok: false,
        error: 'Anda bukan anggota room ini.',
        code: 'NOT_A_MEMBER',
      });
    }

    const globalAnn = sanitizeText(settings.global_announcement || '', 300);
    const roomAnn = sanitizeText(synced.room.announcement || '', 240);
    const announcement = roomAnn
      ? globalAnn
        ? `${globalAnn} | ${roomAnn}`
        : roomAnn
      : globalAnn;

    return sendJson(res, 200, {
      ok: true,
      room: serializeRoom(synced.room, synced.players),
      players: synced.players.map(serializeRoomPlayer),
      worldState: sanitizeDeepValue(synced.room.world_state || {}) || {},
      events: synced.events.map(serializeRoomEvent),
      lastEventSeq: Number(synced.room.last_event_seq ?? 0),
      serverTime: new Date().toISOString(),
      announcement,
    });
  }

  return sendJson(res, 404, { ok: false, error: 'Endpoint room tidak ditemukan.', code: 'NOT_FOUND' });
}
