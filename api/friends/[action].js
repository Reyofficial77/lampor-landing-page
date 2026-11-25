import { z } from 'zod';
import * as db from '../_lib/db.js';
import {
  formatZodError,
  getRouteAction,
  requirePlayerSession,
  runSecurityPreflight,
  sendJson,
  serializeActiveRoomSummary,
  serializePublicPlayerCard,
} from '../_lib/security.js';

const addFriendSchema = z
  .strictObject({
    username: z.string().trim().min(1).max(32).optional(),
    friendUserId: z.string().uuid('friendUserId tidak valid.').optional(),
  })
  .refine((data) => Boolean(data.username || data.friendUserId), {
    message: 'username atau friendUserId wajib diisi.',
  });

const removeFriendSchema = z.strictObject({
  friendUserId: z.string().uuid('friendUserId tidak valid.'),
});

export default async function handler(req, res) {
  const action = getRouteAction(req);
  const pre = await runSecurityPreflight(req, res, db, {
    rateCategory: action === 'list' ? 'sync' : 'general',
    parseBody: req.method === 'POST',
  });
  if (pre.handled) return;

  const auth = await requirePlayerSession(req, res, db);
  if (!auth) return;

  if (action === 'list') {
    if (req.method !== 'GET') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const search = String(req.query?.search || '').trim().slice(0, 64);
    await db.cleanupStaleRooms(15);

    const [rawFriends, rawDirectory] = await Promise.all([
      db.listFriendsWithPresence(auth.user.id),
      db.listTopOrSearchPlayers({ viewerUserId: auth.user.id, search, limit: 10 }),
    ]);

    const friends = rawFriends.map((f) =>
      serializePublicPlayerCard(f, {
        isFriend: true,
        isSelf: false,
        activeRoom: serializeActiveRoomSummary(f.activeRoomRaw, { isFriend: true }),
      })
    );

    const directory = rawDirectory.map((p) =>
      serializePublicPlayerCard(p, {
        isFriend: Boolean(p.isFriend),
        isSelf: Boolean(p.isSelf),
        activeRoom: serializeActiveRoomSummary(p.activeRoomRaw, { isFriend: Boolean(p.isFriend) }),
      })
    );

    return sendJson(res, 200, { ok: true, friends, directory });
  }

  if (action === 'add') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = addFriendSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }

    const target = parsed.data.friendUserId
      ? await db.findUserById(parsed.data.friendUserId)
      : await db.findUserByUsername(parsed.data.username);

    if (!target || target.is_banned) {
      return sendJson(res, 404, {
        ok: false,
        error: 'Pemain tidak ditemukan.',
        code: 'USER_NOT_FOUND',
      });
    }

    if (target.id === auth.user.id) {
      return sendJson(res, 400, {
        ok: false,
        error: 'Tidak dapat menambahkan diri sendiri sebagai teman.',
        code: 'CANNOT_ADD_SELF',
      });
    }

    await db.addFriend(auth.user.id, target.id);
    const friends = await db.listFriendsWithPresence(auth.user.id);
    const addedRow = friends.find((f) => f.id === target.id) || target;
    const friend = serializePublicPlayerCard(addedRow, {
      isFriend: true,
      isSelf: false,
      activeRoom: serializeActiveRoomSummary(addedRow.activeRoomRaw || null, { isFriend: true }),
    });

    return sendJson(res, 200, {
      ok: true,
      message: 'Teman berhasil ditambahkan.',
      friend,
    });
  }

  if (action === 'remove') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = removeFriendSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }

    await db.removeFriend(auth.user.id, parsed.data.friendUserId);
    return sendJson(res, 200, {
      ok: true,
      message: 'Teman dihapus dari daftar.',
    });
  }

  return sendJson(res, 404, { ok: false, error: 'Endpoint teman tidak ditemukan.', code: 'NOT_FOUND' });
}
