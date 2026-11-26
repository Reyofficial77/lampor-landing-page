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

const acceptFriendSchema = z
  .strictObject({
    requesterUserId: z.string().uuid('requesterUserId tidak valid.').optional(),
    username: z.string().trim().min(1).max(32).optional(),
  })
  .refine((data) => Boolean(data.requesterUserId || data.username), {
    message: 'requesterUserId atau username wajib diisi.',
  });

const declineFriendSchema = z.strictObject({
  targetUserId: z.string().uuid('targetUserId tidak valid.'),
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

    const [rawFriends, rawIncoming, rawOutgoing, rawDirectory] = await Promise.all([
      db.listFriendsWithPresence(auth.user.id),
      db.listIncomingFriendRequests(auth.user.id),
      db.listOutgoingFriendRequests(auth.user.id),
      db.listTopOrSearchPlayers({ viewerUserId: auth.user.id, search, limit: 10 }),
    ]);

    const friends = rawFriends.map((f) =>
      serializePublicPlayerCard(f, {
        isFriend: true,
        isSelf: false,
        friendshipStatus: 'friends',
        activeRoom: serializeActiveRoomSummary(f.activeRoomRaw, { isFriend: true }),
      })
    );

    const incomingRequests = rawIncoming.map((r) =>
      serializePublicPlayerCard(r, {
        isFriend: false,
        isSelf: false,
        hasIncomingRequest: true,
        friendshipStatus: 'incoming_pending',
        requestedAt: r.requestedAt,
        activeRoom: null,
      })
    );

    const outgoingRequests = rawOutgoing.map((r) =>
      serializePublicPlayerCard(r, {
        isFriend: false,
        isSelf: false,
        hasOutgoingRequest: true,
        friendshipStatus: 'outgoing_pending',
        requestedAt: r.requestedAt,
        activeRoom: null,
      })
    );

    const directory = rawDirectory.map((p) =>
      serializePublicPlayerCard(p, {
        isFriend: Boolean(p.isFriend),
        isSelf: Boolean(p.isSelf),
        hasIncomingRequest: Boolean(p.hasIncomingRequest),
        hasOutgoingRequest: Boolean(p.hasOutgoingRequest),
        friendshipStatus: p.friendshipStatus,
        activeRoom: p.isFriend ? serializeActiveRoomSummary(p.activeRoomRaw, { isFriend: true }) : null,
      })
    );

    return sendJson(res, 200, {
      ok: true,
      friends,
      incomingRequests,
      outgoingRequests,
      directory,
    });
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

    if (!target || target.is_banned || db.isDashboardOnlyAdminUsername(target.username)) {
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

    const result = await db.sendOrAcceptFriendRequest(auth.user.id, target.id);
    if (result.status === 'friends' || result.status === 'accepted') {
      const friends = await db.listFriendsWithPresence(auth.user.id);
      const addedRow = friends.find((f) => f.id === target.id) || target;
      const friend = serializePublicPlayerCard(addedRow, {
        isFriend: true,
        isSelf: false,
        friendshipStatus: 'friends',
        activeRoom: serializeActiveRoomSummary(addedRow.activeRoomRaw || null, { isFriend: true }),
      });
      return sendJson(res, 200, {
        ok: true,
        status: result.status,
        message:
          result.status === 'accepted'
            ? 'Permintaan pertemanan diterima.'
            : 'Pemain sudah ada di daftar teman.',
        friend,
      });
    }

    const targetCard = serializePublicPlayerCard(target, {
      isFriend: false,
      isSelf: false,
      hasOutgoingRequest: true,
      friendshipStatus: 'outgoing_pending',
      activeRoom: null,
    });
    return sendJson(res, 200, {
      ok: true,
      status: 'request_sent',
      message: 'Permintaan pertemanan terkirim.',
      target: targetCard,
    });
  }

  if (action === 'accept') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = acceptFriendSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }

    const requester = parsed.data.requesterUserId
      ? await db.findUserById(parsed.data.requesterUserId)
      : await db.findUserByUsername(parsed.data.username);

    if (!requester || requester.is_banned || db.isDashboardOnlyAdminUsername(requester.username)) {
      return sendJson(res, 404, {
        ok: false,
        error: 'Pemain tidak ditemukan.',
        code: 'USER_NOT_FOUND',
      });
    }

    const result = await db.acceptFriendRequest(auth.user.id, requester.id);
    if (!result.ok) {
      return sendJson(res, 404, {
        ok: false,
        error: 'Permintaan pertemanan tidak ditemukan.',
        code: 'REQUEST_NOT_FOUND',
      });
    }

    const friends = await db.listFriendsWithPresence(auth.user.id);
    const addedRow = friends.find((f) => f.id === requester.id) || requester;
    const friend = serializePublicPlayerCard(addedRow, {
      isFriend: true,
      isSelf: false,
      friendshipStatus: 'friends',
      activeRoom: serializeActiveRoomSummary(addedRow.activeRoomRaw || null, { isFriend: true }),
    });

    return sendJson(res, 200, {
      ok: true,
      status: 'accepted',
      message: 'Permintaan pertemanan diterima.',
      friend,
    });
  }

  if (action === 'decline') {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
    }
    const parsed = declineFriendSchema.safeParse(pre.body);
    if (!parsed.success) {
      return sendJson(res, 400, {
        ok: false,
        error: formatZodError(parsed.error),
        code: 'VALIDATION_ERROR',
      });
    }

    await db.declineOrCancelFriendRequest(auth.user.id, parsed.data.targetUserId);
    return sendJson(res, 200, {
      ok: true,
      message: 'Permintaan pertemanan dibatalkan.',
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
