import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

process.env.LAMPOR_TEST_DB = 'memory';
process.env.AUTH_SECRET = 'lampor-test-auth-secret-hmac-sha256-v130';
process.env.ADMIN_USERNAME = 'admin_lampor';
process.env.ADMIN_PASSWORD = 'AdminPassword123';
process.env.LAMPOR_RATE_LIMIT_AUTH = '15';

const { createApiServer } = await import('../dev-api-server.mjs');
const { resetMemoryDb } = await import('../api/_lib/db.js');

let server;
let baseUrl;

before(async () => {
  resetMemoryDb();
  server = createApiServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
});

async function api(path, { method = 'GET', body, token, cookies, csrf, ip, headers = {} } = {}) {
  const reqHeaders = { ...headers };
  if (token) reqHeaders.Authorization = `Bearer ${token}`;
  if (ip) reqHeaders['X-Forwarded-For'] = ip;
  if (csrf) reqHeaders['X-Lampor-CSRF'] = csrf;
  if (cookies && Object.keys(cookies).length > 0) {
    reqHeaders.Cookie = Object.entries(cookies)
      .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
      .join('; ');
  }
  let payload;
  if (body !== undefined) {
    reqHeaders['Content-Type'] = 'application/json';
    payload = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: reqHeaders,
    body: payload,
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  const setCookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
  return { status: res.status, headers: res.headers, setCookies, json, text };
}

function parseSetCookieJar(setCookies) {
  const jar = {};
  for (const line of setCookies) {
    const firstPart = line.split(';')[0];
    const idx = firstPart.indexOf('=');
    if (idx > 0) {
      const k = firstPart.slice(0, idx).trim();
      const v = decodeURIComponent(firstPart.slice(idx + 1).trim());
      if (v) jar[k] = v;
      else delete jar[k];
    }
  }
  return jar;
}

async function solvePow(ip = '10.0.0.1') {
  const chRes = await api('/api/auth/challenge', { ip });
  assert.equal(chRes.status, 200);
  assert.equal(chRes.json.ok, true);
  const { challengeId, salt, difficulty, expiresAt, signature } = chRes.json;
  const prefix = '0'.repeat(difficulty);
  let nonce = 0;
  while (true) {
    const digest = crypto.createHash('sha256').update(`${salt}:${nonce}`).digest('hex');
    if (digest.startsWith(prefix)) {
      return { challengeId, salt, difficulty, expiresAt, signature, nonce };
    }
    nonce += 1;
  }
}

async function registerPlayer(username, password = 'PlayerPass123', ip = '10.0.1.10') {
  const challenge = await solvePow(ip);
  const res = await api('/api/auth/register', {
    method: 'POST',
    ip,
    body: { username, password, challenge, website: '' },
  });
  return res;
}

test('GET /api/health returns v1.3.0 health payload and security headers', async () => {
  const res = await api('/api/health', { ip: '10.0.0.2' });
  assert.equal(res.status, 200);
  assert.equal(res.json.ok, true);
  assert.equal(res.json.version, '1.3.0');
  assert.equal(typeof res.json.dbLatencyMs, 'number');
  assert.equal(res.json.maintenanceMode, false);
  assert.equal(res.json.activeRooms, 0);
  assert.ok(res.json.serverTime);

  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
  assert.ok(res.headers.get('content-security-policy'));
  assert.equal(res.headers.get('access-control-allow-origin'), '*');
});

test('Security blocks invalid PoW, honeypot, oversized payload (413), and SQLi usernames', async () => {
  const badPow = await api('/api/auth/register', {
    method: 'POST',
    ip: '10.0.0.3',
    body: {
      username: 'validuser_1',
      password: 'Password123',
      challenge: {
        challengeId: '12345678-1234-1234-1234-123456789012',
        salt: '0123456789abcdef',
        difficulty: 3,
        expiresAt: Date.now() + 60_000,
        signature: 'a'.repeat(64),
        nonce: 0,
      },
      website: '',
    },
  });
  assert.equal(badPow.status, 400);
  assert.equal(badPow.json.code, 'INVALID_POW');

  const ch = await solvePow('10.0.0.4');
  const honeypot = await api('/api/auth/register', {
    method: 'POST',
    ip: '10.0.0.4',
    body: {
      username: 'bot_user',
      password: 'Password123',
      challenge: ch,
      website: 'https://spam-bot.example',
    },
  });
  assert.equal(honeypot.status, 400);
  assert.equal(honeypot.json.code, 'HONEYPOT_TRIGGERED');

  const sqli = await api('/api/auth/register', {
    method: 'POST',
    ip: '10.0.0.5',
    body: {
      username: "admin' OR 1=1;--",
      password: 'Password123',
      challenge: ch,
      website: '',
    },
  });
  assert.equal(sqli.status, 400);
  assert.equal(sqli.json.code, 'VALIDATION_ERROR');

  const hugePayload = JSON.stringify({
    username: 'big_user',
    password: 'Password123',
    pad: 'x'.repeat(35 * 1024),
  });
  const tooLarge = await api('/api/auth/register', {
    method: 'POST',
    ip: '10.0.0.6',
    body: hugePayload,
  });
  assert.equal(tooLarge.status, 413);
  assert.equal(tooLarge.json.code, 'PAYLOAD_TOO_LARGE');
});

test('Auth register -> me -> sync (clamping & saveSeq) -> logout -> login & 5-fail lockout', async () => {
  const reg = await registerPlayer('PemainSatu', 'KunciAman12', '10.0.2.1');
  assert.equal(reg.status, 201);
  assert.equal(reg.json.ok, true);
  assert.ok(reg.json.token);
  assert.equal(reg.json.user.username, 'PemainSatu');

  const me = await api('/api/auth/me', { token: reg.json.token, ip: '10.0.2.1' });
  assert.equal(me.status, 200);
  assert.equal(me.json.user.username, 'PemainSatu');

  const sync = await api('/api/auth/sync', {
    method: 'POST',
    token: reg.json.token,
    ip: '10.0.2.1',
    body: {
      coins: 1_500_000_000,
      totalWins: 3,
      extraLives: 99,
      itemStash: { jamu: 12, baterai: 3, energy_drink: -4, kentongan: 2 },
      redeemedCodes: Array.from({ length: 60 }, (_, i) => `CODE${i}`),
      saveSeq: 5,
      tutorialCompleted: true,
    },
  });
  assert.equal(sync.status, 200);
  assert.equal(sync.json.user.coins, 999_999_999);
  assert.equal(sync.json.user.extraLives, 5);
  assert.deepEqual(sync.json.user.itemStash, {
    jamu: 5,
    baterai: 3,
    energy_drink: 0,
    kentongan: 2,
  });
  assert.equal(sync.json.user.redeemedCodes.length, 50);
  assert.equal(sync.json.user.saveSeq, 5);

  // Stale saveSeq should NOT overwrite higher server progress
  const staleSync = await api('/api/auth/sync', {
    method: 'POST',
    token: reg.json.token,
    ip: '10.0.2.1',
    body: {
      coins: 0,
      extraLives: 0,
      saveSeq: 2,
    },
  });
  assert.equal(staleSync.status, 200);
  assert.equal(staleSync.json.user.coins, 999_999_999);
  assert.equal(staleSync.json.user.saveSeq, 5);

  // Logout revokes token
  const out = await api('/api/auth/logout', {
    method: 'POST',
    token: reg.json.token,
    ip: '10.0.2.1',
  });
  assert.equal(out.status, 200);
  const meAfterLogout = await api('/api/auth/me', { token: reg.json.token, ip: '10.0.2.1' });
  assert.equal(meAfterLogout.status, 401);

  // Brute force lockout: 5 failures -> 15m lockout
  for (let i = 0; i < 5; i += 1) {
    const ch = await solvePow(`10.0.2.${10 + i}`);
    const failRes = await api('/api/auth/login', {
      method: 'POST',
      ip: `10.0.2.${10 + i}`,
      body: {
        username: 'PemainSatu',
        password: 'WrongPassword1',
        challenge: ch,
        website: '',
      },
    });
    assert.equal(failRes.status, 401);
  }

  const chValidAfterLock = await solvePow('10.0.2.20');
  const lockedRes = await api('/api/auth/login', {
    method: 'POST',
    ip: '10.0.2.20',
    body: {
      username: 'PemainSatu',
      password: 'KunciAman12',
      challenge: chValidAfterLock,
      website: '',
    },
  });
  assert.equal(lockedRes.status, 429);
  assert.equal(lockedRes.json.code, 'ACCOUNT_LOCKED');
});

test('Player redeem flow applies reward once and blocks duplicates', async () => {
  const reg = await registerPlayer('PenukarHadiah', 'Hadiah123', '10.0.3.1');
  assert.equal(reg.status, 201);
  const token = reg.json.token;

  const okRedeem = await api('/api/redeem', {
    method: 'POST',
    token,
    ip: '10.0.3.1',
    body: { code: 'lamporgift' },
  });
  assert.equal(okRedeem.status, 200);
  assert.equal(okRedeem.json.ok, true);
  assert.equal(okRedeem.json.reward.code, 'LAMPORGIFT');
  assert.equal(okRedeem.json.user.coins, 2500);

  const dupRedeem = await api('/api/redeem', {
    method: 'POST',
    token,
    ip: '10.0.3.1',
    body: { code: 'LAMPORGIFT' },
  });
  assert.equal(dupRedeem.status, 409);

  const badRedeem = await api('/api/redeem', {
    method: 'POST',
    token,
    ip: '10.0.3.1',
    body: { code: 'KODETIDAKADA' },
  });
  assert.equal(badRedeem.status, 404);
});

test('Multiplayer & Sandbox rooms: auth gate, XSS sanitization, password, kick, sync, leave', async () => {
  // Unauthenticated blocked
  const unauth = await api('/api/rooms/list', { ip: '10.0.4.1' });
  assert.equal(unauth.status, 401);

  const host = await registerPlayer('HostDesa', 'HostPass123', '10.0.4.2');
  const peer = await registerPlayer('RekanDesa', 'PeerPass123', '10.0.4.3');
  const extra = await registerPlayer('TamuDesa', 'ExtraPass123', '10.0.4.4');

  const hostToken = host.json.token;
  const peerToken = peer.json.token;
  const extraToken = extra.json.token;

  // Reject maxPlayers > 4
  const tooManyPlayers = await api('/api/rooms/create', {
    method: 'POST',
    token: hostToken,
    ip: '10.0.4.2',
    body: {
      name: 'Room Berlebihan',
      mode: 'multiplayer',
      maxPlayers: 6,
      difficulty: 'normal',
      canUseShopItems: true,
    },
  });
  assert.equal(tooManyPlayers.status, 400);

  // Create passworded room with XSS attempt in name + Shop Items OFF
  const created = await api('/api/rooms/create', {
    method: 'POST',
    token: hostToken,
    ip: '10.0.4.2',
    body: {
      name: '<script>alert("xss")</script>Desa "Angker" & <Gelap>',
      password: 'rahasia123',
      mode: 'multiplayer',
      maxPlayers: 2,
      difficulty: 'hard',
      canUseShopItems: false,
      settings: { lamporEnabled: true, timeScale: 1.5, friendlyRevive: true },
    },
  });
  assert.equal(created.status, 201);
  const room = created.json.room;
  assert.equal(room.hasPassword, true);
  assert.equal(room.password_hash, undefined);
  assert.equal(room.canUseShopItems, false);
  assert.ok(!room.name.includes('<script>'));
  assert.ok(!room.name.includes('<'));
  assert.ok(!room.name.includes('>'));
  assert.ok(!room.name.includes('"'));
  assert.ok(!room.name.includes('&'));
  assert.equal(created.json.players.length, 1);
  assert.equal(created.json.players[0].isHost, true);
  assert.equal(created.json.players[0].isReady, true);

  // Create sandbox room too
  const sbCreated = await api('/api/rooms/create', {
    method: 'POST',
    token: extraToken,
    ip: '10.0.4.4',
    body: {
      name: 'Lab Sandbox',
      mode: 'sandbox',
      maxPlayers: 2,
      difficulty: 'normal',
      canUseShopItems: true,
    },
  });
  assert.equal(sbCreated.status, 201);
  assert.equal(sbCreated.json.room.mode, 'sandbox');

  // List filter
  const mpList = await api('/api/rooms/list?mode=multiplayer', {
    token: peerToken,
    ip: '10.0.4.3',
  });
  assert.equal(mpList.status, 200);
  assert.ok(mpList.json.rooms.some((r) => r.id === room.id));
  assert.ok(!mpList.json.rooms.some((r) => r.mode === 'sandbox'));

  // Join with wrong password -> 403
  const wrongJoin = await api('/api/rooms/join', {
    method: 'POST',
    token: peerToken,
    ip: '10.0.4.3',
    body: { roomCode: room.roomCode, password: 'salah' },
  });
  assert.equal(wrongJoin.status, 403);

  // Join with right password -> 200
  const okJoin = await api('/api/rooms/join', {
    method: 'POST',
    token: peerToken,
    ip: '10.0.4.3',
    body: { roomCode: room.roomCode, password: 'rahasia123' },
  });
  assert.equal(okJoin.status, 200);
  assert.equal(okJoin.json.players.length, 2);

  // 3rd player blocked (maxPlayers = 2)
  const fullJoin = await api('/api/rooms/join', {
    method: 'POST',
    token: extraToken,
    ip: '10.0.4.4',
    body: { roomId: room.id, password: 'rahasia123' },
  });
  assert.equal(fullJoin.status, 409);

  // Ready toggle + Start (non-host rejected, host allowed)
  const readyPeer = await api('/api/rooms/ready', {
    method: 'POST',
    token: peerToken,
    ip: '10.0.4.3',
    body: { roomId: room.id, isReady: true },
  });
  assert.equal(readyPeer.status, 200);

  const nonHostStart = await api('/api/rooms/start', {
    method: 'POST',
    token: peerToken,
    ip: '10.0.4.3',
    body: { roomId: room.id },
  });
  assert.equal(nonHostStart.status, 403);

  const hostStart = await api('/api/rooms/start', {
    method: 'POST',
    token: hostToken,
    ip: '10.0.4.2',
    body: { roomId: room.id },
  });
  assert.equal(hostStart.status, 200);
  assert.equal(hostStart.json.room.status, 'playing');

  // Host syncs worldState & XSS chat event
  const hostSync = await api('/api/rooms/sync', {
    method: 'POST',
    token: hostToken,
    ip: '10.0.4.2',
    body: {
      roomId: room.id,
      lastEventSeq: 0,
      playerState: { pos: [1, 0, 2], rotY: 1.2, isAlive: true },
      worldState: { hour: 2, minute: 15, torchesLit: 3 },
      events: [{ type: 'chat', payload: { text: '<img src=x onerror=alert(1)>Halo semua!' } }],
    },
  });
  assert.equal(hostSync.status, 200);
  assert.equal(hostSync.json.worldState.torchesLit, 3);
  const chatEv = hostSync.json.events.find((e) => e.type === 'chat');
  assert.ok(chatEv);
  assert.ok(!chatEv.payload.text.includes('<img'));
  assert.ok(chatEv.payload.text.includes('Halo semua!'));

  // Kick peer & verify peer sync receives 403
  const kickRes = await api('/api/rooms/kick', {
    method: 'POST',
    token: hostToken,
    ip: '10.0.4.2',
    body: { roomId: room.id, targetUserId: peer.json.user.id },
  });
  assert.equal(kickRes.status, 200);
  assert.equal(kickRes.json.players.length, 1);

  const kickedSync = await api('/api/rooms/sync', {
    method: 'POST',
    token: peerToken,
    ip: '10.0.4.3',
    body: { roomId: room.id, lastEventSeq: 0 },
  });
  assert.equal(kickedSync.status, 403);
  assert.equal(kickedSync.json.code, 'PLAYER_KICKED');

  // Host leaves empty room -> closes room -> sync returns 410
  const leaveRes = await api('/api/rooms/leave', {
    method: 'POST',
    token: hostToken,
    ip: '10.0.4.2',
    body: { roomId: room.id },
  });
  assert.equal(leaveRes.status, 200);

  const closedSync = await api('/api/rooms/sync', {
    method: 'POST',
    token: hostToken,
    ip: '10.0.4.2',
    body: { roomId: room.id, lastEventSeq: 0 },
  });
  assert.equal(closedSync.status, 410);
});

test('Admin force-login, CSRF enforcement, user/room/server/redeem/IP security controls', async () => {
  // Unauthenticated admin endpoints must return 401
  assert.equal((await api('/api/admin/session', { ip: '10.0.5.1' })).status, 401);
  assert.equal((await api('/api/admin/overview', { ip: '10.0.5.1' })).status, 401);
  assert.equal((await api('/api/admin/users', { ip: '10.0.5.1' })).status, 401);
  assert.equal(
    (await api('/api/admin/users-action', { method: 'POST', ip: '10.0.5.1', body: { action: 'create' } }))
      .status,
    401
  );

  // Regular player blocked from /api/admin/login
  await registerPlayer('BiasaSaja', 'PlayerPass123', '10.0.5.2');
  const chPlayer = await solvePow('10.0.5.2');
  const nonAdminLogin = await api('/api/admin/login', {
    method: 'POST',
    ip: '10.0.5.2',
    body: {
      username: 'BiasaSaja',
      password: 'PlayerPass123',
      challenge: chPlayer,
      website: '',
    },
  });
  assert.equal(nonAdminLogin.status, 403);

  // Valid admin login
  const chAdmin = await solvePow('10.0.5.3');
  const adminLogin = await api('/api/admin/login', {
    method: 'POST',
    ip: '10.0.5.3',
    headers: { Origin: 'http://localhost:5173' },
    body: {
      username: 'admin_lampor',
      password: 'AdminPassword123',
      challenge: chAdmin,
      website: '',
    },
  });
  assert.equal(adminLogin.status, 200);
  assert.equal(adminLogin.json.ok, true);
  assert.ok(adminLogin.json.csrfToken);
  assert.equal(adminLogin.headers.get('access-control-allow-origin'), 'http://localhost:5173');
  assert.equal(adminLogin.headers.get('access-control-allow-credentials'), 'true');
  assert.ok(adminLogin.setCookies.some((c) => c.includes('lampor_admin_session=') && c.includes('HttpOnly') && c.includes('SameSite=Strict')));

  const jar = parseSetCookieJar(adminLogin.setCookies);
  const csrf = adminLogin.json.csrfToken;

  // Missing CSRF rejected with 403
  const noCsrf = await api('/api/admin/server', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    body: { maintenanceMode: true },
  });
  assert.equal(noCsrf.status, 403);
  assert.equal(noCsrf.json.code, 'CSRF_INVALID');

  // Overview
  const overview = await api('/api/admin/overview', {
    ip: '10.0.5.3',
    cookies: jar,
  });
  assert.equal(overview.status, 200);
  assert.equal(typeof overview.json.stats.totalUsers, 'number');
  assert.equal(overview.json.serverSettings.allowRegistration, true);

  // Admin create -> update -> ban -> unban user
  const createdUser = await api('/api/admin/users-action', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: {
      action: 'create',
      username: 'TargetPlayer',
      password: 'TargetPass123',
      coins: 500,
      role: 'player',
    },
  });
  assert.equal(createdUser.status, 201);
  const targetId = createdUser.json.user.id;

  const editedUser = await api('/api/admin/users-action', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: {
      action: 'update',
      userId: targetId,
      coins: 7777,
      totalWins: 9,
      extraLives: 3,
    },
  });
  assert.equal(editedUser.status, 200);
  assert.equal(editedUser.json.user.coins, 7777);
  assert.equal(editedUser.json.user.totalWins, 9);

  const bannedUser = await api('/api/admin/users-action', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: {
      action: 'ban',
      userId: targetId,
      reason: '<b>Cheat</b> detected',
    },
  });
  assert.equal(bannedUser.status, 200);
  assert.equal(bannedUser.json.user.isBanned, true);
  assert.equal(bannedUser.json.user.banReason, 'Cheat detected');

  // Banned user rejected with 403 on login
  const chBanned = await solvePow('10.0.5.4');
  const bannedLogin = await api('/api/auth/login', {
    method: 'POST',
    ip: '10.0.5.4',
    body: {
      username: 'TargetPlayer',
      password: 'TargetPass123',
      challenge: chBanned,
      website: '',
    },
  });
  assert.equal(bannedLogin.status, 403);
  assert.equal(bannedLogin.json.code, 'ACCOUNT_BANNED');

  // Unban user & verify login works
  const unbanned = await api('/api/admin/users-action', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: { action: 'unban', userId: targetId },
  });
  assert.equal(unbanned.status, 200);
  assert.equal(unbanned.json.user.isBanned, false);

  const chUnbanned = await solvePow('10.0.5.5');
  const okLogin = await api('/api/auth/login', {
    method: 'POST',
    ip: '10.0.5.5',
    body: {
      username: 'TargetPlayer',
      password: 'TargetPass123',
      challenge: chUnbanned,
      website: '',
    },
  });
  assert.equal(okLogin.status, 200);
  const playerToken = okLogin.json.token;

  // Admin room force-close
  const roomToClose = await api('/api/rooms/create', {
    method: 'POST',
    token: playerToken,
    ip: '10.0.5.5',
    body: {
      name: 'Room Akan Ditutup',
      mode: 'multiplayer',
      maxPlayers: 4,
      difficulty: 'normal',
      canUseShopItems: true,
    },
  });
  assert.equal(roomToClose.status, 201);
  const closeId = roomToClose.json.room.id;

  const adminRooms = await api('/api/admin/rooms', { ip: '10.0.5.3', cookies: jar });
  assert.equal(adminRooms.status, 200);
  assert.ok(adminRooms.json.rooms.some((r) => r.id === closeId));

  const forceClose = await api('/api/admin/rooms-action', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: { action: 'close_room', roomId: closeId, message: 'Ditutup admin' },
  });
  assert.equal(forceClose.status, 200);

  const syncClosed = await api('/api/rooms/sync', {
    method: 'POST',
    token: playerToken,
    ip: '10.0.5.5',
    body: { roomId: closeId, lastEventSeq: 0 },
  });
  assert.equal(syncClosed.status, 410);

  // Server maintenance mode blocks /api/rooms/* with 503
  const maintOn = await api('/api/admin/server', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: {
      maintenanceMode: true,
      maintenanceMessage: '<script>x</script>Sedang update server.',
      globalAnnouncement: 'Pemeliharaan jam 14:00',
    },
  });
  assert.equal(maintOn.status, 200);
  assert.equal(maintOn.json.serverSettings.maintenanceMode, true);
  assert.equal(maintOn.json.serverSettings.maintenanceMessage, 'Sedang update server.');

  const blockedRoomList = await api('/api/rooms/list', { token: playerToken, ip: '10.0.5.5' });
  assert.equal(blockedRoomList.status, 503);

  const healthMaint = await api('/api/health', { ip: '10.0.5.5' });
  assert.equal(healthMaint.json.maintenanceMode, true);

  // Turn maintenance back off
  await api('/api/admin/server', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: { maintenanceMode: false },
  });

  // Admin redeem CRUD
  const createCode = await api('/api/admin/redeem', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: {
      action: 'create',
      code: 'NEWYEAR130',
      rewardType: 'item',
      itemId: 'jamu',
      quantity: 2,
      maxUses: 10,
      descriptionId: 'Bonus Jamu',
    },
  });
  assert.equal(createCode.status, 201);
  assert.ok(createCode.json.codes.some((c) => c.code === 'NEWYEAR130'));

  // IP blocklist test
  const blockIp = await api('/api/admin/security', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: { action: 'block_ip', ipAddress: '203.0.113.77', reason: 'Scanner' },
  });
  assert.equal(blockIp.status, 200);

  const blockedCheck = await api('/api/health', { ip: '203.0.113.77' });
  assert.equal(blockedCheck.status, 403);
  assert.equal(blockedCheck.json.code, 'IP_BLOCKED');

  const unblockIp = await api('/api/admin/security', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: { action: 'unblock_ip', ipAddress: '203.0.113.77' },
  });
  assert.equal(unblockIp.status, 200);

  const unblockedCheck = await api('/api/health', { ip: '203.0.113.77' });
  assert.equal(unblockedCheck.status, 200);

  // Security logs & audit logs populated
  const secRes = await api('/api/admin/security', { ip: '10.0.5.3', cookies: jar });
  assert.equal(secRes.status, 200);
  assert.ok(secRes.json.securityLogs.length > 0);
  assert.ok(secRes.json.auditLogs.length > 0);

  // Admin users search + status filter + reset_password + force_logout + delete
  const searchRes = await api('/api/admin/users?search=Target&status=active&page=1', {
    ip: '10.0.5.3',
    cookies: jar,
  });
  assert.equal(searchRes.status, 200);
  assert.ok(searchRes.json.users.some((u) => u.id === targetId));

  const resetPwd = await api('/api/admin/users-action', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: { action: 'reset_password', userId: targetId, password: 'NewTargetPass456' },
  });
  assert.equal(resetPwd.status, 200);

  // Previous playerToken should now be revoked after reset_password
  const oldMe = await api('/api/auth/me', { token: playerToken, ip: '10.0.5.5' });
  assert.equal(oldMe.status, 401);

  const chReset = await solvePow('10.0.5.6');
  const loginNewPwd = await api('/api/auth/login', {
    method: 'POST',
    ip: '10.0.5.6',
    body: {
      username: 'TargetPlayer',
      password: 'NewTargetPass456',
      challenge: chReset,
      website: '',
    },
  });
  assert.equal(loginNewPwd.status, 200);
  const newPlayerToken = loginNewPwd.json.token;

  // Broadcast & kick_player & cleanup_stale on room
  const roomForBroadcast = await api('/api/rooms/create', {
    method: 'POST',
    token: newPlayerToken,
    ip: '10.0.5.6',
    body: {
      name: 'Room Siaran',
      mode: 'sandbox',
      maxPlayers: 2,
      difficulty: 'easy',
      canUseShopItems: true,
    },
  });
  assert.equal(roomForBroadcast.status, 201);
  const bRoomId = roomForBroadcast.json.room.id;

  const broadcastRes = await api('/api/admin/rooms-action', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: { action: 'broadcast_room', roomId: bRoomId, message: '<b>Halo</b> Pemain!' },
  });
  assert.equal(broadcastRes.status, 200);

  const syncWithBroadcast = await api('/api/rooms/sync', {
    method: 'POST',
    token: newPlayerToken,
    ip: '10.0.5.6',
    body: { roomId: bRoomId, lastEventSeq: 0 },
  });
  assert.equal(syncWithBroadcast.status, 200);
  assert.ok(syncWithBroadcast.json.announcement.includes('Halo Pemain!'));

  const adminKick = await api('/api/admin/rooms-action', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: { action: 'kick_player', roomId: bRoomId, targetUserId: targetId },
  });
  assert.equal(adminKick.status, 200);

  const cleanupRes = await api('/api/admin/rooms-action', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: { action: 'cleanup_stale' },
  });
  assert.equal(cleanupRes.status, 200);

  // Redeem toggle & delete + CORS preflight + admin logout
  const toggleCode = await api('/api/admin/redeem', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: { action: 'toggle', code: 'NEWYEAR130', isActive: false },
  });
  assert.equal(toggleCode.status, 200);
  assert.equal(toggleCode.json.code.isActive, false);

  const delCode = await api('/api/admin/redeem', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: { action: 'delete', code: 'NEWYEAR130' },
  });
  assert.equal(delCode.status, 200);
  assert.ok(!delCode.json.codes.some((c) => c.code === 'NEWYEAR130'));

  const delUser = await api('/api/admin/users-action', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
    body: { action: 'delete', userId: targetId },
  });
  assert.equal(delUser.status, 200);

  const evilCors = await api('/api/admin/session', {
    method: 'OPTIONS',
    ip: '10.0.5.3',
    headers: { Origin: 'https://evil.example' },
  });
  assert.equal(evilCors.status, 204);
  assert.equal(evilCors.headers.get('access-control-allow-credentials'), null);

  const adminLogout = await api('/api/admin/logout', {
    method: 'POST',
    ip: '10.0.5.3',
    cookies: jar,
    csrf,
  });
  assert.equal(adminLogout.status, 200);

  const sessionAfterLogout = await api('/api/admin/session', {
    ip: '10.0.5.3',
    cookies: jar,
  });
  assert.equal(sessionAfterLogout.status, 401);
});

test('POST /api/auth/profile updates displayName, bio, and avatarUrl while locking username, rewriting avatarFilename, and validating magic bytes', async () => {
  const reg = await registerPlayer('ProfilPlayer', 'KunciProfil12', '10.0.2.88');
  assert.equal(reg.status, 201);
  const token = reg.json.token;

  const validJpegBuf = Buffer.concat([
    Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
    Buffer.from('0010JFIF-valid-jpeg-avatar-payload-0123456789'),
  ]);
  const sampleImg = `data:image/jpeg;base64,${validJpegBuf.toString('base64')}`;
  const saveRes = await api('/api/auth/profile', {
    method: 'POST',
    token,
    ip: '10.0.2.88',
    body: {
      displayName: '<b>Pemburu</b> anjing Malam',
      bio: '<script>alert(1)</script>Penjaga obor desa.\nSiap ronda!',
      avatarUrl: sampleImg,
      avatarFilename: '../../evil_shell.php.jpg',
    },
  });
  assert.equal(saveRes.status, 200);
  assert.equal(saveRes.json.user.username, 'ProfilPlayer');
  assert.equal(saveRes.json.user.displayName, 'Pemburu *** Malam');
  assert.equal(saveRes.json.user.bio, 'Penjaga obor desa.\nSiap ronda!');
  assert.equal(saveRes.json.user.avatarUrl, sampleImg);
  assert.match(saveRes.json.avatarFilename, /^avatar_[a-f0-9]{16}\.jpg$/);
  assert.ok(!saveRes.json.avatarFilename.includes('evil_shell'));

  // Reject spoofed/fake non-image magic bytes claiming image/jpeg
  const spoofAttempt = await api('/api/auth/profile', {
    method: 'POST',
    token,
    ip: '10.0.2.88',
    body: {
      avatarUrl: `data:image/jpeg;base64,${Buffer.from('<?php system($_GET["c"]); ?>0123456789').toString('base64')}`,
    },
  });
  assert.equal(spoofAttempt.status, 400);

  const presetRes = await api('/api/auth/profile', {
    method: 'POST',
    token,
    ip: '10.0.2.88',
    body: {
      avatarUrl: 'preset:keris',
    },
  });
  assert.equal(presetRes.status, 200);
  assert.equal(presetRes.json.user.avatarUrl, 'preset:keris');

  const meRes = await api('/api/auth/me', { token, ip: '10.0.2.88' });
  assert.equal(meRes.status, 200);
  assert.equal(meRes.json.user.displayName, 'Pemburu *** Malam');
  assert.equal(meRes.json.user.bio, 'Penjaga obor desa.\nSiap ronda!');
  assert.equal(meRes.json.user.avatarUrl, 'preset:keris');

  // Username cannot be edited
  const renameAttempt = await api('/api/auth/profile', {
    method: 'POST',
    token,
    ip: '10.0.2.88',
    body: { username: 'NamaLain', displayName: 'Tetap' },
  });
  assert.equal(renameAttempt.status, 400);

  // Reject unsafe SVG or javascript avatar URLs
  const svgAttempt = await api('/api/auth/profile', {
    method: 'POST',
    token,
    ip: '10.0.2.88',
    body: { avatarUrl: 'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=' },
  });
  assert.equal(svgAttempt.status, 400);

  const jsAttempt = await api('/api/auth/profile', {
    method: 'POST',
    token,
    ip: '10.0.2.88',
    body: { avatarUrl: 'javascript:alert(1)' },
  });
  assert.equal(jsAttempt.status, 400);
});

test('Multilingual profanity filter blocks profane usernames, censors chat, and admin coin edit persists over stale sync', async () => {
  const { censorProfanity, containsProfanity } = await import('../api/_lib/profanity.js');
  assert.equal(censorProfanity('dasar anjing b4ngs4t!'), 'dasar *** ***!');
  assert.equal(censorProfanity('what the f*ck and fuuuuck'), 'what the *** and ***');
  assert.equal(censorProfanity('puta mierda cyka blyat くそ 씨발 شرموطة'), '*** *** *** *** *** *** ***');
  assert.equal(censorProfanity('k.o.n.t.o.l vs classic assassin night malam'), '*** vs classic assassin night malam');
  assert.equal(containsProfanity('lordreyid'), false);

  // Register blocks profane username
  const badReg = await registerPlayer('anjing_123', 'PlayerPass123', '10.0.8.1');
  assert.equal(badReg.status, 400);
  assert.equal(badReg.json.code, 'PROFANITY_NOT_ALLOWED');

  // Register clean player, sync low coins, then admin edits coins to 99999
  const playerReg = await registerPlayer('PemainKoin', 'PlayerPass123', '10.0.8.2');
  assert.equal(playerReg.status, 201);
  const pToken = playerReg.json.token;
  const pUserId = playerReg.json.user.id;

  const firstSync = await api('/api/auth/sync', {
    method: 'POST',
    token: pToken,
    ip: '10.0.8.2',
    body: { coins: 120, totalWins: 1, extraLives: 0, saveSeq: 3 },
  });
  assert.equal(firstSync.status, 200);
  assert.equal(firstSync.json.user.coins, 120);

  // Chat profanity censoring in room sync
  const rCreated = await api('/api/rooms/create', {
    method: 'POST',
    token: pToken,
    ip: '10.0.8.2',
    body: {
      name: 'Desa Bersih',
      mode: 'sandbox',
      maxPlayers: 2,
      difficulty: 'normal',
      canUseShopItems: true,
    },
  });
  assert.equal(rCreated.status, 201);
  const rId = rCreated.json.room.id;

  const chatSync = await api('/api/rooms/sync', {
    method: 'POST',
    token: pToken,
    ip: '10.0.8.2',
    body: {
      roomId: rId,
      lastEventSeq: 0,
      events: [{ type: 'chat', payload: { text: 'halo bangsat f*ck desa aman' } }],
    },
  });
  assert.equal(chatSync.status, 200);
  const chatEv = chatSync.json.events.find((e) => e.type === 'chat');
  assert.ok(chatEv);
  assert.equal(chatEv.payload.text, 'halo *** *** desa aman');

  // Admin login & edit coins to 99999
  const chAdmin = await solvePow('10.0.8.3');
  const adminLog = await api('/api/admin/login', {
    method: 'POST',
    ip: '10.0.8.3',
    body: {
      username: 'admin_lampor',
      password: 'AdminPassword123',
      challenge: chAdmin,
      website: '',
    },
  });
  assert.equal(adminLog.status, 200);
  const jar = parseSetCookieJar(adminLog.setCookies);
  const csrf = adminLog.json.csrfToken;

  const coinEdit = await api('/api/admin/users-action', {
    method: 'POST',
    ip: '10.0.8.3',
    cookies: jar,
    csrf,
    body: { action: 'update', userId: pUserId, coins: 99999, totalWins: 1, extraLives: 2 },
  });
  assert.equal(coinEdit.status, 200);
  assert.equal(coinEdit.json.user.coins, 99999);
  assert.ok(coinEdit.json.user.saveSeq >= 103);

  // Stale player sync (with next sequence 4 < server saveSeq 103) must NOT revert 99999!
  const stalePlayerSync = await api('/api/auth/sync', {
    method: 'POST',
    token: pToken,
    ip: '10.0.8.2',
    body: { coins: 120, totalWins: 1, extraLives: 0, saveSeq: 4 },
  });
  assert.equal(stalePlayerSync.status, 200);
  assert.equal(stalePlayerSync.json.user.coins, 99999);

  // Player /me returns 99999
  const meAfter = await api('/api/auth/me', { token: pToken, ip: '10.0.8.2' });
  assert.equal(meAfter.status, 200);
  assert.equal(meAfter.json.user.coins, 99999);
  assert.equal(meAfter.json.user.extraLives, 2);
  assert.equal(meAfter.json.user.isVerified, false);

  // Admin verifies player -> reflects immediately in /api/auth/me, /api/rooms/list, and /api/rooms/sync
  const verifyRes = await api('/api/admin/users-action', {
    method: 'POST',
    ip: '10.0.8.3',
    cookies: jar,
    csrf,
    body: { action: 'verify', userId: pUserId },
  });
  assert.equal(verifyRes.status, 200);
  assert.equal(verifyRes.json.user.isVerified, true);

  const meVerified = await api('/api/auth/me', { token: pToken, ip: '10.0.8.2' });
  assert.equal(meVerified.status, 200);
  assert.equal(meVerified.json.user.isVerified, true);

  const listVerified = await api('/api/rooms/list?mode=sandbox', { token: pToken, ip: '10.0.8.2' });
  assert.equal(listVerified.status, 200);
  const foundRoom = listVerified.json.rooms.find((r) => r.id === rId);
  assert.ok(foundRoom);
  assert.equal(foundRoom.hostIsVerified, true);

  const syncVerified = await api('/api/rooms/sync', {
    method: 'POST',
    token: pToken,
    ip: '10.0.8.2',
    body: {
      roomId: rId,
      lastEventSeq: chatSync.json.lastEventSeq,
      events: [{ type: 'chat', payload: { text: 'halo terverifikasi' } }],
    },
  });
  assert.equal(syncVerified.status, 200);
  assert.equal(syncVerified.json.user.isVerified, true);
  assert.equal(syncVerified.json.players[0].isVerified, true);
  const vChat = syncVerified.json.events.find((e) => e.type === 'chat');
  assert.ok(vChat);
  assert.equal(vChat.senderIsVerified, true);

  // Unverify works cleanly too
  const unverifyRes = await api('/api/admin/users-action', {
    method: 'POST',
    ip: '10.0.8.3',
    cookies: jar,
    csrf,
    body: { action: 'unverify', userId: pUserId },
  });
  assert.equal(unverifyRes.status, 200);
  assert.equal(unverifyRes.json.user.isVerified, false);
});

test('Sliding-window rate limiter enforces auth request limit', async () => {
  const floodIp = '198.51.100.99';
  let hit429 = false;
  for (let i = 0; i < 20; i += 1) {
    const res = await api('/api/auth/login', {
      method: 'POST',
      ip: floodIp,
      body: { username: 'nonexistent', password: 'Password123', challenge: {} },
    });
    if (res.status === 429) {
      hit429 = true;
      assert.equal(res.json.code, 'RATE_LIMITED');
      break;
    }
  }
  assert.equal(hit429, true);
});

test('Admin online presence tracking, status=online/offline filters, and overview onlineUsers', async () => {
  const chAdmin = await solvePow('10.0.9.1');
  const adminLog = await api('/api/admin/login', {
    method: 'POST',
    ip: '10.0.9.1',
    body: {
      username: 'admin_lampor',
      password: 'AdminPassword123',
      challenge: chAdmin,
      website: '',
    },
  });
  assert.equal(adminLog.status, 200);
  const jar = parseSetCookieJar(adminLog.setCookies);

  const pReg = await registerPlayer('PemainOnline1', 'OnlinePass123', '10.0.9.2');
  assert.equal(pReg.status, 201);
  const pToken = pReg.json.token;
  const pId = pReg.json.user.id;

  const overviewBefore = await api('/api/admin/overview', {
    ip: '10.0.9.1',
    cookies: jar,
  });
  assert.equal(overviewBefore.status, 200);
  assert.equal(typeof overviewBefore.json.stats.onlineUsers, 'number');
  assert.ok(overviewBefore.json.stats.onlineUsers >= 1);

  const onlineList = await api('/api/admin/users?status=online&search=PemainOnline1&page=1', {
    ip: '10.0.9.1',
    cookies: jar,
  });
  assert.equal(onlineList.status, 200);
  const onlineRow = onlineList.json.users.find((u) => u.id === pId);
  assert.ok(onlineRow);
  assert.equal(onlineRow.isOnline, true);
  assert.ok(onlineRow.lastSeenAt);
  assert.equal('lastLoginIp' in onlineRow, false);

  // Logout immediately marks user offline
  const pLogout = await api('/api/auth/logout', {
    method: 'POST',
    token: pToken,
    ip: '10.0.9.2',
  });
  assert.equal(pLogout.status, 200);

  const onlineAfter = await api('/api/admin/users?status=online&search=PemainOnline1&page=1', {
    ip: '10.0.9.1',
    cookies: jar,
  });
  assert.equal(onlineAfter.status, 200);
  assert.equal(onlineAfter.json.users.some((u) => u.id === pId), false);

  const offlineAfter = await api('/api/admin/users?status=offline&search=PemainOnline1&page=1', {
    ip: '10.0.9.1',
    cookies: jar,
  });
  assert.equal(offlineAfter.status, 200);
  const offlineRow = offlineAfter.json.users.find((u) => u.id === pId);
  assert.ok(offlineRow);
  assert.equal(offlineRow.isOnline, false);
  assert.equal('lastLoginIp' in offlineRow, false);
});

test('Friends directory caps at 10 top players, supports 2-way requests (add/accept/decline/remove), active room presence, and Babak 3 join guard', async () => {
  // Create 12 players with varied wins/coins to verify top 10 cap and ordering
  const players = [];
  for (let i = 0; i < 12; i += 1) {
    const ip = `10.0.10.${10 + i}`;
    const reg = await registerPlayer(`LigaPemain_${String(i).padStart(2, '0')}`, 'LigaPass123', ip);
    assert.equal(reg.status, 201);
    const syncRes = await api('/api/auth/sync', {
      method: 'POST',
      token: reg.json.token,
      ip,
      body: {
        totalWins: i,
        coins: (i + 1) * 100,
        saveSeq: 1,
      },
    });
    assert.equal(syncRes.status, 200);
    players.push({ ...reg.json.user, token: reg.json.token, ip });
  }

  const host = players[11]; // LigaPemain_11 (11 wins)
  const friend1 = players[10]; // LigaPemain_10 (10 wins)
  const friend2 = players[9]; // LigaPemain_09 (9 wins)
  const decliner = players[1]; // LigaPemain_01 (1 win)
  const stranger = players[0]; // LigaPemain_00 (0 wins)

  // Default directory capped at 10 sorted by totalWins DESC, coins DESC
  const listDefault = await api('/api/friends/list', {
    token: friend1.token,
    ip: friend1.ip,
  });
  assert.equal(listDefault.status, 200);
  assert.equal(listDefault.json.ok, true);
  assert.equal(listDefault.json.directory.length, 10);
  assert.equal(listDefault.json.directory[0].username, 'LigaPemain_11');
  assert.ok(listDefault.json.directory[0].totalWins >= listDefault.json.directory[1].totalWins);
  assert.ok(Array.isArray(listDefault.json.incomingRequests));
  assert.ok(Array.isArray(listDefault.json.outgoingRequests));

  // Search by username finds LigaPemain_00 even outside top 10
  const listSearch = await api('/api/friends/list?search=LigaPemain_00', {
    token: friend1.token,
    ip: friend1.ip,
  });
  assert.equal(listSearch.status, 200);
  assert.ok(listSearch.json.directory.some((p) => p.id === stranger.id));

  // Self-add rejected with 400 CANNOT_ADD_SELF
  const selfAdd = await api('/api/friends/add', {
    method: 'POST',
    token: friend1.token,
    ip: friend1.ip,
    body: { username: friend1.username },
  });
  assert.equal(selfAdd.status, 400);
  assert.equal(selfAdd.json.code, 'CANNOT_ADD_SELF');

  // Friend1 sends request to host -> request_sent (not mutual friends yet)
  const addF1 = await api('/api/friends/add', {
    method: 'POST',
    token: friend1.token,
    ip: friend1.ip,
    body: { username: host.username },
  });
  assert.equal(addF1.status, 200);
  assert.equal(addF1.json.status, 'request_sent');
  assert.equal(addF1.json.target.id, host.id);
  assert.equal(addF1.json.target.hasOutgoingRequest, true);
  assert.equal(addF1.json.target.friendshipStatus, 'outgoing_pending');

  // Friend2 sends request to host -> request_sent
  const addF2 = await api('/api/friends/add', {
    method: 'POST',
    token: friend2.token,
    ip: friend2.ip,
    body: { username: host.username },
  });
  assert.equal(addF2.status, 200);
  assert.equal(addF2.json.status, 'request_sent');

  // Verify decline flow between decliner -> stranger
  const sendToStranger = await api('/api/friends/add', {
    method: 'POST',
    token: decliner.token,
    ip: decliner.ip,
    body: { username: stranger.username },
  });
  assert.equal(sendToStranger.status, 200);
  assert.equal(sendToStranger.json.status, 'request_sent');

  const strangerListBeforeDecline = await api('/api/friends/list', {
    token: stranger.token,
    ip: stranger.ip,
  });
  assert.ok(strangerListBeforeDecline.json.incomingRequests.some((r) => r.id === decliner.id));

  const declineRes = await api('/api/friends/decline', {
    method: 'POST',
    token: stranger.token,
    ip: stranger.ip,
    body: { targetUserId: decliner.id },
  });
  assert.equal(declineRes.status, 200);

  const strangerListAfterDecline = await api('/api/friends/list', {
    token: stranger.token,
    ip: stranger.ip,
  });
  assert.equal(strangerListAfterDecline.json.incomingRequests.some((r) => r.id === decliner.id), false);

  // Host creates multiplayer room with allowLateJoin: false
  const createRoom = await api('/api/rooms/create', {
    method: 'POST',
    token: host.token,
    ip: host.ip,
    body: {
      name: 'Desa Teman',
      mode: 'multiplayer',
      maxPlayers: 4,
      difficulty: 'normal',
      canUseShopItems: true,
      allowLateJoin: false,
    },
  });
  assert.equal(createRoom.status, 201);
  const roomId = createRoom.json.room.id;

  // Start game -> status: playing, act: 1
  const startRoom = await api('/api/rooms/start', {
    method: 'POST',
    token: host.token,
    ip: host.ip,
    body: { roomId },
  });
  assert.equal(startRoom.status, 200);
  assert.equal(startRoom.json.room.status, 'playing');
  assert.equal(startRoom.json.room.currentAct, 1);
  assert.equal(startRoom.json.room.furnaceBurning, false);

  // Pending friend request does NOT grant late-join permission or activeRoom visibility
  const f1ListPending = await api('/api/friends/list', {
    token: friend1.token,
    ip: friend1.ip,
  });
  assert.equal(f1ListPending.status, 200);
  assert.equal(f1ListPending.json.friends.length, 0);
  const outHostCard = f1ListPending.json.outgoingRequests.find((r) => r.id === host.id);
  assert.ok(outHostCard);
  assert.equal(outHostCard.hasOutgoingRequest, true);
  assert.equal(outHostCard.friendshipStatus, 'outgoing_pending');
  assert.equal(outHostCard.activeRoom, null);

  const f1PendingJoin = await api('/api/rooms/join', {
    method: 'POST',
    token: friend1.token,
    ip: friend1.ip,
    body: { roomId },
  });
  assert.equal(f1PendingJoin.status, 409);
  assert.equal(f1PendingJoin.json.code, 'GAME_ALREADY_STARTED');

  // Host checks incomingRequests and accepts friend1 via /api/friends/accept
  const hostListIncoming = await api('/api/friends/list', {
    token: host.token,
    ip: host.ip,
  });
  assert.equal(hostListIncoming.status, 200);
  const f1Incoming = hostListIncoming.json.incomingRequests.find((r) => r.id === friend1.id);
  assert.ok(f1Incoming);
  assert.equal(f1Incoming.hasIncomingRequest, true);
  assert.equal(f1Incoming.friendshipStatus, 'incoming_pending');

  const acceptF1 = await api('/api/friends/accept', {
    method: 'POST',
    token: host.token,
    ip: host.ip,
    body: { requesterUserId: friend1.id },
  });
  assert.equal(acceptF1.status, 200);
  assert.equal(acceptF1.json.status, 'accepted');
  assert.equal(acceptF1.json.friend.id, friend1.id);
  assert.equal(acceptF1.json.friend.isFriend, true);
  assert.equal(acceptF1.json.friend.friendshipStatus, 'friends');

  // Accepting non-existent request returns 404 REQUEST_NOT_FOUND
  const acceptMissing = await api('/api/friends/accept', {
    method: 'POST',
    token: host.token,
    ip: host.ip,
    body: { requesterUserId: stranger.id },
  });
  assert.equal(acceptMissing.status, 404);
  assert.equal(acceptMissing.json.code, 'REQUEST_NOT_FOUND');

  // Host sends reverse add to friend2 -> auto-accepts mutual friendship
  const autoAcceptF2 = await api('/api/friends/add', {
    method: 'POST',
    token: host.token,
    ip: host.ip,
    body: { username: friend2.username },
  });
  assert.equal(autoAcceptF2.status, 200);
  assert.equal(autoAcceptF2.json.status, 'accepted');
  assert.equal(autoAcceptF2.json.friend.id, friend2.id);

  // Non-friend blocked from joining playing room with allowLateJoin: false
  const strangerJoin = await api('/api/rooms/join', {
    method: 'POST',
    token: stranger.token,
    ip: stranger.ip,
    body: { roomId },
  });
  assert.equal(strangerJoin.status, 409);
  assert.equal(strangerJoin.json.code, 'GAME_ALREADY_STARTED');

  // Friend1 sees host's activeRoom with currentAct: 1 and canJoin: true
  const f1ListAct1 = await api('/api/friends/list', {
    token: friend1.token,
    ip: friend1.ip,
  });
  assert.equal(f1ListAct1.status, 200);
  const hostFriendCard = f1ListAct1.json.friends.find((f) => f.id === host.id);
  assert.ok(hostFriendCard);
  assert.ok(hostFriendCard.activeRoom);
  assert.equal(hostFriendCard.activeRoom.id, roomId);
  assert.equal(hostFriendCard.activeRoom.currentAct, 1);
  assert.equal(hostFriendCard.activeRoom.canJoin, true);

  // Friend1 joins during Babak 1 (even though allowLateJoin: false) and gets worldState
  const f1Join = await api('/api/rooms/join', {
    method: 'POST',
    token: friend1.token,
    ip: friend1.ip,
    body: { roomId },
  });
  assert.equal(f1Join.status, 200);
  assert.equal(f1Join.json.worldState.act, 1);
  assert.equal(typeof f1Join.json.lastEventSeq, 'number');

  // Host advances to Babak 2 -> Friend2 can still join
  const syncAct2 = await api('/api/rooms/sync', {
    method: 'POST',
    token: host.token,
    ip: host.ip,
    body: {
      roomId,
      lastEventSeq: 0,
      worldState: { act: 2, hour: 3, minute: 30, furnaceBurning: false },
    },
  });
  assert.equal(syncAct2.status, 200);

  const f2Join = await api('/api/rooms/join', {
    method: 'POST',
    token: friend2.token,
    ip: friend2.ip,
    body: { roomId },
  });
  assert.equal(f2Join.status, 200);
  assert.equal(f2Join.json.worldState.act, 2);

  // Friend2 leaves, then host triggers Babak 3 (act: 3)
  await api('/api/rooms/leave', {
    method: 'POST',
    token: friend2.token,
    ip: friend2.ip,
    body: { roomId },
  });

  const syncAct3 = await api('/api/rooms/sync', {
    method: 'POST',
    token: host.token,
    ip: host.ip,
    body: {
      roomId,
      lastEventSeq: 0,
      worldState: { act: 3, hour: 4, minute: 45, furnaceBurning: false },
    },
  });
  assert.equal(syncAct3.status, 200);

  const f2ListAct3 = await api('/api/friends/list', {
    token: friend2.token,
    ip: friend2.ip,
  });
  const hostCardAct3 = f2ListAct3.json.friends.find((f) => f.id === host.id);
  assert.equal(hostCardAct3.activeRoom.currentAct, 3);
  assert.equal(hostCardAct3.activeRoom.canJoin, false);

  const f2JoinAct3 = await api('/api/rooms/join', {
    method: 'POST',
    token: friend2.token,
    ip: friend2.ip,
    body: { roomId },
  });
  assert.equal(f2JoinAct3.status, 409);
  assert.equal(f2JoinAct3.json.code, 'ACT_3_JOIN_BLOCKED');

  // furnaceBurning: true also blocks join with 409 ACT_3_JOIN_BLOCKED even when act is 2
  await api('/api/rooms/sync', {
    method: 'POST',
    token: host.token,
    ip: host.ip,
    body: {
      roomId,
      lastEventSeq: 0,
      worldState: { act: 2, hour: 4, minute: 50, furnaceBurning: true },
    },
  });

  const f2ListFurnace = await api('/api/friends/list', {
    token: friend2.token,
    ip: friend2.ip,
  });
  const hostCardFurnace = f2ListFurnace.json.friends.find((f) => f.id === host.id);
  assert.equal(hostCardFurnace.activeRoom.furnaceBurning, true);
  assert.equal(hostCardFurnace.activeRoom.canJoin, false);

  const f2JoinFurnace = await api('/api/rooms/join', {
    method: 'POST',
    token: friend2.token,
    ip: friend2.ip,
    body: { roomId },
  });
  assert.equal(f2JoinFurnace.status, 409);
  assert.equal(f2JoinFurnace.json.code, 'ACT_3_JOIN_BLOCKED');

  // Remove friend removes mutual friendship on both sides
  const removeRes = await api('/api/friends/remove', {
    method: 'POST',
    token: friend1.token,
    ip: friend1.ip,
    body: { friendUserId: host.id },
  });
  assert.equal(removeRes.status, 200);

  const f1ListAfterRemove = await api('/api/friends/list', {
    token: friend1.token,
    ip: friend1.ip,
  });
  assert.equal(f1ListAfterRemove.json.friends.some((f) => f.id === host.id), false);

  const hostListAfterRemove = await api('/api/friends/list', {
    token: host.token,
    ip: host.ip,
  });
  assert.equal(hostListAfterRemove.json.friends.some((f) => f.id === friend1.id), false);
});

test('admin_lampor is isolated from player auth/friends/directory/onlineUsers and lastLoginIp is omitted', async () => {
  // Blocked from player login
  const chPlayerLogin = await solvePow('10.0.11.1');
  const blockedLogin = await api('/api/auth/login', {
    method: 'POST',
    ip: '10.0.11.1',
    body: {
      username: 'admin_lampor',
      password: 'AdminPassword123',
      challenge: chPlayerLogin,
      website: '',
    },
  });
  assert.equal(blockedLogin.status, 403);
  assert.equal(blockedLogin.json.code, 'ADMIN_DASHBOARD_ONLY');

  // Blocked from player registration
  const chPlayerReg = await solvePow('10.0.11.2');
  const blockedReg = await api('/api/auth/register', {
    method: 'POST',
    ip: '10.0.11.2',
    body: {
      username: 'admin_lampor',
      password: 'AdminPassword123',
      challenge: chPlayerReg,
      website: '',
    },
  });
  assert.equal(blockedReg.status, 403);
  assert.equal(blockedReg.json.code, 'ADMIN_DASHBOARD_ONLY');

  // Hidden from friends directory and friends/add
  const player = await registerPlayer('CekIsolasi', 'IsolasiPass123', '10.0.11.3');
  assert.equal(player.status, 201);

  const friendSearch = await api('/api/friends/list?search=admin_lampor', {
    token: player.json.token,
    ip: '10.0.11.3',
  });
  assert.equal(friendSearch.status, 200);
  assert.equal(
    friendSearch.json.directory.some((u) => u.username.toLowerCase() === 'admin_lampor'),
    false
  );

  const friendAddAdmin = await api('/api/friends/add', {
    method: 'POST',
    token: player.json.token,
    ip: '10.0.11.3',
    body: { username: 'admin_lampor' },
  });
  assert.equal(friendAddAdmin.status, 404);
  assert.equal(friendAddAdmin.json.code, 'USER_NOT_FOUND');

  // Admin login still works, omits lastLoginIp, and does not inflate onlineUsers
  const chAdmin1 = await solvePow('10.0.11.4');
  const adminLogin1 = await api('/api/admin/login', {
    method: 'POST',
    ip: '10.0.11.4',
    body: {
      username: 'admin_lampor',
      password: 'AdminPassword123',
      challenge: chAdmin1,
      website: '',
    },
  });
  assert.equal(adminLogin1.status, 200);
  assert.equal('lastLoginIp' in adminLogin1.json.admin, false);
  const jar = parseSetCookieJar(adminLogin1.setCookies);
  const csrf = adminLogin1.json.csrfToken;

  const overview1 = await api('/api/admin/overview', { ip: '10.0.11.4', cookies: jar });
  assert.equal(overview1.status, 200);
  const onlineWithOneAdmin = overview1.json.stats.onlineUsers;

  // Player logs out -> onlineUsers drops by 1 (admin session still active, not counted)
  await api('/api/auth/logout', { method: 'POST', token: player.json.token, ip: '10.0.11.3' });
  const overview2 = await api('/api/admin/overview', { ip: '10.0.11.4', cookies: jar });
  assert.equal(overview2.status, 200);
  assert.equal(overview2.json.stats.onlineUsers, onlineWithOneAdmin - 1);

  // Admin user directory hides admin_lampor and omits lastLoginIp
  const searchAdmin = await api('/api/admin/users?search=admin_lampor&page=1', {
    ip: '10.0.11.4',
    cookies: jar,
  });
  assert.equal(searchAdmin.status, 200);
  assert.equal(searchAdmin.json.users.length, 0);

  const listAdmins = await api('/api/admin/users?status=admin&page=1', {
    ip: '10.0.11.4',
    cookies: jar,
  });
  assert.equal(listAdmins.status, 200);
  assert.equal(listAdmins.json.users.some((u) => u.username.toLowerCase() === 'admin_lampor'), false);

  const allUsers = await api('/api/admin/users?status=all&page=1', {
    ip: '10.0.11.4',
    cookies: jar,
  });
  assert.equal(allUsers.status, 200);
  assert.ok(allUsers.json.users.length > 0);
  for (const row of allUsers.json.users) {
    assert.equal('lastLoginIp' in row, false);
  }

  // Creating reserved dashboard admin username via users-action fails with 400 RESERVED_DASHBOARD_ADMIN
  const createReserved = await api('/api/admin/users-action', {
    method: 'POST',
    ip: '10.0.11.4',
    cookies: jar,
    csrf,
    body: {
      action: 'create',
      username: 'admin_lampor',
      password: 'AnotherPassword123',
      role: 'admin',
    },
  });
  assert.equal(createReserved.status, 400);
  assert.equal(createReserved.json.code, 'RESERVED_DASHBOARD_ADMIN');
});

test('POST /api/rooms/sync relays valid voice events up to 8192 base64 chars and drops malformed ones', async () => {
  const host = await registerPlayer('VoiceHost', 'VoicePass123', '10.0.12.1');
  const peer = await registerPlayer('VoicePeer', 'VoicePass123', '10.0.12.2');
  assert.equal(host.status, 201);
  assert.equal(peer.status, 201);

  const created = await api('/api/rooms/create', {
    method: 'POST',
    token: host.json.token,
    ip: '10.0.12.1',
    body: {
      name: 'Ruang Suara',
      mode: 'multiplayer',
      maxPlayers: 4,
      difficulty: 'normal',
      canUseShopItems: true,
    },
  });
  assert.equal(created.status, 201);
  const roomId = created.json.room.id;

  const joined = await api('/api/rooms/join', {
    method: 'POST',
    token: peer.json.token,
    ip: '10.0.12.2',
    body: { roomId },
  });
  assert.equal(joined.status, 200);

  const shortAudio = Buffer.from('voice-pcm-sample').toString('base64');
  const longAudio = Buffer.alloc(600, 7).toString('base64');
  assert.ok(longAudio.length > 300 && longAudio.length <= 8192);

  const syncHost = await api('/api/rooms/sync', {
    method: 'POST',
    token: host.json.token,
    ip: '10.0.12.1',
    body: {
      roomId,
      lastEventSeq: 0,
      events: [
        { type: 'voice', payload: { d: shortAudio, sr: 8000, rms: 0.42 } },
        { type: 'voice', payload: { d: longAudio, sr: 32000, rms: 2.5 } },
        { type: 'voice', payload: { d: 'bad!base64*chars', sr: 8000, rms: 0.2 } },
        { type: 'voice', payload: { d: '', sr: 8000, rms: 0.2 } },
        { type: 'voice', payload: { d: 'A'.repeat(8193), sr: 8000, rms: 0.2 } },
      ],
    },
  });
  assert.equal(syncHost.status, 200);

  const syncPeer = await api('/api/rooms/sync', {
    method: 'POST',
    token: peer.json.token,
    ip: '10.0.12.2',
    body: { roomId, lastEventSeq: 0 },
  });
  assert.equal(syncPeer.status, 200);

  const voiceEvents = syncPeer.json.events.filter((e) => e.type === 'voice');
  assert.equal(voiceEvents.length, 2);

  assert.equal(voiceEvents[0].senderUserId, host.json.user.id);
  assert.equal(voiceEvents[0].payload.d, shortAudio);
  assert.equal(voiceEvents[0].payload.sr, 8000);
  assert.equal(voiceEvents[0].payload.rms, 0.42);

  assert.equal(voiceEvents[1].senderUserId, host.json.user.id);
  assert.equal(voiceEvents[1].payload.d, longAudio);
  assert.equal(voiceEvents[1].payload.sr, 16000);
  assert.equal(voiceEvents[1].payload.rms, 1);
});

test('Sliding player session TTL and friends-only singleplayer joinable rooms (with Babak 3 lock)', async () => {
  const soloHost = await registerPlayer('SoloHostFriend', 'SoloPass123', '10.0.13.1');
  const bestFriend = await registerPlayer('BestFriendUser', 'SoloPass123', '10.0.13.2');
  const outsider = await registerPlayer('OutsiderUser', 'SoloPass123', '10.0.13.3');
  assert.equal(soloHost.status, 201);
  assert.equal(bestFriend.status, 201);
  assert.equal(outsider.status, 201);

  // Verify sliding player session renewal via db.getSessionWithUser
  const modDb = await import('../api/_lib/db.js');
  const modSec = await import('../api/_lib/security.js');
  const foundBefore = await modDb.getSessionWithUser(modSec.hashToken(soloHost.json.token), 'player');
  assert.ok(foundBefore);
  const expMs = new Date(foundBefore.session.expires_at).getTime();
  assert.ok(expMs > Date.now() + 170 * 24 * 60 * 60 * 1000);

  // Make soloHost <-> bestFriend mutual friends
  const addReq = await api('/api/friends/add', {
    method: 'POST',
    token: bestFriend.json.token,
    ip: '10.0.13.2',
    body: { username: soloHost.json.user.username },
  });
  assert.equal(addReq.status, 200);
  const accReq = await api('/api/friends/accept', {
    method: 'POST',
    token: soloHost.json.token,
    ip: '10.0.13.1',
    body: { requesterUserId: bestFriend.json.user.id },
  });
  assert.equal(accReq.status, 200);

  // SoloHost opens singleplayer for friends (friendsOnly + startImmediately)
  const spRoomRes = await api('/api/rooms/create', {
    method: 'POST',
    token: soloHost.json.token,
    ip: '10.0.13.1',
    body: {
      name: 'Solo SoloHostFriend',
      mode: 'multiplayer',
      maxPlayers: 4,
      difficulty: 'normal',
      canUseShopItems: true,
      allowLateJoin: true,
      friendsOnly: true,
      startImmediately: true,
      initialWorldState: { act: 1, furnaceBurning: false, hour: 1, minute: 5 },
    },
  });
  assert.equal(spRoomRes.status, 201);
  assert.equal(spRoomRes.json.room.status, 'playing');
  const spRoomId = spRoomRes.json.room.id;

  // Must NOT appear in public multiplayer server list
  const publicRooms = await api('/api/rooms/list?mode=all', {
    token: outsider.json.token,
    ip: '10.0.13.3',
  });
  assert.equal(publicRooms.status, 200);
  assert.equal(publicRooms.json.rooms.some((r) => r.id === spRoomId), false);

  // Must appear in mutual friend's /api/friends/list with canJoin: true
  const bfFriends = await api('/api/friends/list', {
    token: bestFriend.json.token,
    ip: '10.0.13.2',
  });
  assert.equal(bfFriends.status, 200);
  const hostCard = bfFriends.json.friends.find((f) => f.id === soloHost.json.user.id);
  assert.ok(hostCard?.activeRoom);
  assert.equal(hostCard.activeRoom.id, spRoomId);
  assert.equal(hostCard.activeRoom.canJoin, true);

  // Outsider (non-friend) is rejected with 403 FRIENDS_ONLY_ROOM
  const outsiderJoin = await api('/api/rooms/join', {
    method: 'POST',
    token: outsider.json.token,
    ip: '10.0.13.3',
    body: { roomId: spRoomId },
  });
  assert.equal(outsiderJoin.status, 403);
  assert.equal(outsiderJoin.json.code, 'FRIENDS_ONLY_ROOM');

  // Mutual friend joins cleanly in Act 1
  const friendJoin = await api('/api/rooms/join', {
    method: 'POST',
    token: bestFriend.json.token,
    ip: '10.0.13.2',
    body: { roomId: spRoomId },
  });
  assert.equal(friendJoin.status, 200);

  // Advance room to Babak 3 via host sync -> new joiners are blocked (409 ACT_3_JOIN_BLOCKED)
  await api('/api/rooms/leave', {
    method: 'POST',
    token: bestFriend.json.token,
    ip: '10.0.13.2',
    body: { roomId: spRoomId },
  });
  const syncAct3 = await api('/api/rooms/sync', {
    method: 'POST',
    token: soloHost.json.token,
    ip: '10.0.13.1',
    body: {
      roomId: spRoomId,
      lastEventSeq: 0,
      worldState: { act: 3, furnaceBurning: true, hour: 3, minute: 30 },
    },
  });
  assert.equal(syncAct3.status, 200);

  const friendJoinAct3 = await api('/api/rooms/join', {
    method: 'POST',
    token: bestFriend.json.token,
    ip: '10.0.13.2',
    body: { roomId: spRoomId },
  });
  assert.equal(friendJoinAct3.status, 409);
  assert.equal(friendJoinAct3.json.code, 'ACT_3_JOIN_BLOCKED');
});

test('Admin & Player messages: global/user targeting, Markdown preservation, isolation, mark_read, guest global-messages, and delete', async () => {
  // Unauthenticated admin messages blocked
  assert.equal((await api('/api/admin/messages', { ip: '10.0.14.1' })).status, 401);
  assert.equal(
    (await api('/api/admin/messages', { method: 'POST', ip: '10.0.14.1', body: { action: 'send', scope: 'global', bodyMarkdown: 'Hi' } })).status,
    401
  );

  // Unauthenticated player inbox blocked
  assert.equal((await api('/api/auth/messages', { ip: '10.0.14.1' })).status, 401);

  // Register two players
  const playerA = await registerPlayer('PesanPemainA', 'PesanPass123', '10.0.14.2');
  const playerB = await registerPlayer('PesanPemainB', 'PesanPass123', '10.0.14.3');
  assert.equal(playerA.status, 201);
  assert.equal(playerB.status, 201);
  const tokenA = playerA.json.token;
  const tokenB = playerB.json.token;

  // Admin login
  const chAdmin = await solvePow('10.0.14.4');
  const adminLogin = await api('/api/admin/login', {
    method: 'POST',
    ip: '10.0.14.4',
    body: {
      username: 'admin_lampor',
      password: 'AdminPassword123',
      challenge: chAdmin,
      website: '',
    },
  });
  assert.equal(adminLogin.status, 200);
  const jar = parseSetCookieJar(adminLogin.setCookies);
  const csrf = adminLogin.json.csrfToken;

  // CSRF required on POST /api/admin/messages
  const missingCsrf = await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.14.4',
    cookies: jar,
    body: { action: 'send', scope: 'global', bodyMarkdown: 'Tanpa CSRF' },
  });
  assert.equal(missingCsrf.status, 403);
  assert.equal(missingCsrf.json.code, 'CSRF_INVALID');

  // Empty bodyMarkdown rejected with 400 VALIDATION_ERROR
  const emptyBody = await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.14.4',
    cookies: jar,
    csrf,
    body: { action: 'send', scope: 'global', title: 'Kosong', bodyMarkdown: '   \u0000\x07  ' },
  });
  assert.equal(emptyBody.status, 400);
  assert.equal(emptyBody.json.code, 'VALIDATION_ERROR');

  // Target unknown user -> 404 USER_NOT_FOUND
  const unknownTarget = await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.14.4',
    cookies: jar,
    csrf,
    body: {
      action: 'send',
      scope: 'user',
      targetUsername: 'TidakAdaPemain999',
      title: 'Halo',
      bodyMarkdown: 'Tes pesan',
    },
  });
  assert.equal(unknownTarget.status, 404);
  assert.equal(unknownTarget.json.code, 'USER_NOT_FOUND');

  // Target dashboard admin -> 400 INVALID_TARGET_USER
  const adminTarget = await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.14.4',
    cookies: jar,
    csrf,
    body: {
      action: 'send',
      scope: 'user',
      targetUsername: 'admin_lampor',
      title: 'Admin',
      bodyMarkdown: 'Pesan ke admin',
    },
  });
  assert.equal(adminTarget.status, 400);
  assert.equal(adminTarget.json.code, 'INVALID_TARGET_USER');

  // Send global message with rich Markdown & control chars to sanitize
  const rawMarkdown = '# Pengumuman Desa\r\n\r\n**Penting:** _Waspada_ ~~kabut~~ `lilin`.\r\n> Tetap bersama tim.\r\n- Bawa [Jamu](https://lampor.example)\u0000\x07';
  const expectedMarkdown = '# Pengumuman Desa\n\n**Penting:** _Waspada_ ~~kabut~~ `lilin`.\n> Tetap bersama tim.\n- Bawa [Jamu](https://lampor.example)';

  const sendGlobal = await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.14.4',
    cookies: jar,
    csrf,
    body: {
      action: 'send',
      scope: 'global',
      title: '<b>Update</b> Server',
      bodyMarkdown: rawMarkdown,
    },
  });
  assert.equal(sendGlobal.status, 201);
  assert.equal(sendGlobal.json.ok, true);
  assert.equal(sendGlobal.json.message.scope, 'global');
  assert.equal(sendGlobal.json.message.title, 'Update Server');
  assert.equal(sendGlobal.json.message.bodyMarkdown, expectedMarkdown);
  assert.equal(sendGlobal.json.message.senderUsername, 'admin_lampor');
  const globalMsgId = sendGlobal.json.message.id;

  // Send targeted message to Player A (case-insensitive username lookup)
  const sendToA = await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.14.4',
    cookies: jar,
    csrf,
    body: {
      action: 'send',
      scope: 'user',
      targetUsername: 'pesanpemaina',
      title: 'Hadiah Khusus A',
      bodyMarkdown: 'Halo **PesanPemainA**, cek kode `LAMPORGIFT`.',
    },
  });
  assert.equal(sendToA.status, 201);
  assert.equal(sendToA.json.message.scope, 'user');
  assert.equal(sendToA.json.message.targetUserId, playerA.json.user.id);
  assert.equal(sendToA.json.message.targetUsername, 'PesanPemainA');
  const msgToAId = sendToA.json.message.id;

  // Send targeted message to Player B
  const sendToB = await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.14.4',
    cookies: jar,
    csrf,
    body: {
      action: 'send',
      scope: 'user',
      targetUsername: 'PesanPemainB',
      title: 'Pesan Rahasia B',
      bodyMarkdown: 'Hanya untuk **PesanPemainB**.',
    },
  });
  assert.equal(sendToB.status, 201);
  const msgToBId = sendToB.json.message.id;

  // Admin GET /api/admin/messages lists all 3 messages
  const adminList = await api('/api/admin/messages', { ip: '10.0.14.4', cookies: jar });
  assert.equal(adminList.status, 200);
  assert.equal(adminList.json.messages.length >= 3, true);
  assert.ok(adminList.json.messages.some((m) => m.id === globalMsgId));
  assert.ok(adminList.json.messages.some((m) => m.id === msgToAId));
  assert.ok(adminList.json.messages.some((m) => m.id === msgToBId));

  // Guest GET /api/auth/global-messages returns ONLY global messages (no targeted messages leaked)
  const guestGlobal = await api('/api/auth/global-messages', { ip: '10.0.14.5' });
  assert.equal(guestGlobal.status, 200);
  assert.equal(guestGlobal.json.ok, true);
  assert.ok(guestGlobal.json.messages.some((m) => m.id === globalMsgId));
  assert.equal(guestGlobal.json.messages.some((m) => m.id === msgToAId || m.id === msgToBId), false);

  // /api/auth/me includes unreadMessagesCount
  const meA = await api('/api/auth/me', { token: tokenA, ip: '10.0.14.2' });
  assert.equal(meA.status, 200);
  assert.equal(meA.json.unreadMessagesCount, 2);

  const meB = await api('/api/auth/me', { token: tokenB, ip: '10.0.14.3' });
  assert.equal(meB.status, 200);
  assert.equal(meB.json.unreadMessagesCount, 2);

  // Visibility isolation: Player A sees global + msgToA, NOT msgToB
  const inboxA = await api('/api/auth/messages', { token: tokenA, ip: '10.0.14.2' });
  assert.equal(inboxA.status, 200);
  assert.equal(inboxA.json.unreadCount, 2);
  assert.ok(inboxA.json.messages.some((m) => m.id === globalMsgId && m.isRead === false));
  assert.ok(inboxA.json.messages.some((m) => m.id === msgToAId && m.isRead === false));
  assert.equal(inboxA.json.messages.some((m) => m.id === msgToBId), false);

  // Visibility isolation: Player B sees global + msgToB, NOT msgToA
  const inboxB = await api('/api/auth/messages', { token: tokenB, ip: '10.0.14.3' });
  assert.equal(inboxB.status, 200);
  assert.equal(inboxB.json.unreadCount, 2);
  assert.ok(inboxB.json.messages.some((m) => m.id === globalMsgId && m.isRead === false));
  assert.ok(inboxB.json.messages.some((m) => m.id === msgToBId && m.isRead === false));
  assert.equal(inboxB.json.messages.some((m) => m.id === msgToAId), false);

  // Player A marks only msgToAId (plus ignores msgToBId if passed) as read
  const markOneA = await api('/api/auth/messages', {
    method: 'POST',
    token: tokenA,
    ip: '10.0.14.2',
    body: { action: 'mark_read', messageIds: [msgToAId, msgToBId] },
  });
  assert.equal(markOneA.status, 200);
  assert.equal(markOneA.json.unreadCount, 1);

  const inboxAAfterOne = await api('/api/auth/messages', { token: tokenA, ip: '10.0.14.2' });
  assert.equal(inboxAAfterOne.json.messages.find((m) => m.id === msgToAId).isRead, true);
  assert.equal(inboxAAfterOne.json.messages.find((m) => m.id === globalMsgId).isRead, false);

  // Player B's unread count must remain untouched
  const meBAfterA = await api('/api/auth/me', { token: tokenB, ip: '10.0.14.3' });
  assert.equal(meBAfterA.json.unreadMessagesCount, 2);

  // Player A marks all remaining messages read (no messageIds)
  const markAllA = await api('/api/auth/messages', {
    method: 'POST',
    token: tokenA,
    ip: '10.0.14.2',
    body: { action: 'mark_read' },
  });
  assert.equal(markAllA.status, 200);
  assert.equal(markAllA.json.unreadCount, 0);

  const meAAfterAll = await api('/api/auth/me', { token: tokenA, ip: '10.0.14.2' });
  assert.equal(meAAfterAll.json.unreadMessagesCount, 0);

  // Admin deletes global message -> Player B unread drops from 2 to 1 and global-messages no longer includes it
  const delGlobal = await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.14.4',
    cookies: jar,
    csrf,
    body: { action: 'delete', messageId: globalMsgId },
  });
  assert.equal(delGlobal.status, 200);
  assert.equal(delGlobal.json.messages.some((m) => m.id === globalMsgId), false);

  const delAgain = await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.14.4',
    cookies: jar,
    csrf,
    body: { action: 'delete', messageId: globalMsgId },
  });
  assert.equal(delAgain.status, 404);

  const meBAfterDel = await api('/api/auth/me', { token: tokenB, ip: '10.0.14.3' });
  assert.equal(meBAfterDel.json.unreadMessagesCount, 1);

  const guestGlobalAfterDel = await api('/api/auth/global-messages', { ip: '10.0.14.5' });
  assert.equal(guestGlobalAfterDel.json.messages.some((m) => m.id === globalMsgId), false);
});

test('Public player profile endpoint, bio on friend/directory cards, and room player displayName', async () => {
  const viewer = await registerPlayer('ProfilViewer', 'ProfilPass123', '10.0.15.1');
  const target = await registerPlayer('ProfilTarget', 'ProfilPass123', '10.0.15.2');
  const fallbackUser = await registerPlayer('ProfilPolos', 'ProfilPass123', '10.0.15.3');
  assert.equal(viewer.status, 201);
  assert.equal(target.status, 201);
  assert.equal(fallbackUser.status, 201);

  // Update target profile with displayName, bio (with HTML + profanity), and preset avatar
  const updateTarget = await api('/api/auth/profile', {
    method: 'POST',
    token: target.json.token,
    ip: '10.0.15.2',
    body: {
      displayName: '<b>Penjaga</b> Desa',
      bio: '<script>alert(1)</script>Penjaga anjing ronda malam.\nSiap membantu tim!',
      avatarUrl: 'preset:obor',
    },
  });
  assert.equal(updateTarget.status, 200);

  const syncTarget = await api('/api/auth/sync', {
    method: 'POST',
    token: target.json.token,
    ip: '10.0.15.2',
    body: { totalWins: 7, coins: 450, saveSeq: 1 },
  });
  assert.equal(syncTarget.status, 200);

  // Verify bio & displayName appear in /api/friends/list directory
  const dirRes = await api('/api/friends/list?search=ProfilTarget', {
    token: viewer.json.token,
    ip: '10.0.15.1',
  });
  assert.equal(dirRes.status, 200);
  const dirCard = dirRes.json.directory.find((p) => p.id === target.json.user.id);
  assert.ok(dirCard);
  assert.equal(dirCard.displayName, 'Penjaga Desa');
  assert.equal(dirCard.bio, 'Penjaga *** ronda malam.\nSiap membantu tim!');
  assert.equal(dirCard.avatarUrl, 'preset:obor');

  // Unauthenticated profile lookup blocked
  const unauthProfile = await api('/api/friends/profile?username=ProfilTarget', { ip: '10.0.15.1' });
  assert.equal(unauthProfile.status, 401);

  // Missing or invalid query params return 400 VALIDATION_ERROR
  const missingQuery = await api('/api/friends/profile', {
    token: viewer.json.token,
    ip: '10.0.15.1',
  });
  assert.equal(missingQuery.status, 400);
  assert.equal(missingQuery.json.code, 'VALIDATION_ERROR');

  const badUuid = await api('/api/friends/profile?userId=not-a-uuid', {
    token: viewer.json.token,
    ip: '10.0.15.1',
  });
  assert.equal(badUuid.status, 400);
  assert.equal(badUuid.json.code, 'VALIDATION_ERROR');

  // Lookup by username (case-insensitive) for non-friend
  const byUsername = await api('/api/friends/profile?username=profiltarget', {
    token: viewer.json.token,
    ip: '10.0.15.1',
  });
  assert.equal(byUsername.status, 200);
  assert.equal(byUsername.json.ok, true);
  assert.equal(byUsername.json.profile.id, target.json.user.id);
  assert.equal(byUsername.json.profile.username, 'ProfilTarget');
  assert.equal(byUsername.json.profile.displayName, 'Penjaga Desa');
  assert.equal(byUsername.json.profile.bio, 'Penjaga *** ronda malam.\nSiap membantu tim!');
  assert.equal(byUsername.json.profile.avatarUrl, 'preset:obor');
  assert.equal(byUsername.json.profile.isVerified, false);
  assert.equal(byUsername.json.profile.totalWins, 7);
  assert.equal(byUsername.json.profile.isOnline, true);
  assert.equal(byUsername.json.profile.friendshipStatus, 'none');
  assert.equal(byUsername.json.profile.activeRoom, null);

  // Lookup self by userId
  const selfProfile = await api(`/api/friends/profile?userId=${viewer.json.user.id}`, {
    token: viewer.json.token,
    ip: '10.0.15.1',
  });
  assert.equal(selfProfile.status, 200);
  assert.equal(selfProfile.json.profile.isSelf, true);
  assert.equal(selfProfile.json.profile.friendshipStatus, 'self');

  // Unknown user and admin_lampor return 404 USER_NOT_FOUND
  const unknownProfile = await api('/api/friends/profile?username=TidakAdaPemainXYZ', {
    token: viewer.json.token,
    ip: '10.0.15.1',
  });
  assert.equal(unknownProfile.status, 404);
  assert.equal(unknownProfile.json.code, 'USER_NOT_FOUND');

  const adminProfile = await api('/api/friends/profile?username=admin_lampor', {
    token: viewer.json.token,
    ip: '10.0.15.1',
  });
  assert.equal(adminProfile.status, 404);
  assert.equal(adminProfile.json.code, 'USER_NOT_FOUND');

  // Friend request -> outgoing_pending / incoming_pending -> friends with activeRoom & bio on friend card
  const sendReq = await api('/api/friends/add', {
    method: 'POST',
    token: viewer.json.token,
    ip: '10.0.15.1',
    body: { friendUserId: target.json.user.id },
  });
  assert.equal(sendReq.status, 200);

  const outgoingProf = await api(`/api/friends/profile?userId=${target.json.user.id}`, {
    token: viewer.json.token,
    ip: '10.0.15.1',
  });
  assert.equal(outgoingProf.status, 200);
  assert.equal(outgoingProf.json.profile.friendshipStatus, 'outgoing_pending');

  const incomingProf = await api(`/api/friends/profile?userId=${viewer.json.user.id}`, {
    token: target.json.token,
    ip: '10.0.15.2',
  });
  assert.equal(incomingProf.status, 200);
  assert.equal(incomingProf.json.profile.friendshipStatus, 'incoming_pending');

  const acceptReq = await api('/api/friends/accept', {
    method: 'POST',
    token: target.json.token,
    ip: '10.0.15.2',
    body: { requesterUserId: viewer.json.user.id },
  });
  assert.equal(acceptReq.status, 200);

  // Target creates a room -> check room players displayName and friend profile activeRoom + bio
  const createdRoom = await api('/api/rooms/create', {
    method: 'POST',
    token: target.json.token,
    ip: '10.0.15.2',
    body: {
      name: 'Pos Ronda Malam',
      mode: 'multiplayer',
      maxPlayers: 4,
      difficulty: 'normal',
      canUseShopItems: true,
    },
  });
  assert.equal(createdRoom.status, 201);
  assert.equal(createdRoom.json.players[0].username, 'ProfilTarget');
  assert.equal(createdRoom.json.players[0].displayName, 'Penjaga Desa');
  assert.equal(createdRoom.json.players[0].avatarUrl, 'preset:obor');

  // FallbackUser (no displayName set) joins -> displayName falls back to username
  const joinFallback = await api('/api/rooms/join', {
    method: 'POST',
    token: fallbackUser.json.token,
    ip: '10.0.15.3',
    body: { roomId: createdRoom.json.room.id },
  });
  assert.equal(joinFallback.status, 200);
  const hostInRoom = joinFallback.json.players.find((p) => p.userId === target.json.user.id);
  const fallbackInRoom = joinFallback.json.players.find((p) => p.userId === fallbackUser.json.user.id);
  assert.equal(hostInRoom.displayName, 'Penjaga Desa');
  assert.equal(fallbackInRoom.username, 'ProfilPolos');
  assert.equal(fallbackInRoom.displayName, 'ProfilPolos');

  const syncRoom = await api('/api/rooms/sync', {
    method: 'POST',
    token: target.json.token,
    ip: '10.0.15.2',
    body: { roomId: createdRoom.json.room.id, lastEventSeq: 0 },
  });
  assert.equal(syncRoom.status, 200);
  assert.equal(
    syncRoom.json.players.find((p) => p.userId === target.json.user.id).displayName,
    'Penjaga Desa'
  );

  // Friend list card includes bio, and friend profile includes activeRoom
  const friendsList = await api('/api/friends/list', {
    token: viewer.json.token,
    ip: '10.0.15.1',
  });
  assert.equal(friendsList.status, 200);
  const friendCard = friendsList.json.friends.find((f) => f.id === target.json.user.id);
  assert.equal(friendCard.bio, 'Penjaga *** ronda malam.\nSiap membantu tim!');

  const friendProf = await api(`/api/friends/profile?userId=${target.json.user.id}`, {
    token: viewer.json.token,
    ip: '10.0.15.1',
  });
  assert.equal(friendProf.status, 200);
  assert.equal(friendProf.json.profile.isFriend, true);
  assert.equal(friendProf.json.profile.friendshipStatus, 'friends');
  assert.equal(friendProf.json.profile.bio, 'Penjaga *** ronda malam.\nSiap membantu tim!');
  assert.ok(friendProf.json.profile.activeRoom);
  assert.equal(friendProf.json.profile.activeRoom.id, createdRoom.json.room.id);
});

test('Player message @username placeholder resolves per recipient while preserving template and emails', async () => {
  const chAdmin = await solvePow('10.0.16.1');
  const adminLogin = await api('/api/admin/login', {
    method: 'POST',
    ip: '10.0.16.1',
    body: {
      username: 'admin_lampor',
      password: 'AdminPassword123',
      challenge: chAdmin,
      website: '',
    },
  });
  assert.equal(adminLogin.status, 200);
  const jar = parseSetCookieJar(adminLogin.setCookies);
  const csrf = adminLogin.json.csrfToken;
  const pA = await registerPlayer('FmtPlayerA', 'PassFmt123', '10.0.16.2');
  const pB = await registerPlayer('FmtPlayerB', 'PassFmt123', '10.0.16.3');
  assert.equal(pA.status, 201);
  assert.equal(pB.status, 201);

  const sendGlobal = await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.16.1',
    cookies: jar,
    csrf,
    body: {
      action: 'send',
      scope: 'global',
      title: 'Halo @username!',
      bodyMarkdown: 'Selamat datang **@username** (@USERNAME), info di help@username.com atau @username123.',
    },
  });
  assert.equal(sendGlobal.status, 201);
  assert.equal(sendGlobal.json.message.title, 'Halo @username!');
  assert.ok(sendGlobal.json.message.bodyMarkdown.includes('**@username**'));
  const gId = sendGlobal.json.message.id;

  const sendDirect = await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.16.1',
    cookies: jar,
    csrf,
    body: {
      action: 'send',
      scope: 'user',
      targetUsername: 'fmtplayerb',
      title: 'Hadiah Khusus @username',
      bodyMarkdown: 'Hai @username, hadiahmu sudah aktif.',
    },
  });
  assert.equal(sendDirect.status, 201);
  const dId = sendDirect.json.message.id;

  // Admin list preserves raw @username placeholder
  const adminList = await api('/api/admin/messages', { ip: '10.0.16.1', cookies: jar });
  assert.equal(adminList.status, 200);
  const adminG = adminList.json.messages.find((m) => m.id === gId);
  assert.equal(adminG.title, 'Halo @username!');
  assert.ok(adminG.bodyMarkdown.includes('**@username**'));

  // Guest global-messages preserves raw @username
  const guestRes = await api('/api/auth/global-messages', { ip: '10.0.16.4' });
  assert.equal(guestRes.status, 200);
  const guestG = guestRes.json.messages.find((m) => m.id === gId);
  assert.equal(guestG.title, 'Halo @username!');

  // Authenticated Player A receives personalized FmtPlayerA without corrupting emails/suffixes
  const inboxA = await api('/api/auth/messages', { token: pA.json.token, ip: '10.0.16.2' });
  assert.equal(inboxA.status, 200);
  const msgA = inboxA.json.messages.find((m) => m.id === gId);
  assert.equal(msgA.title, 'Halo FmtPlayerA!');
  assert.equal(
    msgA.bodyMarkdown,
    'Selamat datang **FmtPlayerA** (FmtPlayerA), info di help@username.com atau @username123.'
  );

  // Authenticated Player B receives personalized FmtPlayerB in both global & direct messages
  const inboxB = await api('/api/auth/messages', { token: pB.json.token, ip: '10.0.16.3' });
  assert.equal(inboxB.status, 200);
  const msgBG = inboxB.json.messages.find((m) => m.id === gId);
  const msgBD = inboxB.json.messages.find((m) => m.id === dId);
  assert.equal(msgBG.title, 'Halo FmtPlayerB!');
  assert.equal(
    msgBG.bodyMarkdown,
    'Selamat datang **FmtPlayerB** (FmtPlayerB), info di help@username.com atau @username123.'
  );
  assert.equal(msgBD.title, 'Hadiah Khusus FmtPlayerB');
  assert.equal(msgBD.bodyMarkdown, 'Hai FmtPlayerB, hadiahmu sudah aktif.');

  await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.16.1',
    cookies: jar,
    csrf,
    body: { action: 'delete', messageId: gId },
  });
  await api('/api/admin/messages', {
    method: 'POST',
    ip: '10.0.16.1',
    cookies: jar,
    csrf,
    body: { action: 'delete', messageId: dId },
  });
});
