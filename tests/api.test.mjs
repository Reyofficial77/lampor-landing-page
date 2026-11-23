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
