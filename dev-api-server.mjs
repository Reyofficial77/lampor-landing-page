import http from 'node:http';
import { pathToFileURL } from 'node:url';
import healthHandler from './api/health.js';
import authHandler from './api/auth/[action].js';
import roomsHandler from './api/rooms/[action].js';
import adminHandler from './api/admin/[action].js';
import friendsHandler from './api/friends/[action].js';
import redeemHandler from './api/redeem.js';
import { applySecurityHeaders, applyCorsHeaders } from './api/_lib/security.js';

function attachResponseHelpers(res) {
  res.status = (code) => {
    res.statusCode = code;
    return res;
  };
  res.json = (data) => {
    if (!res.headersSent && !res.getHeader('Content-Type')) {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
    }
    res.end(JSON.stringify(data));
    return res;
  };
  res.send = (data) => {
    if (data !== null && typeof data === 'object' && !Buffer.isBuffer(data)) {
      return res.json(data);
    }
    res.end(data ?? '');
    return res;
  };
  return res;
}

export function createApiServer() {
  return http.createServer(async (req, res) => {
    attachResponseHelpers(res);

    res.on('finish', () => {
      if (!req.readableEnded && !req.destroyed) {
        req.resume();
      }
    });

    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname.replace(/\/+$/, '') || '/';
    const query = Object.fromEntries(parsedUrl.searchParams.entries());
    req.query = query;

    try {
      if (pathname === '/api/health') {
        await healthHandler(req, res);
        return;
      }

      if (pathname === '/api/redeem') {
        await redeemHandler(req, res);
        return;
      }

      const authMatch = /^\/api\/auth\/([^/]+)$/.exec(pathname);
      if (authMatch) {
        req.query.action = decodeURIComponent(authMatch[1]);
        await authHandler(req, res);
        return;
      }

      const roomsMatch = /^\/api\/rooms\/([^/]+)$/.exec(pathname);
      if (roomsMatch) {
        req.query.action = decodeURIComponent(roomsMatch[1]);
        await roomsHandler(req, res);
        return;
      }

      const adminMatch = /^\/api\/admin\/([^/]+)$/.exec(pathname);
      if (adminMatch) {
        req.query.action = decodeURIComponent(adminMatch[1]);
        await adminHandler(req, res);
        return;
      }

      const friendsMatch = /^\/api\/friends\/([^/]+)$/.exec(pathname);
      if (friendsMatch) {
        req.query.action = decodeURIComponent(friendsMatch[1]);
        await friendsHandler(req, res);
        return;
      }

      applySecurityHeaders(res);
      applyCorsHeaders(req, res, { allowCredentials: false });
      if (req.method === 'OPTIONS') {
        res.status(204).end();
        return;
      }
      res.status(404).json({ ok: false, error: 'API endpoint not found.', code: 'NOT_FOUND' });
    } catch (err) {
      console.error('[dev-api-server] Unhandled error:', err);
      if (!res.headersSent) {
        applySecurityHeaders(res);
        res.status(500).json({
          ok: false,
          error: 'Terjadi kesalahan internal pada server.',
          code: 'INTERNAL_ERROR',
        });
      } else if (!res.writableEnded) {
        res.end();
      }
    }
  });
}

const isMain =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  try {
    process.loadEnvFile?.();
  } catch {
    // Ignore missing .env file in local dev
  }

  const port = Number(process.env.API_PORT || 3001);
  const server = createApiServer();
  server.listen(port, () => {
    console.log(`[lampor-api] Listening on http://localhost:${port}`);
  });
}
