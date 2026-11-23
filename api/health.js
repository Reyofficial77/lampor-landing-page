import * as db from './_lib/db.js';
import {
  runSecurityPreflight,
  sanitizeText,
  sendJson,
} from './_lib/security.js';

export default async function handler(req, res) {
  const pre = await runSecurityPreflight(req, res, db, { rateCategory: 'general' });
  if (pre.handled) return;

  if (req.method !== 'GET') {
    return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
  }

  const dbLatencyMs = await db.pingDb();
  await db.cleanupStaleRooms(15);
  const [settings, activeRooms] = await Promise.all([
    db.getServerSettings(),
    db.countActiveRooms(),
  ]);

  return sendJson(res, 200, {
    ok: true,
    version: '1.3.0',
    dbLatencyMs,
    maintenanceMode: Boolean(settings.maintenance_mode),
    maintenanceMessage: sanitizeText(settings.maintenance_message || '', 300),
    activeRooms,
    serverTime: new Date().toISOString(),
  });
}
