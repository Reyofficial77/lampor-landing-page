import { z } from 'zod';
import * as db from './_lib/db.js';
import {
  formatZodError,
  requirePlayerSession,
  runSecurityPreflight,
  sendJson,
  serializePlayerUser,
} from './_lib/security.js';

const redeemSchema = z.strictObject({
  code: z.string().trim().min(1, 'Kode redeem wajib diisi.').max(64),
});

export default async function handler(req, res) {
  const pre = await runSecurityPreflight(req, res, db, {
    rateCategory: 'general',
    parseBody: req.method === 'POST',
  });
  if (pre.handled) return;

  if (req.method !== 'POST') {
    return sendJson(res, 405, { ok: false, error: 'Method not allowed.', code: 'METHOD_NOT_ALLOWED' });
  }

  const auth = await requirePlayerSession(req, res, db);
  if (!auth) return;

  const parsed = redeemSchema.safeParse(pre.body);
  if (!parsed.success) {
    return sendJson(res, 400, {
      ok: false,
      error: formatZodError(parsed.error),
      code: 'VALIDATION_ERROR',
    });
  }

  const normalized = parsed.data.code.toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (normalized.length < 3 || normalized.length > 32) {
    return sendJson(res, 400, {
      ok: false,
      error: 'Format kode redeem tidak valid.',
      code: 'INVALID_CODE_FORMAT',
    });
  }

  const result = await db.redeemCodeForUser({ userId: auth.user.id, rawCode: normalized });
  if (!result.ok) {
    return sendJson(res, result.status, {
      ok: false,
      error: result.error,
      code: result.code,
    });
  }

  return sendJson(res, 200, {
    ok: true,
    message: `Berhasil menukarkan kode ${result.reward.code}!`,
    reward: result.reward,
    user: serializePlayerUser(result.user),
  });
}
