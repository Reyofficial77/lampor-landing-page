import { useEffect, useRef } from 'react'

let inMemoryCsrfToken = ''

export class ApiError extends Error {
  constructor(message, status = 0, data = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.data = data
  }
}

export function setCsrfToken(token) {
  inMemoryCsrfToken = typeof token === 'string' ? token : ''
}

export function getCsrfToken() {
  if (inMemoryCsrfToken) return inMemoryCsrfToken
  if (typeof document === 'undefined') return ''
  const match = document.cookie
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith('lampor_csrf='))
  if (!match) return ''
  const val = decodeURIComponent(match.slice('lampor_csrf='.length))
  inMemoryCsrfToken = val
  return val
}

async function requestJson(url, options = {}) {
  const { method = 'GET', body, requireCsrf = false } = options
  const headers = {
    Accept: 'application/json',
  }

  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }

  if (requireCsrf) {
    const csrf = getCsrfToken()
    if (csrf) headers['X-Lampor-CSRF'] = csrf
  }
  if (method === 'GET') {
    headers['Cache-Control'] = 'no-cache'
  }

  let res
  try {
    res = await fetch(url, {
      method,
      headers,
      cache: 'no-store',
      credentials: 'include',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new ApiError(
      'Tidak dapat menghubungi server API. Periksa koneksi jaringan atau pastikan server API berjalan.',
      0,
      null
    )
  }

  let data = null
  const text = await res.text()
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = { raw: text }
    }
  }

  if (!res.ok) {
    const baseMsg =
      data?.error ||
      data?.message ||
      (res.status === 401
        ? 'Sesi admin tidak valid atau telah berakhir. Silakan masuk kembali.'
        : res.status === 403
          ? 'Akses ditolak oleh server.'
          : res.status === 429
            ? 'Terlalu banyak percobaan. Tunggu beberapa saat sebelum mencoba lagi.'
            : `Permintaan gagal dengan kode status ${res.status}.`)
    const serverMsg = data?.reason ? `${baseMsg} (Alasan: ${data.reason})` : baseMsg
    throw new ApiError(serverMsg, res.status, data)
  }

  if (data && typeof data.csrfToken === 'string' && data.csrfToken) {
    setCsrfToken(data.csrfToken)
  }

  return data || { ok: true }
}

function toHex(buffer) {
  const bytes = new Uint8Array(buffer)
  let out = ''
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, '0')
  }
  return out
}

export async function solvePowChallenge(onProgress) {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new ApiError(
      'Peramban tidak mendukung Web Crypto API (SHA-256) untuk verifikasi anti-bot.',
      0,
      null
    )
  }

  const challenge = await requestJson('/api/auth/challenge', { method: 'GET' })
  const { challengeId, salt, difficulty = 3, expiresAt, signature } = challenge
  if (!challengeId || !salt || !signature) {
    throw new ApiError('Server mengembalikan tantangan anti-bot yang tidak lengkap.', 500, challenge)
  }

  const prefix = '0'.repeat(Math.max(1, Number(difficulty) || 3))
  const encoder = new TextEncoder()
  let nonce = 0

  while (true) {
    const digest = await crypto.subtle.digest('SHA-256', encoder.encode(`${salt}:${nonce}`))
    const hex = toHex(digest)
    if (hex.startsWith(prefix)) {
      return {
        challengeId,
        salt,
        difficulty: Number(difficulty) || 3,
        expiresAt,
        signature,
        nonce,
      }
    }
    nonce += 1
    if (nonce % 400 === 0) {
      onProgress?.(nonce)
      await new Promise((resolve) => setTimeout(resolve, 0))
    }
  }
}

export async function getAdminSession() {
  try {
    return await requestJson('/api/admin/session', { method: 'GET' })
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      setCsrfToken('')
      return null
    }
    throw err
  }
}

export async function loginAdmin({ username, password, website = '', onStatus }) {
  onStatus?.('Mengambil tantangan anti-bot dari server...')
  const challenge = await solvePowChallenge((attempts) => {
    onStatus?.(`Memverifikasi anti-bot PoW (${attempts} iterasi)...`)
  })
  onStatus?.('Mengautentikasi kredensial admin...')
  return requestJson('/api/admin/login', {
    method: 'POST',
    body: {
      username,
      password,
      challenge,
      website,
    },
  })
}

export async function logoutAdmin() {
  try {
    await requestJson('/api/admin/logout', {
      method: 'POST',
      body: {},
      requireCsrf: true,
    })
  } finally {
    setCsrfToken('')
  }
}

export function fetchOverview() {
  return requestJson('/api/admin/overview', { method: 'GET' })
}

export function fetchServerSettings() {
  return requestJson('/api/admin/server', { method: 'GET' })
}

export function saveServerSettings(payload) {
  return requestJson('/api/admin/server', {
    method: 'POST',
    body: payload,
    requireCsrf: true,
  })
}

export function fetchUsers({ search = '', status = 'all', page = 1 } = {}) {
  const params = new URLSearchParams()
  if (search) params.set('search', search)
  if (status && status !== 'all') params.set('status', status)
  params.set('page', String(page))
  return requestJson(`/api/admin/users?${params.toString()}`, { method: 'GET' })
}

export function postUsersAction(payload) {
  return requestJson('/api/admin/users-action', {
    method: 'POST',
    body: payload,
    requireCsrf: true,
  })
}

export function fetchRooms() {
  return requestJson('/api/admin/rooms', { method: 'GET' })
}

export function postRoomsAction(payload) {
  return requestJson('/api/admin/rooms-action', {
    method: 'POST',
    body: payload,
    requireCsrf: true,
  })
}

export function fetchSecurity() {
  return requestJson('/api/admin/security', { method: 'GET' })
}

export function postSecurityAction(payload) {
  return requestJson('/api/admin/security', {
    method: 'POST',
    body: payload,
    requireCsrf: true,
  })
}

export function fetchRedeemCodes() {
  return requestJson('/api/admin/redeem', { method: 'GET' })
}

export function postRedeemAction(payload) {
  return requestJson('/api/admin/redeem', {
    method: 'POST',
    body: payload,
    requireCsrf: true,
  })
}

export function normalizeServerSettings(raw = {}) {
  const s = raw || {}
  return {
    maintenanceMode: Boolean(s.maintenanceMode ?? s.maintenance_mode ?? false),
    maintenanceMessage: String(s.maintenanceMessage ?? s.maintenance_message ?? ''),
    allowRegistration: Boolean(s.allowRegistration ?? s.allow_registration ?? true),
    allowMultiplayer: Boolean(s.allowMultiplayer ?? s.allow_multiplayer ?? true),
    allowSandbox: Boolean(s.allowSandbox ?? s.allow_sandbox ?? true),
    maxActiveRooms: Number(s.maxActiveRooms ?? s.max_active_rooms ?? 50),
    globalAnnouncement: String(s.globalAnnouncement ?? s.global_announcement ?? ''),
    minClientVersion: String(s.minClientVersion ?? s.min_client_version ?? '1.3.0'),
  }
}

export function normalizeUser(raw = {}) {
  return {
    id: raw.id ?? raw.userId ?? raw.user_id ?? '',
    username: raw.username ?? '',
    role: raw.role ?? 'player',
    isVerified: Boolean(raw.isVerified ?? raw.is_verified ?? false),
    coins: Number(raw.coins ?? 0),
    totalWins: Number(raw.totalWins ?? raw.total_wins ?? 0),
    extraLives: Number(raw.extraLives ?? raw.extra_lives ?? 0),
    isBanned: Boolean(raw.isBanned ?? raw.is_banned ?? false),
    banReason: raw.banReason ?? raw.ban_reason ?? '',
    failedLoginAttempts: Number(raw.failedLoginAttempts ?? raw.failed_login_attempts ?? 0),
    lockedUntil: raw.lockedUntil ?? raw.locked_until ?? null,
    lastLoginIp: raw.lastLoginIp ?? raw.last_login_ip ?? '',
    createdAt: raw.createdAt ?? raw.created_at ?? null,
    lastLoginAt: raw.lastLoginAt ?? raw.last_login_at ?? null,
  }
}

export function normalizeRoom(raw = {}) {
  const players = Array.isArray(raw.players) ? raw.players : []
  return {
    id: raw.id ?? raw.roomId ?? raw.room_id ?? '',
    roomCode: raw.roomCode ?? raw.room_code ?? '',
    name: raw.name ?? 'Room Tanpa Nama',
    mode: raw.mode ?? 'multiplayer',
    status: raw.status ?? 'lobby',
    difficulty: raw.difficulty ?? 'normal',
    maxPlayers: Number(raw.maxPlayers ?? raw.max_players ?? 4),
    playerCount: Number(raw.playerCount ?? raw.player_count ?? players.length),
    hasPassword: Boolean(raw.hasPassword ?? raw.has_password ?? false),
    canUseShopItems: Boolean(raw.canUseShopItems ?? raw.can_use_shop_items ?? true),
    allowLateJoin: Boolean(raw.allowLateJoin ?? raw.allow_late_join ?? false),
    announcement: raw.announcement ?? '',
    hostUserId: raw.hostUserId ?? raw.host_user_id ?? '',
    hostUsername: raw.hostUsername ?? raw.host_username ?? '',
    hostIsVerified: Boolean(raw.hostIsVerified ?? raw.host_is_verified ?? false),
    lastActivityAt: raw.lastActivityAt ?? raw.last_activity_at ?? raw.updatedAt ?? raw.updated_at ?? null,
    players: players.map((p) => ({
      userId: p.userId ?? p.user_id ?? p.id ?? '',
      username: p.username ?? 'Pemain',
      isHost: Boolean(p.isHost ?? p.is_host ?? false),
      isReady: Boolean(p.isReady ?? p.is_ready ?? false),
      isVerified: Boolean(p.isVerified ?? p.is_verified ?? false),
      joinedAt: p.joinedAt ?? p.joined_at ?? null,
      lastSeenAt: p.lastSeenAt ?? p.last_seen_at ?? null,
    })),
  }
}

export function normalizeRedeemCode(raw = {}) {
  const rawMax = raw.maxUses ?? raw.max_uses
  return {
    code: raw.code ?? '',
    rewardType: raw.rewardType ?? raw.reward_type ?? 'coins',
    itemId: raw.itemId ?? raw.item_id ?? '',
    quantity: Number(raw.quantity ?? 0),
    maxUses: rawMax === null || rawMax === undefined ? null : Number(rawMax),
    usesCount: Number(raw.usesCount ?? raw.uses_count ?? raw.currentUses ?? raw.current_uses ?? 0),
    descriptionId: raw.descriptionId ?? raw.description_id ?? '',
    descriptionEn: raw.descriptionEn ?? raw.description_en ?? '',
    isActive: Boolean(raw.isActive ?? raw.is_active ?? true),
    createdAt: raw.createdAt ?? raw.created_at ?? null,
  }
}

export function formatTimestamp(value) {
  if (!value) return 'Belum tercatat'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleString('id-ID', {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

export function useDialogController(isOpen, onClose, returnFocusRef) {
  const dialogRef = useRef(null)
  const wasOpenRef = useRef(false)

  useEffect(() => {
    const dialog = dialogRef.current
    if (!dialog) return

    if (isOpen) {
      if (!dialog.open) dialog.showModal()
      wasOpenRef.current = true
    } else if (dialog.open) {
      dialog.close()
    }
  }, [isOpen])

  useEffect(() => {
    if (!isOpen && wasOpenRef.current) {
      wasOpenRef.current = false
      if (returnFocusRef?.current && typeof returnFocusRef.current.focus === 'function') {
        returnFocusRef.current.focus()
        returnFocusRef.current = null
      }
    }
  }, [isOpen, returnFocusRef])

  const onDialogClick = (e) => {
    if (e.target === dialogRef.current) {
      onClose()
    }
  }

  const onDialogCancel = (e) => {
    e.preventDefault()
    onClose()
  }

  return { dialogRef, onDialogClick, onDialogCancel }
}
