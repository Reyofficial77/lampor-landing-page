-- LAMPOR: Malam Jahanam — Neon PostgreSQL Schema (v1.3.0)

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  username TEXT NOT NULL,
  username_lower TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  bio TEXT NOT NULL DEFAULT '',
  avatar_url TEXT NOT NULL DEFAULT '',
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
);

CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);
CREATE INDEX IF NOT EXISTS idx_users_banned ON users (is_banned);

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
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);

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
);

CREATE INDEX IF NOT EXISTS idx_rooms_status_mode ON rooms (status, mode);
CREATE INDEX IF NOT EXISTS idx_rooms_last_activity ON rooms (last_activity_at);

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
);

CREATE INDEX IF NOT EXISTS idx_room_players_last_seen ON room_players (room_id, last_seen_at);

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
);

CREATE INDEX IF NOT EXISTS idx_room_events_room_seq ON room_events (room_id, seq);

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
);

CREATE TABLE IF NOT EXISTS security_logs (
  id UUID PRIMARY KEY,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  username TEXT NOT NULL DEFAULT '',
  ip_address TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_logs_created ON security_logs (created_at DESC);

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
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs (created_at DESC);

CREATE TABLE IF NOT EXISTS ip_blocks (
  id UUID PRIMARY KEY,
  ip_address TEXT NOT NULL UNIQUE,
  reason TEXT NOT NULL DEFAULT '',
  blocked_by TEXT NOT NULL DEFAULT 'admin',
  expires_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rate_limits (
  bucket_key TEXT PRIMARY KEY,
  window_start TIMESTAMPTZ NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  timestamps JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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
);

INSERT INTO server_settings (
  id,
  maintenance_mode,
  maintenance_message,
  allow_registration,
  allow_multiplayer,
  allow_sandbox,
  max_active_rooms,
  global_announcement,
  min_client_version,
  updated_by
) VALUES (
  1,
  FALSE,
  '',
  TRUE,
  TRUE,
  TRUE,
  50,
  '',
  '1.3.0',
  'system'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO redeem_codes (
  code, reward_type, item_id, quantity, max_uses, description_id, description_en, is_active
) VALUES
  ('LAMPORGIFT', 'coins', '', 2500, NULL, 'hadiah untuk kalian!', 'A gift for you!', TRUE),
  ('FOREVERYONE', 'coins', '', 5000, NULL, 'Hadiah untuk semua pemain!', 'A gift for everyone!', TRUE),
  ('LAMPORLOVER', 'coins', '', 10000, NULL, 'Hadiah spesial pecinta Lampor!', 'Special gift for Lampor fans!', TRUE)
ON CONFLICT (code) DO NOTHING;
