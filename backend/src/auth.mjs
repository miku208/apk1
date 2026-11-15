// Device pairing, token issuing and request authentication.
import crypto from 'node:crypto';
import { config } from './config.mjs';
import { query } from './db.mjs';
import { logger } from './logger.mjs';
import { recordActivity } from './events.mjs';

const OWNER_ID = 'owner';

export function ensureOwner() {
  const existing = query.get('SELECT * FROM users WHERE id = ?', OWNER_ID);
  if (existing) {
    if (config.ownerPassword && !existing.password_hash) {
      query.run('UPDATE users SET password_hash = ? WHERE id = ?', hashSecret(config.ownerPassword), OWNER_ID);
    }
    return existing;
  }
  query.run(
    'INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)',
    OWNER_ID,
    'owner',
    config.ownerPassword ? hashSecret(config.ownerPassword) : null,
    Date.now(),
  );
  return query.get('SELECT * FROM users WHERE id = ?', OWNER_ID);
}

function hashSecret(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function tokenHash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * A pairing code is short enough to type on a phone and valid once. Only its
 * hash is stored, and it expires after PAIRING_TTL_MS.
 */
export function createPairingSession({ createdBy = 'server' } = {}) {
  const code = String(crypto.randomInt(100000, 999999));
  const id = crypto.randomUUID();
  const now = Date.now();
  query.run('DELETE FROM pairing_sessions WHERE expires_at < ? OR used_at IS NOT NULL', now);
  query.run(
    'INSERT INTO pairing_sessions (id, code_hash, expires_at, created_at, created_by) VALUES (?, ?, ?, ?, ?)',
    id,
    hashSecret(code),
    now + config.pairingTtlMs,
    now,
    createdBy,
  );
  return { id, code, expiresAt: now + config.pairingTtlMs };
}

export function activePairingSessions() {
  return query
    .all('SELECT id, expires_at, created_at FROM pairing_sessions WHERE used_at IS NULL AND expires_at > ?', Date.now())
    .map((row) => ({ id: row.id, expiresAt: row.expires_at, createdAt: row.created_at }));
}

function issueTokens(deviceId) {
  const now = Date.now();
  const access = randomToken();
  const refresh = randomToken();
  query.run(
    'INSERT INTO tokens (id, device_id, kind, token_hash, scopes, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    crypto.randomUUID(),
    deviceId,
    'access',
    tokenHash(access),
    'owner',
    now + config.accessTokenTtlMs,
    now,
  );
  query.run(
    'INSERT INTO tokens (id, device_id, kind, token_hash, scopes, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    crypto.randomUUID(),
    deviceId,
    'refresh',
    tokenHash(refresh),
    'owner',
    now + config.refreshTokenTtlMs,
    now,
  );
  return {
    accessToken: access,
    refreshToken: refresh,
    expiresIn: Math.floor(config.accessTokenTtlMs / 1000),
  };
}

export function pairDevice({ code, name, platform = 'android' }) {
  ensureOwner();
  const row = query.get(
    'SELECT * FROM pairing_sessions WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?',
    hashSecret(String(code ?? '').trim()),
    Date.now(),
  );
  if (!row) {
    const error = new Error('Pairing code is invalid or expired.');
    error.status = 401;
    error.code = 'INVALID_PAIRING_CODE';
    throw error;
  }
  const active = query.get('SELECT COUNT(*) AS n FROM devices WHERE revoked_at IS NULL');
  if (Number(active?.n ?? 0) >= config.maxDevices) {
    const error = new Error(`Device limit reached (${config.maxDevices}). Revoke a device first.`);
    error.status = 409;
    error.code = 'DEVICE_LIMIT';
    throw error;
  }
  const deviceId = crypto.randomUUID();
  const now = Date.now();
  query.run(
    'INSERT INTO devices (id, user_id, name, platform, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)',
    deviceId,
    OWNER_ID,
    String(name ?? 'Android device').slice(0, 80),
    String(platform ?? 'android').slice(0, 40),
    now,
    now,
  );
  query.run('UPDATE pairing_sessions SET used_at = ? WHERE id = ?', now, row.id);
  audit('system', 'device.paired', deviceId, { platform });
  recordActivity({ type: 'auth', title: `New device paired: ${name ?? 'Android device'}`, source: 'auth', result: 'ok' });
  return { deviceId, ...issueTokens(deviceId) };
}

export function loginWithPassword({ password, name = 'Android device', platform = 'android' }) {
  ensureOwner();
  const user = query.get('SELECT * FROM users WHERE id = ?', OWNER_ID);
  if (!user?.password_hash) {
    const error = new Error('Password login is disabled. Use a pairing code.');
    error.status = 401;
    error.code = 'PASSWORD_DISABLED';
    throw error;
  }
  if (hashSecret(password ?? '') !== user.password_hash) {
    const error = new Error('Wrong password.');
    error.status = 401;
    error.code = 'INVALID_CREDENTIALS';
    throw error;
  }
  const deviceId = crypto.randomUUID();
  const now = Date.now();
  query.run(
    'INSERT INTO devices (id, user_id, name, platform, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)',
    deviceId,
    OWNER_ID,
    String(name).slice(0, 80),
    String(platform).slice(0, 40),
    now,
    now,
  );
  audit('owner', 'device.login', deviceId, { platform });
  return { deviceId, ...issueTokens(deviceId) };
}

export function refreshTokens({ refreshToken, deviceId }) {
  const row = query.get(
    "SELECT * FROM tokens WHERE token_hash = ? AND kind = 'refresh' AND revoked_at IS NULL AND expires_at > ?",
    tokenHash(refreshToken ?? ''),
    Date.now(),
  );
  if (!row || row.device_id !== deviceId) {
    const error = new Error('Refresh token is invalid or expired.');
    error.status = 401;
    error.code = 'INVALID_REFRESH_TOKEN';
    throw error;
  }
  const device = query.get('SELECT * FROM devices WHERE id = ? AND revoked_at IS NULL', deviceId);
  if (!device) {
    const error = new Error('Device was revoked.');
    error.status = 401;
    error.code = 'DEVICE_REVOKED';
    throw error;
  }
  // Rotate: the used refresh token dies with the request.
  query.run('UPDATE tokens SET revoked_at = ? WHERE id = ?', Date.now(), row.id);
  return { deviceId, ...issueTokens(deviceId) };
}

export function authenticateToken(rawToken) {
  if (!rawToken) return null;
  const row = query.get(
    "SELECT t.*, d.name AS device_name, d.revoked_at AS device_revoked FROM tokens t JOIN devices d ON d.id = t.device_id WHERE t.token_hash = ? AND t.kind = 'access'",
    tokenHash(rawToken),
  );
  if (!row) return null;
  if (row.revoked_at || row.device_revoked) return null;
  if (Number(row.expires_at) < Date.now()) return null;
  query.run('UPDATE devices SET last_seen_at = ? WHERE id = ?', Date.now(), row.device_id);
  return { deviceId: row.device_id, deviceName: row.device_name, scopes: row.scopes };
}

export function revokeDevice(deviceId) {
  const device = query.get('SELECT * FROM devices WHERE id = ?', deviceId);
  if (!device) return false;
  const now = Date.now();
  query.run('UPDATE devices SET revoked_at = ? WHERE id = ?', now, deviceId);
  query.run('UPDATE tokens SET revoked_at = ? WHERE device_id = ?', now, deviceId);
  audit('owner', 'device.revoked', deviceId, {});
  return true;
}

export function listDevices() {
  return query.all('SELECT * FROM devices ORDER BY created_at DESC').map((row) => ({
    id: row.id,
    name: row.name,
    platform: row.platform,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    revoked: Boolean(row.revoked_at),
  }));
}

export function logoutDevice(deviceId) {
  query.run('UPDATE tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL', Date.now(), deviceId);
  return true;
}

/** Every privileged action lands here; never includes secret material. */
export function audit(actor, action, target = null, detail = null, result = 'ok') {
  try {
    query.run(
      'INSERT INTO audit_logs (actor, action, target, detail, result, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      actor,
      action,
      target,
      detail ? JSON.stringify(detail) : null,
      result,
      Date.now(),
    );
  } catch (error) {
    logger.warn('audit write failed', String(error));
  }
}
