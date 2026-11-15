// Saved remote servers: CRUD, encrypted credentials, defaults and history.
import crypto from 'node:crypto';
import { query } from '../db.mjs';
import { config } from '../config.mjs';
import { audit } from '../auth.mjs';
import { decryptSecret, encryptSecret, secretHint } from './crypto.mjs';
import { normalizeFingerprint } from './fingerprint.mjs';
import { normalizeRoot } from './paths.mjs';
import { HttpError } from '../http.mjs';

import os from 'node:os';
const PROTOCOLS = new Set(['sftp', 'ftp', 'ftps', 'local']);
const RUNTIMES = new Set(['remote', 'local']);
const HOST_RE = /^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

function localAddresses() {
  const out = new Set();
  try { out.add(String(os.hostname()).toLowerCase()); } catch { /* ignore */ }
  try {
    for (const list of Object.values(os.networkInterfaces())) {
      for (const item of list ?? []) if (item?.address) out.add(String(item.address).toLowerCase());
    }
  } catch { /* ignore */ }
  return out;
}

/**
 * Local runtime is an explicit property of the saved node. It is never guessed
 * from a loopback-looking host, because a real SSH server can legitimately run
 * on 127.0.0.1 (tests, bastion). Primary detection happens once, in
 * ensurePrimaryNode(), using the backend's own identity.
 */
export function isLocalRuntime(row) {
  if (!row) return false;
  const runtime = String(row.runtime ?? '').toLowerCase();
  if (runtime === 'local' || runtime === 'primary') return true;
  return String(row.protocol ?? '').toLowerCase() === 'local';
}

/** Hosts that identify this machine (used once, when adopting the Primary Node). */
export async function primaryHostIdentities() {
  const out = localAddresses();
  try {
    const base = new URL(config.publicBaseUrl).hostname.toLowerCase();
    out.add(base);
    const { lookup } = await import('node:dns/promises');
    for (const item of await lookup(base, { all: true }).catch(() => [])) out.add(String(item.address).toLowerCase());
  } catch { /* no public url */ }
  for (const extra of [process.env.PRIMARY_HOST, process.env.PUBLIC_HOST, process.env.PRIMARY_HOSTNAME]) {
    if (extra) out.add(String(extra).trim().toLowerCase());
  }
  return out;
}

/**
 * Adopt (or create) the Primary Node record. The primary VPS must be reached
 * through the local runtime — never SSH to itself — so anything that identifies
 * this host is converted once, preserving its history and files.
 */
export async function ensurePrimaryNode() {
  const identities = await primaryHostIdentities();
  const now = Date.now();
  const existingLocal = query.get("SELECT * FROM remote_servers WHERE runtime = 'local' OR protocol = 'local' ORDER BY created_at LIMIT 1");
  if (existingLocal) {
    query.run(
      "UPDATE remote_servers SET last_status = 'connected', last_error = NULL, runtime = 'local', runtime_kind = 'primary', host = '127.0.0.1', port = 0, protocol = 'local', auth_type = 'local', updated_at = ? WHERE id = ?",
      now,
      existingLocal.id,
    );
    return query.get('SELECT * FROM remote_servers WHERE id = ?', existingLocal.id);
  }

  const rows = query.all("SELECT * FROM remote_servers WHERE runtime <> 'local'");
  const match = rows.find((row) => identities.has(String(row.host ?? '').trim().toLowerCase()));
  if (match) {
    query.run(
      "UPDATE remote_servers SET runtime = 'local', runtime_kind = 'primary', protocol = 'local', host = '127.0.0.1', port = 0, auth_type = 'local', host_fingerprint = NULL, last_status = 'connected', last_error = NULL, updated_at = ? WHERE id = ?",
      now,
      match.id,
    );
    audit('system', 'remote.primary.adopted', match.id, { from: match.host, runtime: 'local' });
    recordEvent({ serverId: match.id, protocol: 'local', event: 'server.adopted', status: 'connected', detail: 'local-runtime', actor: 'system' });
    return query.get('SELECT * FROM remote_servers WHERE id = ?', match.id);
  }

  const id = crypto.randomUUID();
  query.run(
    `INSERT INTO remote_servers (id, name, protocol, host, port, username, auth_type, password_encrypted,
       private_key_encrypted, passphrase_encrypted, host_fingerprint, remote_root, connect_timeout_ms,
       is_default, last_status, last_error, created_at, updated_at, runtime, runtime_kind)
     VALUES (?, 'Primary VPS', 'local', '127.0.0.1', 0, ?, 'local', NULL, NULL, NULL, NULL, '/', 15000, 1, 'connected', NULL, ?, ?, 'local', 'primary')`,
    id,
    process.env.USER || 'root',
    now,
    now,
  );
  recordEvent({ serverId: id, protocol: 'local', event: 'server.created', status: 'connected', detail: 'local-runtime', actor: 'system' });
  return query.get('SELECT * FROM remote_servers WHERE id = ?', id);
}

/** Remote control is device-token only: API keys may not touch other machines. */
export function requireDeviceAuth(auth) {
  if (!auth) throw new HttpError(401, 'Token akses diperlukan.', 'MISSING_TOKEN');
  if (auth.apiKey) {
    throw new HttpError(403, 'Remote Control membutuhkan token device, bukan API key.', 'DEVICE_TOKEN_REQUIRED');
  }
  return auth;
}

export function validateHost(host, { allowLocal = false } = {}) {
  const value = String(host ?? '').trim();
  if (allowLocal && (!value || ['127.0.0.1', 'localhost', '::1'].includes(value.toLowerCase()))) return value || '127.0.0.1';
  if (!value || value.length > 253) throw new HttpError(400, 'Host tidak valid.', 'VALIDATION');
  if (IPV6_RE.test(value) && value.includes(':')) return value;
  if (!HOST_RE.test(value)) throw new HttpError(400, 'Host tidak valid (gunakan hostname atau IP).', 'VALIDATION');
  return value;
}

function boolInt(value) {
  return value === true || value === 1 || value === '1' || value === 'true' ? 1 : 0;
}

function serverRow(id) {
  const row = query.get('SELECT * FROM remote_servers WHERE id = ?', id);
  if (!row) throw new HttpError(404, 'Server remote tidak ditemukan.', 'REMOTE_SERVER_NOT_FOUND');
  return row;
}

function connectionSummary(serverId) {
  const last = query.get('SELECT event, status, detail, created_at FROM remote_connection_events WHERE server_id = ? ORDER BY created_at DESC LIMIT 1', serverId);
  return last
    ? { event: last.event, status: last.status, detail: last.detail, at: last.created_at }
    : null;
}

/** Public shape: no secrets, only whether they exist and a masked hint. */
export function publicServer(row) {
  const local = isLocalRuntime(row);
  const password = local ? null : (row.password_encrypted ? 'password' : null);
  const key = local ? null : (row.private_key_encrypted ? 'key' : null);
  return {
    id: row.id,
    name: row.name,
    protocol: local ? 'local' : row.protocol,
    runtime: local ? 'local' : 'remote',
    nodeKind: local ? 'primary' : 'remote',
    host: local ? '127.0.0.1' : row.host,
    port: local ? 0 : row.port,
    username: local ? (process.env.USER || row.username || 'root') : row.username,
    authType: local ? 'local' : row.auth_type,
    hasPassword: local ? false : Boolean(row.password_encrypted),
    hasPrivateKey: local ? false : Boolean(row.private_key_encrypted),
    hasPassphrase: local ? false : Boolean(row.passphrase_encrypted),
    credential: password ?? key,
    hostFingerprint: local ? null : row.host_fingerprint,
    remoteRoot: row.remote_root,
    connectTimeoutMs: row.connect_timeout_ms,
    isDefault: Boolean(row.is_default),
    lastStatus: local ? 'connected' : row.last_status,
    lastError: local ? null : row.last_error,
    lastConnectedAt: local ? (row.last_connected_at ?? Date.now()) : row.last_connected_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastEvent: connectionSummary(row.id),
    supportsTerminal: local || row.protocol === 'sftp',
    isPrimary: local,
    isLocal: local,
  };
}

export function listServers() {
  const rows = query.all('SELECT * FROM remote_servers ORDER BY is_default DESC, name COLLATE NOCASE');
  return rows.map(publicServer);
}

export function getServerRow(id) {
  return serverRow(id);
}

export function defaultServerId() {
  const row = query.get('SELECT id FROM remote_servers WHERE is_default = 1 LIMIT 1');
  if (row) return row.id;
  const any = query.get('SELECT id FROM remote_servers ORDER BY created_at LIMIT 1');
  return any?.id ?? null;
}

/** Decrypted connection material. Never leaves the backend. */
export function serverCredentials(row) {
  return {
    password: row.password_encrypted ? decryptSecret(row.password_encrypted) : null,
    privateKey: row.private_key_encrypted ? decryptSecret(row.private_key_encrypted) : null,
    passphrase: row.passphrase_encrypted ? decryptSecret(row.passphrase_encrypted) : null,
  };
}

function validateInput(body, { existing = null, partial = false } = {}) {
  const out = {};
  const pick = (key) => (body[key] === undefined ? undefined : body[key]);

  const runtimeRaw = pick('runtime') ?? (body?.protocol === 'local' ? 'local' : (existing?.runtime ?? 'remote'));
  const runtime = String(runtimeRaw ?? 'remote').toLowerCase();
  if (!RUNTIMES.has(runtime)) throw new HttpError(400, 'runtime harus remote atau local.', 'VALIDATION');
  out.runtime = runtime;

  const name = pick('name');
  if (name !== undefined || !partial) {
    const value = String(name ?? existing?.name ?? (runtime === 'local' ? 'Primary VPS' : '')).trim();
    if (value.length < 1 || value.length > 80) throw new HttpError(400, 'Nama server harus 1-80 karakter.', 'VALIDATION');
    out.name = value;
  }

  const protocol = pick('protocol');
  if (protocol !== undefined || !partial || runtime === 'local') {
    const value = runtime === 'local' ? 'local' : String(protocol ?? existing?.protocol ?? 'sftp').toLowerCase();
    if (!PROTOCOLS.has(value)) throw new HttpError(400, 'Protocol harus sftp, ftp, ftps, atau local.', 'VALIDATION');
    out.protocol = value;
  }

  const host = pick('host');
  if (runtime === 'local') {
    out.host = '127.0.0.1';
  } else if (host !== undefined || !partial) {
    out.host = validateHost(host ?? existing?.host);
  }

  const port = pick('port');
  if (runtime === 'local') {
    out.port = 0;
  } else if (port !== undefined || !partial) {
    const protocolValue = out.protocol ?? existing?.protocol ?? 'sftp';
    const fallback = protocolValue === 'sftp' ? 22 : 21;
    const value = Number(port ?? existing?.port ?? fallback);
    if (!Number.isInteger(value) || value < 1 || value > 65535) throw new HttpError(400, 'Port tidak valid (1-65535).', 'VALIDATION');
    out.port = value;
  }

  const username = pick('username');
  if (runtime === 'local') {
    out.username = String(username ?? existing?.username ?? process.env.USER ?? 'root').trim() || 'root';
  } else if (username !== undefined || !partial) {
    const value = String(username ?? existing?.username ?? '').trim();
    if (!value || value.length > 64) throw new HttpError(400, 'Username wajib diisi (1-64 karakter).', 'VALIDATION');
    out.username = value;
  }

  const authType = pick('authType');
  if (runtime === 'local') {
    out.authType = 'local';
  } else if (authType !== undefined || !partial) {
    const value = String(authType ?? existing?.auth_type ?? 'password').toLowerCase();
    if (!['password', 'key'].includes(value)) throw new HttpError(400, 'authType harus password atau key.', 'VALIDATION');
    out.authType = value;
  }

  const root = pick('remoteRoot');
  if (root !== undefined || !partial) out.remoteRoot = normalizeRoot(root ?? existing?.remote_root ?? '/');

  const timeout = pick('connectTimeoutMs');
  if (timeout !== undefined || !partial) {
    const value = Number(timeout ?? existing?.connect_timeout_ms ?? 15000);
    if (!Number.isFinite(value) || value < 2000 || value > 60000) {
      throw new HttpError(400, 'connectTimeoutMs harus 2000-60000.', 'VALIDATION');
    }
    out.connectTimeoutMs = Math.round(value);
  }

  if (body.hostFingerprint !== undefined) {
    if (runtime === 'local' || body.hostFingerprint === null || body.hostFingerprint === '') out.hostFingerprint = null;
    else {
      const normalized = normalizeFingerprint(body.hostFingerprint);
      if (!normalized) throw new HttpError(400, 'Fingerprint harus format SHA256:<base64>.', 'VALIDATION');
      out.hostFingerprint = normalized;
    }
  } else if (runtime === 'local') {
    out.hostFingerprint = null;
  }

  if (body.password !== undefined) out.password = body.password ? String(body.password) : null;
  if (body.privateKey !== undefined) out.privateKey = body.privateKey ? String(body.privateKey) : null;
  if (body.passphrase !== undefined) out.passphrase = body.passphrase ? String(body.passphrase) : null;
  if (body.isDefault !== undefined) out.isDefault = boolInt(body.isDefault);
  if (runtime === 'local') {
    out.password = null; out.privateKey = null; out.passphrase = null;
  }
  out.runtimeKind = runtime === 'local' ? 'primary' : null;
  return out;
}

function recordEvent({ serverId, protocol = null, event, status = null, detail = null, actor = 'owner' }) {
  query.run(
    'INSERT INTO remote_connection_events (id, server_id, protocol, event, status, detail, actor, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    crypto.randomUUID(),
    serverId,
    protocol,
    event,
    status,
    detail ? String(detail).slice(0, 500) : null,
    actor,
    Date.now(),
  );
}

export { recordEvent };

export function createServer(body, auth) {
  requireDeviceAuth(auth);
  const input = validateInput(body);
  if (!input.name) throw new HttpError(400, 'Nama server wajib.', 'VALIDATION');
  if (input.runtime !== 'local') {
    if (input.authType === 'password' && !input.password) {
      throw new HttpError(400, 'Password SSH wajib untuk authType=password.', 'VALIDATION');
    }
    if (input.authType === 'key' && !input.privateKey) {
      throw new HttpError(400, 'Private key wajib untuk authType=key.', 'VALIDATION');
    }
    if (input.protocol === 'sftp' && input.authType === 'key' && !/BEGIN [A-Z ]*PRIVATE KEY/.test(input.privateKey)) {
      throw new HttpError(400, 'Private key tidak dikenali (harus PEM/OpenSSH).', 'VALIDATION');
    }
  }
  const id = crypto.randomUUID();
  const now = Date.now();
  if (input.isDefault) query.run('UPDATE remote_servers SET is_default = 0');
  const status = input.runtime === 'local' ? 'connected' : 'unknown';
  query.run(
    `INSERT INTO remote_servers (id, name, protocol, host, port, username, auth_type, password_encrypted,
       private_key_encrypted, passphrase_encrypted, host_fingerprint, remote_root, connect_timeout_ms,
       is_default, last_status, last_error, created_at, updated_at, runtime, runtime_kind)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)`,
    id,
    input.name,
    input.protocol,
    input.host,
    input.port,
    input.username,
    input.authType,
    encryptSecret(input.password ?? null),
    encryptSecret(input.privateKey ?? null),
    encryptSecret(input.passphrase ?? null),
    input.hostFingerprint ?? null,
    input.remoteRoot,
    input.connectTimeoutMs,
    input.isDefault ?? (query.get('SELECT COUNT(*) AS c FROM remote_servers').c === 0 ? 1 : 0),
    status,
    now,
    now,
    input.runtime,
    input.runtimeKind ?? null,
  );
  audit(auth.deviceId, 'remote.server.created', id, { host: input.host, port: input.port, protocol: input.protocol, runtime: input.runtime });
  recordEvent({ serverId: id, protocol: input.protocol, event: 'server.created', actor: auth.deviceName ?? auth.deviceId });
  return publicServer(serverRow(id));
}

export function updateServer(id, body, auth) {
  requireDeviceAuth(auth);
  const existing = serverRow(id);
  const input = validateInput(body, { existing, partial: true });
  const sets = [];
  const params = [];
  const map = {
    name: 'name',
    protocol: 'protocol',
    host: 'host',
    port: 'port',
    username: 'username',
    authType: 'auth_type',
    remoteRoot: 'remote_root',
    connectTimeoutMs: 'connect_timeout_ms',
    hostFingerprint: 'host_fingerprint',
    isDefault: 'is_default',
    runtime: 'runtime',
    runtimeKind: 'runtime_kind',
  };
  for (const [key, column] of Object.entries(map)) {
    if (input[key] === undefined) continue;
    sets.push(`${column} = ?`);
    params.push(input[key]);
  }
  if (input.password !== undefined) {
    sets.push('password_encrypted = ?');
    params.push(encryptSecret(input.password));
  }
  if (input.privateKey !== undefined) {
    sets.push('private_key_encrypted = ?');
    params.push(encryptSecret(input.privateKey));
  }
  if (input.passphrase !== undefined) {
    sets.push('passphrase_encrypted = ?');
    params.push(encryptSecret(input.passphrase));
  }
  if (input.runtime === 'local') {
    sets.push('password_encrypted = ?'); params.push(null);
    sets.push('private_key_encrypted = ?'); params.push(null);
    sets.push('passphrase_encrypted = ?'); params.push(null);
    sets.push('host_fingerprint = ?'); params.push(null);
    sets.push('last_status = ?'); params.push('connected');
    sets.push('last_error = ?'); params.push(null);
  }
  if (!sets.length) return publicServer(existing);
  if (input.isDefault) query.run('UPDATE remote_servers SET is_default = 0 WHERE id <> ?', id);
  sets.push('updated_at = ?');
  params.push(Date.now(), id);
  query.run(`UPDATE remote_servers SET ${sets.join(', ')} WHERE id = ?`, ...params);
  audit(auth.deviceId, 'remote.server.updated', id, { fields: Object.keys(input) });
  recordEvent({ serverId: id, protocol: input.protocol ?? existing.protocol, event: 'server.updated', actor: auth.deviceName ?? auth.deviceId });
  return publicServer(serverRow(id));
}

export function deleteServer(id, auth) {
  requireDeviceAuth(auth);
  const existing = serverRow(id);
  query.run('DELETE FROM remote_servers WHERE id = ?', id);
  if (existing.is_default) {
    const next = query.get('SELECT id FROM remote_servers ORDER BY created_at LIMIT 1');
    if (next) query.run('UPDATE remote_servers SET is_default = 1 WHERE id = ?', next.id);
  }
  // History survives the server so the audit trail stays intact.
  recordEvent({ serverId: id, protocol: existing.protocol, event: 'server.deleted', status: 'deleted', actor: auth.deviceName ?? auth.deviceId });
  audit(auth.deviceId, 'remote.server.deleted', id, { host: existing.host });
  return { deleted: true, id };
}

export function setServerStatus(id, { status, error = null, connectedAt = null }) {
  query.run(
    'UPDATE remote_servers SET last_status = ?, last_error = ?, last_connected_at = COALESCE(?, last_connected_at), updated_at = ? WHERE id = ?',
    status,
    error ? String(error).slice(0, 500) : null,
    connectedAt,
    Date.now(),
    id,
  );
}

export function listConnectionHistory({ serverId = null, limit = 50 } = {}) {
  const rows = serverId
    ? query.all('SELECT * FROM remote_connection_events WHERE server_id = ? ORDER BY created_at DESC LIMIT ?', serverId, limit)
    : query.all('SELECT * FROM remote_connection_events ORDER BY created_at DESC LIMIT ?', limit);
  return rows.map((row) => ({
    id: row.id,
    serverId: row.server_id,
    protocol: row.protocol,
    event: row.event,
    status: row.status,
    detail: row.detail,
    actor: row.actor,
    createdAt: row.created_at,
  }));
}

export function credentialHint(row) {
  const material = serverCredentials(row);
  return secretHint(material.password ?? material.privateKey);
}
