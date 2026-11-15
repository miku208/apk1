// Connection manager shared by the file manager and the terminal.
// One live SSH/FTP connection per saved server, host-key pinned, with status
// and connection history recorded for the UI.
import fs from 'node:fs';
import ssh2 from 'ssh2';
import { Client as FtpClient } from 'basic-ftp';
import { config } from '../config.mjs';
import { logger } from '../logger.mjs';
import { HttpError } from '../http.mjs';
import { createHostVerifier, fingerprintFromKeyBlob, HostKeyMismatchError, normalizeFingerprint } from './fingerprint.mjs';
import { createSftpAdapter } from './sftp-adapter.mjs';
import { createFtpAdapter } from './ftp-adapter.mjs';
import { createLocalAdapter } from './local-adapter.mjs';
import { localNodeInfo } from './local-runtime.mjs';
import {
  getServerRow,
  isLocalRuntime,
  listServers,
  publicServer,
  recordEvent,
  serverCredentials,
  setServerStatus,
} from './servers.mjs';

const { Client: SshClient } = ssh2;

/** serverId -> { adapter, status, lastError, connectedAt, fingerprint, idleTimer } */
const pool = new Map();

function stateFor(serverId) {
  return pool.get(serverId) ?? null;
}

export function liveConnections() {
  const out = [];
  for (const [serverId, state] of pool.entries()) {
    const row = getServerRow(serverId);
    out.push({
      serverId,
      name: row.name,
      protocol: row.protocol,
      status: state.status,
      connectedAt: state.connectedAt ?? null,
      lastError: state.lastError ?? null,
      fingerprint: state.fingerprint ?? row.host_fingerprint ?? null,
    });
  }
  return out;
}

function touchIdle(serverId) {
  const state = pool.get(serverId);
  if (!state) return;
  state.lastUsedAt = Date.now();
  if (state.idleTimer) clearTimeout(state.idleTimer);
  state.idleTimer = setTimeout(() => {
    if (state.adapter?.supportsTerminal === false && Date.now() - (state.lastUsedAt ?? 0) >= config.remoteIdleTimeoutMs) {
      closeServer(serverId, 'idle-timeout');
    }
  }, config.remoteIdleTimeoutMs + 1000);
  state.idleTimer.unref?.();
}

export function closeServer(serverId, reason = 'manual') {
  const state = pool.get(serverId);
  if (!state) return false;
  if (state.idleTimer) clearTimeout(state.idleTimer);
  try {
    state.adapter?.close();
  } catch (error) {
    logger.debug('remote close failed', String(error?.message ?? error));
  }
  pool.delete(serverId);
  recordEvent({ serverId, event: 'connection.closed', status: 'closed', detail: reason, actor: 'system' });
  setServerStatus(serverId, { status: 'disconnected' });
  return true;
}

export function closeAllConnections() {
  for (const serverId of Array.from(pool.keys())) closeServer(serverId, 'shutdown');
}

/**
 * Read the host key fingerprint without authenticating. The verifier always
 * returns false, so no credentials are ever sent to an unverified host.
 */
export function probeHostKey(row) {
  return new Promise((resolve) => {
    const client = new SshClient();
    let seen = null;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      try {
        client.end();
      } catch {
        /* ignore */
      }
      resolve(seen);
    };
    const timer = setTimeout(finish, Math.min(row.connect_timeout_ms ?? 15000, 15000));
    timer.unref?.();
    client.on('error', finish);
    client.on('close', finish);
    client.on('ready', () => {
      // Should not happen because the verifier rejects, but keep it safe.
      finish();
    });
    try {
      client.connect({
        host: row.host,
        port: row.port,
        username: row.username,
        readyTimeout: row.connect_timeout_ms ?? 15000,
        hostVerifier: (keyBlob) => {
          seen = fingerprintFromKeyBlob(keyBlob);
          return false;
        },
        // Never let ssh2 fall back to weaker authentication silently.
        tryKeyboard: false,
      });
    } catch {
      finish();
    }
  });
}

async function openSsh(row) {
  if (!row.host_fingerprint) {
    const fingerprint = await probeHostKey(row);
    const error = new HttpError(
      409,
      fingerprint
        ? 'Host key server belum dipercaya. Periksa fingerprint lalu simpan untuk mengaktifkan koneksi.'
        : 'Tidak bisa membaca host key server.',
      'HOST_KEY_UNTRUSTED',
      { fingerprint, requiresTrust: Boolean(fingerprint) },
    );
    throw error;
  }

  const credentials = serverCredentials(row);
  if (row.auth_type === 'key' && !credentials.privateKey) {
    throw new HttpError(400, 'Private key server belum tersimpan.', 'MISSING_CREDENTIAL');
  }
  if (row.auth_type === 'password' && !credentials.password) {
    throw new HttpError(400, 'Password server belum tersimpan.', 'MISSING_CREDENTIAL');
  }

  let seenFingerprint = null;
  const client = new SshClient();
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      try {
        client.end();
      } catch {
        /* ignore */
      }
      reject(new HttpError(504, 'Koneksi SSH melewati batas waktu.', 'REMOTE_TIMEOUT'));
    }, (row.connect_timeout_ms ?? 15000) + 2000);
    timer.unref?.();

    client.on('ready', () => {
      clearTimeout(timer);
      resolve();
    });
    client.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    try {
      client.connect({
        host: row.host,
        port: row.port,
        username: row.username,
        readyTimeout: row.connect_timeout_ms ?? 15000,
        keepaliveInterval: 10000,
        keepaliveCountMax: 3,
        hostVerifier: createHostVerifier(row.host_fingerprint, (fp) => {
          seenFingerprint = fp;
        }),
        ...(row.auth_type === 'key'
          ? { privateKey: credentials.privateKey, ...(credentials.passphrase ? { passphrase: credentials.passphrase } : {}) }
          : { password: credentials.password }),
      });
    } catch (error) {
      clearTimeout(timer);
      reject(error);
    }
  }).catch(async (error) => {
    const message = String(error?.message ?? error);
    if (/host denied|verification failed|host key/i.test(message) || error?.level === 'client-verification') {
      AUDIT_HOSTKEYS.set(row.id, seenFingerprint);
      throw new HostKeyMismatchError({ expected: row.host_fingerprint, actual: seenFingerprint });
    }
    if (error?.level === 'client-authentication') {
      throw new HttpError(401, 'Autentikasi SSH gagal: periksa username, password, atau private key.', 'REMOTE_AUTH_FAILED');
    }
    throw error;
  });

  const sftp = await new Promise((resolve, reject) => {
    client.sftp((error, wrapper) => (error ? reject(error) : resolve(wrapper)));
  });
  const adapter = createSftpAdapter({ client, sftp, server: row });
  adapter.onClose = () => {
    const state = pool.get(row.id);
    if (state?.adapter === adapter) {
      pool.delete(row.id);
      setServerStatus(row.id, { status: 'disconnected' });
    }
  };
  client.on('close', () => adapter.onClose?.());
  client.on('error', (error) => {
    const state = pool.get(row.id);
    if (state) {
      state.lastError = String(error?.message ?? error);
      state.status = 'error';
    }
    logger.warn('remote ssh error', { server: row.name, message: String(error?.message ?? error) });
  });
  return adapter;
}

const AUDIT_HOSTKEYS = new Map();
export function observedHostKeys() {
  return new Map(AUDIT_HOSTKEYS);
}

async function openFtp(row) {
  const credentials = serverCredentials(row);
  if (!credentials.password) throw new HttpError(400, 'Password FTP belum tersimpan.', 'MISSING_CREDENTIAL');
  const client = new FtpClient(Math.max(row.connect_timeout_ms ?? 15000, 5000));
  client.ftp.verbose = false;
  // FTPS keeps certificate validation on; a private CA can be trusted via file.
  let secureOptions = { rejectUnauthorized: true };
  if (row.protocol === 'ftps' && config.remoteFtpsCaFile) {
    secureOptions = { ...secureOptions, ca: fs.readFileSync(config.remoteFtpsCaFile, 'utf8') };
  }
  await client.access({
    host: row.host,
    port: row.port,
    user: row.username,
    password: credentials.password,
    secure: row.protocol === 'ftps',
    secureOptions,
  });
  const adapter = createFtpAdapter({ client, server: row, secure: row.protocol === 'ftps' });
  return adapter;
}

export async function connectServer(serverId, { force = false } = {}) {
  const row = getServerRow(serverId);
  const local = isLocalRuntime(row);
  const existing = pool.get(serverId);
  if (existing && !force && existing.status === 'connected' && !existing.adapter.closed) {
    touchIdle(serverId);
    return existing.adapter;
  }
  if (existing) closeServer(serverId, 'reconnect');

  const state = { adapter: null, status: local ? 'connected' : 'connecting', lastError: null, connectedAt: local ? Date.now() : null, fingerprint: local ? null : row.host_fingerprint };
  pool.set(serverId, state);

  // Primary VPS: native local runtime, never SSH/SFTP to this host.
  if (local) {
    const adapter = createLocalAdapter({ server: row });
    state.adapter = adapter;
    state.status = 'connected';
    state.connectedAt = Date.now();
    state.lastError = null;
    setServerStatus(serverId, { status: 'connected', connectedAt: state.connectedAt, error: null });
    recordEvent({ serverId, protocol: 'local', event: 'connection.opened', status: 'connected', detail: 'local-runtime', actor: 'system' });
    return adapter;
  }

  recordEvent({ serverId, protocol: row.protocol, event: 'connection.opening', status: 'connecting', actor: 'owner' });
  try {
    const adapter = row.protocol === 'sftp' ? await openSsh(row) : await openFtp(row);
    state.adapter = adapter;
    state.status = 'connected';
    state.connectedAt = Date.now();
    state.lastError = null;
    setServerStatus(serverId, { status: 'connected', connectedAt: state.connectedAt });
    recordEvent({ serverId, protocol: row.protocol, event: 'connection.opened', status: 'connected', actor: 'owner' });
    touchIdle(serverId);
    return adapter;
  } catch (error) {
    state.status = 'error';
    state.lastError = String(error?.message ?? error);
    setServerStatus(serverId, { status: 'error', error: state.lastError });
    recordEvent({
      serverId,
      protocol: row.protocol,
      event: 'connection.failed',
      status: 'error',
      detail: error?.detail?.actual ? `${state.lastError} (host key: ${error.detail.actual})` : state.lastError,
      actor: 'owner',
    });
    pool.delete(serverId);
    throw error;
  }
}

export async function getAdapter(serverId) {
  const adapter = await connectServer(serverId);
  touchIdle(serverId);
  return adapter;
}

/** Test a saved server. Local runtime connects natively; remote servers verify host key first. */
export async function testServer(serverId) {
  const row = getServerRow(serverId);
  const startedAt = Date.now();
  if (isLocalRuntime(row)) {
    try {
      const adapter = await connectServer(serverId, { force: true });
      const root = row.remote_root || '/';
      const entries = await adapter.list(root);
      return {
        ok: true,
        runtime: 'local',
        protocol: 'local',
        needsTrust: false,
        fingerprint: null,
        latencyMs: Date.now() - startedAt,
        root,
        entries: entries.length,
        server: publicServer(getServerRow(serverId)),
        status: 'connected',
        message: 'Primary VPS terhubung melalui Local Runtime.',
      };
    } catch (error) {
      return {
        ok: false,
        runtime: 'local',
        protocol: 'local',
        needsTrust: false,
        message: String(error?.message ?? error),
        code: error?.code ?? 'LOCAL_RUNTIME_FAILED',
        latencyMs: Date.now() - startedAt,
      };
    }
  }
  if (row.protocol === 'sftp' && !row.host_fingerprint) {
    const fingerprint = await probeHostKey(row);
    recordEvent({
      serverId,
      protocol: row.protocol,
      event: 'connection.probed',
      status: 'untrusted',
      detail: fingerprint ?? 'host key tidak terbaca',
      actor: 'owner',
    });
    return {
      ok: false,
      needsTrust: Boolean(fingerprint),
      fingerprint,
      hostFingerprint: null,
      message: fingerprint
        ? 'Host key diterima dari server. Cocokkan fingerprint lalu simpan untuk mempercayai server ini.'
        : 'Host key server tidak terbaca.',
      latencyMs: Date.now() - startedAt,
    };
  }
  try {
    const adapter = await connectServer(serverId, { force: true });
    const root = row.remote_root || '/';
    const entries = await adapter.list(root);
    const status = 'connected';
    return {
      ok: true,
      needsTrust: false,
      fingerprint: row.host_fingerprint,
      latencyMs: Date.now() - startedAt,
      protocol: row.protocol,
      root,
      entries: entries.length,
      server: publicServer(getServerRow(serverId)),
      status,
    };
  } catch (error) {
    return {
      ok: false,
      needsTrust: error?.code === 'HOST_KEY_UNTRUSTED',
      fingerprint: error?.detail?.actual ?? error?.detail?.fingerprint ?? null,
      expectedFingerprint: row.host_fingerprint ?? null,
      message: String(error?.message ?? error),
      code: error?.code ?? 'CONNECTION_FAILED',
      latencyMs: Date.now() - startedAt,
    };
  }
}

export function connectionOverview() {
  const servers = listServers();
  const live = new Map(liveConnections().map((item) => [item.serverId, item]));
  return servers.map((server) => {
    const connection = live.get(server.id) ?? {
      serverId: server.id,
      status: server.lastStatus === 'connected' ? 'disconnected' : server.lastStatus ?? 'unknown',
      connectedAt: null,
      lastError: server.lastError,
      fingerprint: server.hostFingerprint,
    };
    if (server.isLocal) {
      return {
        ...server,
        connection: {
          ...connection,
          status: 'connected',
          runtime: 'local',
          protocol: 'local',
          lastError: null,
          fingerprint: null,
        },
      };
    }
    return { ...server, connection };
  });
}

/** Attach live Primary Node identity to a local server entry. */
export async function withNodeInfo(server) {
  if (!server?.isLocal) return server;
  const info = await localNodeInfo();
  return { ...server, node: info, connection: { ...(server.connection ?? {}), status: 'connected', runtime: 'local' } };
}

export function saveTrustedFingerprint(serverId, fingerprint) {
  const normalized = normalizeFingerprint(fingerprint);
  if (!normalized) throw new HttpError(400, 'Fingerprint tidak valid.', 'VALIDATION');
  return normalized;
}
