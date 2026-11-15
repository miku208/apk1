// Interactive PTY sessions over SSH. One shell process per session, state kept
// between commands, output buffered with a hard cap and mirrored to the phone
// over the shared WebSocket.
import crypto from 'node:crypto';
import { StringDecoder } from 'node:string_decoder';
import { config } from '../config.mjs';
import { logger } from '../logger.mjs';
import { query } from '../db.mjs';
import { emitEvent, recordActivity } from '../events.mjs';
import { audit } from '../auth.mjs';
import { HttpError } from '../http.mjs';
import { getAdapter } from './connection.mjs';
import { getServerRow } from './servers.mjs';
import { normalizeRoot, posix, resolveRemotePath } from './paths.mjs';

const sessions = new Map();
let sweeper = null;

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function emit(session, type, payload) {
  emitEvent(type, {
    sessionId: session.id,
    serverId: session.serverId,
    deviceId: session.deviceId,
    ...payload,
  });
}

function publicSession(session) {
  return {
    id: session.id,
    serverId: session.serverId,
    serverName: session.serverName,
    deviceId: session.deviceId,
    shell: session.shell,
    cwd: session.cwd,
    cols: session.cols,
    rows: session.rows,
    status: session.status,
    ptyPid: session.ptyPid,
    bufferBytes: session.bufferBytes,
    createdAt: session.createdAt,
    lastActivity: session.lastActivity,
    closedAt: session.closedAt,
  };
}

function appendBuffer(session, text) {
  if (!text) return;
  session.chunks.push(text);
  session.bufferBytes += Buffer.byteLength(text);
  while (session.bufferBytes > config.remoteTerminalBufferBytes && session.chunks.length > 1) {
    const removed = session.chunks.shift();
    session.bufferBytes -= Buffer.byteLength(removed);
  }
  if (session.bufferBytes > config.remoteTerminalBufferBytes) {
    // A single huge chunk: keep the tail only.
    const joined = session.chunks.join('');
    const tail = joined.slice(-Math.floor(config.remoteTerminalBufferBytes / 2));
    session.chunks = [tail];
    session.bufferBytes = Buffer.byteLength(tail);
  }
}

export function sessionBuffer(id) {
  const session = sessions.get(id);
  if (!session) return null;
  return session.chunks.join('');
}

export function listSessions({ serverId = null } = {}) {
  const rows = serverId
    ? query.all('SELECT * FROM remote_terminal_sessions WHERE server_id = ? ORDER BY created_at DESC LIMIT 50', serverId)
    : query.all('SELECT * FROM remote_terminal_sessions ORDER BY created_at DESC LIMIT 50');
  return rows.map((row) => {
    const live = sessions.get(row.id);
    return {
      id: row.id,
      serverId: row.server_id,
      deviceId: row.device_id,
      shell: row.shell,
      cwd: row.cwd,
      cols: row.cols,
      rows: row.rows,
      status: live ? live.status : row.status === 'active' ? 'disconnected' : row.status,
      ptyPid: row.pty_pid,
      bufferBytes: row.buffer_bytes,
      createdAt: row.created_at,
      lastActivity: row.last_activity,
      closedAt: row.closed_at,
      closeReason: row.close_reason,
      live: Boolean(live),
    };
  });
}

export function getSession(id, { deviceId = null } = {}) {
  const row = query.get('SELECT * FROM remote_terminal_sessions WHERE id = ?', id);
  if (!row) throw new HttpError(404, 'Session terminal tidak ditemukan.', 'TERMINAL_SESSION_NOT_FOUND');
  const live = sessions.get(id);
  if (row.device_id && deviceId && row.device_id !== deviceId) {
    throw new HttpError(403, 'Session ini milik device lain.', 'TERMINAL_SESSION_FORBIDDEN');
  }
  return {
    ...publicSession({
      id: row.id,
      serverId: row.server_id,
      serverName: getServerName(row.server_id),
      deviceId: row.device_id,
      shell: row.shell,
      cwd: row.cwd,
      cols: row.cols,
      rows: row.rows,
      status: live ? live.status : row.status === 'active' ? 'disconnected' : row.status,
      ptyPid: row.pty_pid,
      bufferBytes: live ? live.bufferBytes : row.buffer_bytes,
      createdAt: row.created_at,
      lastActivity: live ? live.lastActivity : row.last_activity,
      closedAt: row.closed_at,
    }),
    live: Boolean(live),
    buffer: live ? live.chunks.join('') : null,
  };
}

function getServerName(serverId) {
  try {
    return getServerRow(serverId).name;
  } catch {
    return null;
  }
}

export async function createSession({ serverId, deviceId, userId = null, cwd = null, cols = 80, rows = 24, shell = null }) {
  const row = getServerRow(serverId);
  if (row.protocol !== 'sftp') {
    throw new HttpError(400, 'Terminal interaktif membutuhkan server SSH/SFTP.', 'TERMINAL_UNSUPPORTED');
  }
  const activeForDevice = Array.from(sessions.values()).filter((session) => session.deviceId === deviceId && session.status === 'active');
  if (activeForDevice.length >= config.remoteTerminalMaxSessions) {
    throw new HttpError(429, `Maksimal ${config.remoteTerminalMaxSessions} session aktif per device. Tutup salah satu dulu.`, 'TERMINAL_LIMIT');
  }

  const root = normalizeRoot(row.remote_root);
  let workingDirectory = root;
  if (cwd) workingDirectory = resolveRemotePath({ root, target: cwd });

  const adapter = await getAdapter(serverId);
  const safeCols = Math.max(20, Math.min(400, Number(cols) || 80));
  const safeRows = Math.max(5, Math.min(200, Number(rows) || 24));
  const stream = await adapter.shell({ cols: safeCols, rows: safeRows, term: 'xterm-256color' });

  const id = crypto.randomUUID();
  const now = Date.now();
  const session = {
    id,
    serverId,
    serverName: row.name,
    deviceId,
    userId,
    shell: shell ?? 'default',
    cwd: workingDirectory,
    cols: safeCols,
    rows: safeRows,
    status: 'active',
    ptyPid: null,
    chunks: [],
    bufferBytes: 0,
    createdAt: now,
    lastActivity: now,
    stream,
    adapter,
    decoder: new StringDecoder('utf8'),
    markerPending: true,
    pending: '',
    closedAt: null,
  };
  sessions.set(id, session);

  query.run(
    `INSERT INTO remote_terminal_sessions (id, server_id, device_id, user_id, shell, cwd, cols, rows, status, buffer_bytes, created_at, last_activity)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 0, ?, ?)`,
    id,
    serverId,
    deviceId,
    userId,
    session.shell,
    workingDirectory,
    safeCols,
    safeRows,
    now,
    now,
  );

  stream.on('data', (chunk) => {
    let text = session.decoder.write(chunk);
    if (session.markerPending) {
      session.pending += text;
      const lines = session.pending.split('\n');
      const markerIndex = lines.findIndex((line) => /LIFEFORM_READY\s+(\d+)\s*$/.test(line));
      if (markerIndex === -1) {
        // The shell echoes the command before running it, so the PID line
        // arrives on a later chunk. Keep waiting until the marker appears.
        if (session.pending.length > 4096) {
          text = session.pending;
          session.pending = '';
          session.markerPending = false;
        } else return;
      } else {
        const match = lines[markerIndex].match(/LIFEFORM_READY\s+(\d+)/);
        session.ptyPid = Number(match[1]);
        query.run('UPDATE remote_terminal_sessions SET pty_pid = ? WHERE id = ?', session.ptyPid, id);
        text = lines.slice(markerIndex + 1).join('\n');
        session.pending = '';
        session.markerPending = false;
      }
    }
    if (!text) return;
    session.lastActivity = Date.now();
    appendBuffer(session, text);
    emit(session, 'remote.terminal.output', { data: text, bytes: Buffer.byteLength(text) });
  });

  stream.on('close', () => closeSession(id, 'remote-close', { silent: false }));
  stream.on('error', (error) => {
    emit(session, 'remote.terminal.error', { message: String(error?.message ?? error) });
    closeSession(id, 'error', { silent: false });
  });
  stream.stderr?.on('data', (chunk) => {
    const text = session.decoder.write(chunk);
    if (!text) return;
    appendBuffer(session, text);
    emit(session, 'remote.terminal.output', { data: text, bytes: Buffer.byteLength(text), stderr: true });
  });

  // Enter the requested directory and report the real shell PID in one line
  // that is removed from the visible stream.
  stream.write(`cd -- ${shellQuote(workingDirectory)} 2>/dev/null; printf 'LIFEFORM_READY %s\\n' "$$"\n`);

  audit(deviceId ?? 'owner', 'remote.terminal.created', `${serverId}:${id}`, { cwd: workingDirectory, cols: safeCols, rows: safeRows });
  recordActivity({
    type: 'terminal',
    title: `Terminal dibuka di ${row.name}`,
    detail: workingDirectory,
    source: deviceId ?? 'owner',
    result: 'ok',
  });
  emit(session, 'remote.terminal.session.created', { session: publicSession(session) });
  return { ...publicSession(session), buffer: '' };
}

export function writeInput(id, data, { deviceId = null } = {}) {
  const session = sessions.get(id);
  if (!session) throw new HttpError(404, 'Session terminal tidak aktif.', 'TERMINAL_SESSION_NOT_LIVE');
  if (session.deviceId && deviceId && session.deviceId !== deviceId) {
    throw new HttpError(403, 'Session ini milik device lain.', 'TERMINAL_SESSION_FORBIDDEN');
  }
  if (session.status !== 'active') throw new HttpError(409, 'Session sudah tidak aktif.', 'TERMINAL_SESSION_CLOSED');
  const text = String(data ?? '');
  if (text.length > 16384) throw new HttpError(413, 'Input terlalu panjang.', 'INPUT_TOO_LARGE');
  session.stream.write(text);
  session.lastActivity = Date.now();
  emit(session, 'remote.terminal.input', { data: text.slice(0, 2000), bytes: Buffer.byteLength(text) });
  return { ok: true };
}

export function resizeSession(id, { cols, rows, deviceId = null }) {
  const session = sessions.get(id);
  if (!session) throw new HttpError(404, 'Session terminal tidak aktif.', 'TERMINAL_SESSION_NOT_LIVE');
  if (session.deviceId && deviceId && session.deviceId !== deviceId) {
    throw new HttpError(403, 'Session ini milik device lain.', 'TERMINAL_SESSION_FORBIDDEN');
  }
  const safeCols = Math.max(20, Math.min(400, Number(cols) || session.cols));
  const safeRows = Math.max(5, Math.min(200, Number(rows) || session.rows));
  session.cols = safeCols;
  session.rows = safeRows;
  session.stream.setWindow(safeRows, safeCols, 0, 0);
  query.run('UPDATE remote_terminal_sessions SET cols = ?, rows = ? WHERE id = ?', safeCols, safeRows, id);
  emit(session, 'remote.terminal.resize', { cols: safeCols, rows: safeRows });
  return { cols: safeCols, rows: safeRows };
}

/** Ctrl+C equivalent (SIGINT through the PTY). */
export function interruptSession(id, { deviceId = null } = {}) {
  const session = sessions.get(id);
  if (!session) throw new HttpError(404, 'Session terminal tidak aktif.', 'TERMINAL_SESSION_NOT_LIVE');
  if (session.deviceId && deviceId && session.deviceId !== deviceId) {
    throw new HttpError(403, 'Session ini milik device lain.', 'TERMINAL_SESSION_FORBIDDEN');
  }
  session.stream.write('\u0003');
  session.lastActivity = Date.now();
  emit(session, 'remote.terminal.interrupt', {});
  return { ok: true };
}

export function closeSession(id, reason = 'closed', { silent = false } = {}) {
  const session = sessions.get(id);
  const now = Date.now();
  if (!session) {
    const row = query.get('SELECT * FROM remote_terminal_sessions WHERE id = ?', id);
    if (!row) throw new HttpError(404, 'Session terminal tidak ditemukan.', 'TERMINAL_SESSION_NOT_FOUND');
    if (row.status !== 'closed') {
      query.run("UPDATE remote_terminal_sessions SET status = 'closed', closed_at = ?, close_reason = ? WHERE id = ?", now, reason, id);
    }
    return { id, closed: true };
  }
  sessions.delete(id);
  try {
    session.stream.end();
  } catch {
    /* ignore */
  }
  query.run("UPDATE remote_terminal_sessions SET status = 'closed', closed_at = ?, close_reason = ? WHERE id = ?", now, reason, id);
  if (!silent) emit(session, 'remote.terminal.session.closed', { reason, closedAt: now });
  return { id, closed: true, reason };
}

export function closeAllSessions(reason = 'backend shutdown') {
  for (const id of Array.from(sessions.keys())) {
    try {
      closeSession(id, reason);
    } catch {
      /* ignore */
    }
  }
}

/** Backend restart: PTY processes are gone, so never pretend they still run. */
export function recoverSessionsOnStartup() {
  const now = Date.now();
  const stale = query.all("SELECT id FROM remote_terminal_sessions WHERE status = 'active'");
  for (const row of stale) {
    query.run(
      "UPDATE remote_terminal_sessions SET status = 'disconnected', closed_at = ?, close_reason = 'backend-restart' WHERE id = ?",
      now,
      row.id,
    );
  }
  if (stale.length) logger.info(`remote terminal: ${stale.length} session lama ditandai disconnected (backend restart)`);
  return stale.length;
}

export function startTerminalSweeper() {
  if (sweeper) return;
  sweeper = setInterval(() => {
    const now = Date.now();
    for (const session of Array.from(sessions.values())) {
      if (now - session.lastActivity > config.remoteTerminalIdleMs) {
        try {
          closeSession(session.id, 'idle-timeout');
        } catch (error) {
          logger.warn('terminal idle close failed', String(error?.message ?? error));
        }
      }
    }
    // Keep the persisted buffer size roughly in sync for the session list.
    for (const session of sessions.values()) {
      query.run('UPDATE remote_terminal_sessions SET last_activity = ?, buffer_bytes = ? WHERE id = ?', session.lastActivity, session.bufferBytes, session.id);
    }
  }, 60_000);
  sweeper.unref?.();
}

export function stopTerminalSweeper() {
  if (sweeper) clearInterval(sweeper);
  sweeper = null;
}

export function activeSessionCount() {
  return sessions.size;
}
