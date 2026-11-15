// Transfer registry: uploads/downloads that stream, report progress over the
// shared WebSocket and can be cancelled without leaving broken files behind.
import crypto from 'node:crypto';
import { query } from '../db.mjs';
import { emitEvent } from '../events.mjs';
import { HttpError } from '../http.mjs';

const active = new Map();

function emit(type, transfer) {
  emitEvent(type, {
    transferId: transfer.id,
    serverId: transfer.serverId,
    direction: transfer.direction,
    remotePath: transfer.remotePath,
    localName: transfer.localName ?? null,
    transferredBytes: transfer.transferredBytes ?? 0,
    totalBytes: transfer.totalBytes ?? null,
    status: transfer.status,
    error: transfer.error ?? null,
    deviceId: transfer.deviceId ?? null,
    ts: Date.now(),
  });
}

function rowToTransfer(row) {
  return {
    id: row.id,
    serverId: row.server_id,
    direction: row.direction,
    remotePath: row.remote_path,
    localName: row.local_name,
    totalBytes: row.total_bytes ?? null,
    transferredBytes: row.transferred_bytes ?? 0,
    status: row.status,
    error: row.error ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    finishedAt: row.finished_at ?? null,
  };
}

export function beginTransfer({ serverId, deviceId = null, direction, remotePath, localName = null, totalBytes = null }) {
  const id = crypto.randomUUID();
  const now = Date.now();
  query.run(
    `INSERT INTO remote_transfers (id, server_id, device_id, direction, remote_path, local_name, total_bytes, transferred_bytes, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'running', ?, ?)`,
    id,
    serverId,
    deviceId,
    direction,
    remotePath,
    localName,
    totalBytes,
    now,
    now,
  );
  const transfer = {
    id,
    serverId,
    deviceId,
    direction,
    remotePath,
    localName,
    totalBytes,
    transferredBytes: 0,
    status: 'running',
    createdAt: now,
    updatedAt: now,
  };
  const state = { aborted: false, abortHandlers: [], lastEmitAt: 0, transfer };
  active.set(id, state);
  emit('remote.transfer.started', transfer);
  return {
    id,
    transfer,
    get aborted() {
      return state.aborted;
    },
    progress(bytes, total = null) {
      transfer.transferredBytes = bytes;
      if (total !== null) transfer.totalBytes = total;
      const now2 = Date.now();
      // Throttle progress events: 10/s is plenty for a phone UI.
      if (now2 - state.lastEmitAt < 100 && bytes !== transfer.totalBytes) return;
      state.lastEmitAt = now2;
      query.run('UPDATE remote_transfers SET transferred_bytes = ?, total_bytes = COALESCE(?, total_bytes), updated_at = ? WHERE id = ?', bytes, total, now2, id);
      emit('remote.transfer.progress', transfer);
    },
    attachAbort(handler) {
      state.abortHandlers.push(handler);
    },
    complete(bytes = transfer.transferredBytes) {
      const now3 = Date.now();
      transfer.transferredBytes = bytes;
      transfer.status = 'completed';
      transfer.finishedAt = now3;
      query.run(
        "UPDATE remote_transfers SET status = 'completed', transferred_bytes = ?, updated_at = ?, finished_at = ? WHERE id = ?",
        bytes,
        now3,
        now3,
        id,
      );
      active.delete(id);
      emit('remote.transfer.completed', transfer);
      return transfer;
    },
    fail(error) {
      const now4 = Date.now();
      transfer.status = state.aborted ? 'cancelled' : 'failed';
      transfer.error = state.aborted ? 'Dibatalkan oleh pengguna.' : String(error?.message ?? error).slice(0, 500);
      transfer.finishedAt = now4;
      query.run(
        'UPDATE remote_transfers SET status = ?, error = ?, updated_at = ?, finished_at = ? WHERE id = ?',
        transfer.status,
        transfer.error,
        now4,
        now4,
        id,
      );
      active.delete(id);
      emit(transfer.status === 'cancelled' ? 'remote.transfer.cancelled' : 'remote.transfer.failed', transfer);
      return transfer;
    },
  };
}

export function cancelTransfer(id) {
  const state = active.get(id);
  if (!state) {
    const row = query.get('SELECT * FROM remote_transfers WHERE id = ?', id);
    if (!row) throw new HttpError(404, 'Transfer tidak ditemukan.', 'TRANSFER_NOT_FOUND');
    if (row.status === 'completed') throw new HttpError(409, 'Transfer sudah selesai.', 'TRANSFER_FINISHED');
    return rowToTransfer(row);
  }
  state.aborted = true;
  for (const handler of state.abortHandlers) {
    try {
      handler();
    } catch {
      /* ignore */
    }
  }
  state.transfer.status = 'cancelled';
  emit('remote.transfer.cancelled', state.transfer);
  active.delete(id);
  const now = Date.now();
  query.run(
    "UPDATE remote_transfers SET status = 'cancelled', error = ?, updated_at = ?, finished_at = ? WHERE id = ?",
    'Dibatalkan oleh pengguna.',
    now,
    now,
    id,
  );
  return { ...state.transfer, error: 'Dibatalkan oleh pengguna.', finishedAt: now };
}

export function getTransfer(id) {
  const row = query.get('SELECT * FROM remote_transfers WHERE id = ?', id);
  if (!row) throw new HttpError(404, 'Transfer tidak ditemukan.', 'TRANSFER_NOT_FOUND');
  return rowToTransfer(row);
}

export function listTransfers({ limit = 50, serverId = null } = {}) {
  const rows = serverId
    ? query.all('SELECT * FROM remote_transfers WHERE server_id = ? ORDER BY created_at DESC LIMIT ?', serverId, limit)
    : query.all('SELECT * FROM remote_transfers ORDER BY created_at DESC LIMIT ?', limit);
  return rows.map(rowToTransfer);
}

/** Abort everything still running (backend shutdown). */
export function cancelAllTransfers(reason = 'backend shutdown') {
  for (const [id, state] of active.entries()) {
    state.aborted = true;
    for (const handler of state.abortHandlers) {
      try {
        handler();
      } catch {
        /* ignore */
      }
    }
    const now = Date.now();
    query.run("UPDATE remote_transfers SET status = 'failed', error = ?, updated_at = ?, finished_at = ? WHERE id = ?", reason, now, now, id);
    active.delete(id);
  }
}
