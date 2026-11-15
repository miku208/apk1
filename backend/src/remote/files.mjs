// Remote file operations: everything is validated against the server root,
// symlinks are resolved before use, and every mutation is audited.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config } from '../config.mjs';
import { logger } from '../logger.mjs';
import { HttpError } from '../http.mjs';
import { audit } from '../auth.mjs';
import { emitEvent, recordActivity } from '../events.mjs';
import { getAdapter } from './connection.mjs';
import { getServerRow } from './servers.mjs';
import { beginTransfer } from './transfers.mjs';
import { lineDiff } from './diff.mjs';
import {
  isInsideRoot,
  isPreviewableText,
  isSensitivePath,
  looksBinary,
  mimeTypeFor,
  normalizeRoot,
  parentOf,
  posix,
  resolveEntry,
  resolveRemotePath,
  sortEntries,
} from './paths.mjs';

const MAX_COPY_ENTRIES = 5000;
const MAX_COPY_DEPTH = 32;

async function adapterFor(serverId) {
  const row = getServerRow(serverId);
  const adapter = await getAdapter(serverId);
  return { adapter, row, root: normalizeRoot(row.remote_root) };
}

async function canonicalRoot(adapter, root) {
  try {
    return await adapter.realpath(root);
  } catch {
    return root;
  }
}

function ensureInside(root, realRoot, candidate, original) {
  if (isInsideRoot(root, candidate) || isInsideRoot(realRoot, candidate)) return;
  throw new HttpError(403, `Path "${original}" mengarah ke luar ${root} (symlink ditolak).`, 'PATH_ESCAPE');
}

/**
 * Resolve a path and prove it stays inside the root after symlinks.
 * Missing targets are checked through their canonical parent directory.
 */
async function safePath({ adapter, row, root, target, mustExist = true, cwd = null }) {
  const requested = resolveRemotePath({ root, cwd, target });
  const realRoot = await canonicalRoot(adapter, root);
  if (mustExist) {
    let stat;
    try {
      stat = await adapter.lstat(requested);
    } catch (error) {
      const message = String(error?.message ?? error);
      // Only a genuine "missing" becomes a 404; protocol/permission failures
      // must surface as errors instead of pretending the path is gone.
      if (error?.code === 2 || error?.code === 'ENOENT' || error?.status === 404 || /no such file|not found|ENOENT|tidak ditemukan/i.test(message)) {
        throw new HttpError(404, `Path tidak ditemukan: ${requested}`, 'REMOTE_NOT_FOUND');
      }
      throw new HttpError(502, `Gagal membaca path ${requested}: ${message}`, 'REMOTE_IO_ERROR');
    }
    let canonical = requested;
    try {
      canonical = await adapter.realpath(requested);
    } catch {
      /* keep lexical path when realpath is unsupported */
    }
    ensureInside(root, realRoot, canonical, target ?? requested);
    if (stat.isSymlink) {
      const targetReal = await adapter.realpath(requested).catch(() => null);
      if (targetReal) ensureInside(root, realRoot, targetReal, target ?? requested);
    }
    return { path: requested, stat, canonical, realRoot };
  }
  const parent = parentOf(requested);
  let canonicalParent = parent;
  try {
    canonicalParent = await adapter.realpath(parent);
  } catch {
    /* parent may not exist yet; the caller creates intermediate dirs */
  }
  ensureInside(root, realRoot, canonicalParent, target ?? requested);
  ensureInside(root, realRoot, requested, target ?? requested);
  return { path: requested, stat: null, canonical: requested, parent, realRoot };
}

function mapEntry(entry) {
  return {
    name: entry.name,
    path: entry.path,
    type: entry.type,
    size: entry.size,
    owner: entry.owner,
    group: entry.group,
    permissions: entry.permissions,
    mode: entry.mode,
    modifiedAt: entry.modifiedAt,
    isSymlink: entry.isSymlink,
    symlinkTarget: entry.symlinkTarget ?? null,
    extension: posix.extname(entry.name).replace(/^\./, '') || null,
  };
}

export async function listDirectory({
  serverId,
  target = '.',
  cwd = null,
  showHidden = true,
  sortBy = 'name',
  order = 'asc',
  search = null,
  offset = 0,
  limit = 200,
}) {
  const { adapter, row, root } = await adapterFor(serverId);
  const { path: directory } = await safePath({ adapter, row, root, target, cwd });
  const stat = await adapter.stat(directory);
  if (stat.type !== 'directory') throw new HttpError(400, 'Path bukan direktori.', 'NOT_DIRECTORY');

  let entries = await adapter.list(directory);
  if (!showHidden) entries = entries.filter((entry) => !entry.name.startsWith('.'));
  if (search) {
    const needle = String(search).toLowerCase();
    entries = entries.filter((entry) => entry.name.toLowerCase().includes(needle));
  }
  const sorted = sortEntries(entries.map(mapEntry), { sortBy, order });
  const total = sorted.length;
  const page = sorted.slice(offset, offset + limit);
  const storage = await adapter.statvfs(directory);

  return {
    serverId,
    path: directory,
    root,
    breadcrumbs: breadcrumbs(root, directory),
    entries: page,
    total,
    offset,
    limit,
    truncated: offset + page.length < total,
    storage,
    sort: { by: sortBy, order },
    showHidden,
    protocol: adapter.protocol,
  };
}

export function breadcrumbs(root, directory) {
  const base = normalizeRoot(root);
  const crumbs = [{ name: base === '/' ? '/' : posix.basename(base) || '/', path: base }];
  if (directory === base) return crumbs;
  const relative = directory.startsWith(`${base}/`) ? directory.slice(base.length + 1) : '';
  let current = base;
  for (const part of relative.split('/').filter(Boolean)) {
    current = current === '/' ? `/${part}` : `${current}/${part}`;
    crumbs.push({ name: part, path: current });
  }
  return crumbs;
}

export async function readFile({ serverId, target, cwd = null, maxBytes = null, offset = 0, length = null }) {
  const { adapter, row, root } = await adapterFor(serverId);
  const { path: file, stat } = await safePath({ adapter, row, root, target, cwd });
  if (stat.type === 'directory') throw new HttpError(400, 'Path adalah direktori.', 'IS_DIRECTORY');
  const limit = Math.min(maxBytes ?? config.remoteMaxEditBytes, config.remoteMaxEditBytes);
  if (stat.size > limit && length === null) {
    throw new HttpError(413, `File ${Math.round(stat.size / 1024)} KB melebihi batas editor ${Math.round(limit / 1024)} KB.`, 'FILE_TOO_LARGE');
  }
  const stream = adapter.readStream(file);
  const chunks = [];
  let size = 0;
  let truncated = false;
  await new Promise((resolve, reject) => {
    stream.on('data', (chunk) => {
      if (size >= limit) {
        truncated = true;
        stream.destroy();
        resolve();
        return;
      }
      chunks.push(chunk);
      size += chunk.length;
    });
    stream.on('error', reject);
    stream.on('end', resolve);
  });
  const buffer = Buffer.concat(chunks);
  const binary = looksBinary(buffer);
  const sensitive = isSensitivePath(file);
  return {
    serverId,
    path: file,
    name: posix.basename(file),
    mime: mimeTypeFor(file),
    size: stat.size,
    modifiedAt: stat.modifiedAt,
    permissions: stat.permissions,
    sensitive,
    binary,
    previewable: !binary && isPreviewableText(file),
    truncated: truncated || buffer.length < stat.size,
    offset,
    encoding: 'utf-8',
    content: binary ? null : buffer.toString('utf8'),
    note: binary ? 'File biner tidak ditampilkan sebagai teks.' : null,
  };
}

function localBackupPath(serverId, remotePath) {
  const directory = path.join(config.dataDir, 'remote-backups', serverId);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const base = posix.basename(remotePath).replace(/[^\w.@-]/g, '_');
  return path.join(directory, `${stamp}-${base}`);
}

async function readRemoteText(adapter, file, limit = config.remoteMaxEditBytes) {
  const stream = adapter.readStream(file);
  const chunks = [];
  let size = 0;
  return new Promise((resolve, reject) => {
    stream.on('data', (chunk) => {
      chunks.push(chunk);
      size += chunk.length;
      if (size > limit) {
        stream.destroy();
        resolve({ buffer: Buffer.concat(chunks), truncated: true });
      }
    });
    stream.on('error', reject);
    stream.on('end', () => resolve({ buffer: Buffer.concat(chunks), truncated: false }));
  });
}

export async function writeFile({
  serverId,
  target,
  content,
  cwd = null,
  confirmSensitive = false,
  expectedModifiedAt = null,
  actor = 'owner',
}) {
  if (typeof content !== 'string') throw new HttpError(400, 'Konten file wajib berupa string.', 'VALIDATION');
  if (Buffer.byteLength(content) > config.remoteMaxEditBytes) {
    throw new HttpError(413, 'Konten melebihi batas editor.', 'FILE_TOO_LARGE');
  }
  const { adapter, row, root } = await adapterFor(serverId);
  let resolved;
  try {
    resolved = await safePath({ adapter, row, root, target, cwd, mustExist: true });
  } catch (error) {
    if (error.code !== 'REMOTE_NOT_FOUND') throw error;
    resolved = await safePath({ adapter, row, root, target, cwd, mustExist: false });
  }

  const file = resolved.path;
  const sensitive = isSensitivePath(file);
  if (sensitive && !confirmSensitive) {
    throw new HttpError(409, 'File sensitif: konfirmasi eksplisit diperlukan sebelum menulis.', 'SENSITIVE_CONFIRM_REQUIRED', {
      sensitive: true,
      path: file,
    });
  }
  if (resolved.stat?.type === 'directory') throw new HttpError(400, 'Path adalah direktori.', 'IS_DIRECTORY');
  if (resolved.stat && expectedModifiedAt && resolved.stat.modifiedAt && resolved.stat.modifiedAt !== expectedModifiedAt) {
    throw new HttpError(409, 'File berubah di server sejak dibuka. Muat ulang sebelum menyimpan.', 'CONFLICT_MODIFIED', {
      currentModifiedAt: resolved.stat.modifiedAt,
      expectedModifiedAt,
    });
  }

  let previous = '';
  let backupPath = null;
  let diff = null;
  if (resolved.stat) {
    const read = await readRemoteText(adapter, file);
    previous = read.buffer.toString('utf8');
    if (!looksBinary(read.buffer)) {
      if (!isSensitivePath(file)) {
        backupPath = localBackupPath(serverId, file);
        fs.writeFileSync(backupPath, read.buffer, { mode: 0o600 });
      }
      diff = lineDiff(previous, content);
    }
  }

  await adapter.writeFile(file, Buffer.from(content, 'utf8'), { mode: resolved.stat?.mode ? Number.parseInt(resolved.stat.mode, 8) & 0o777 : null });
  const stat = await adapter.stat(file);
  emitEvent(resolved.stat ? 'remote.file.updated' : 'remote.file.created', {
    serverId,
    path: file,
    size: stat.size,
    modifiedAt: stat.modifiedAt,
    actor,
  });
  audit(actor, 'remote.file.written', `${row.id}:${file}`, { bytes: Buffer.byteLength(content), sensitive, backup: Boolean(backupPath) });
  recordActivity({
    type: 'file',
    title: `${resolved.stat ? 'Mengubah' : 'Membuat'} file remote ${posix.basename(file)}`,
    detail: `${row.name}:${file}${diff && !diff.truncated ? ` (+${diff.added}/-${diff.removed})` : ''}`,
    source: actor,
    result: 'ok',
  });

  return {
    serverId,
    path: file,
    size: stat.size,
    modifiedAt: stat.modifiedAt,
    created: !resolved.stat,
    backupPath,
    diff,
    sensitive,
  };
}

/** Diff-only preview, used before saving a sensitive file. */
export async function previewWrite({ serverId, target, content, cwd = null }) {
  const { adapter, row, root } = await adapterFor(serverId);
  let resolved;
  try {
    resolved = await safePath({ adapter, row, root, target, cwd, mustExist: true });
  } catch (error) {
    if (error.code !== 'REMOTE_NOT_FOUND') throw error;
    resolved = await safePath({ adapter, row, root, target, cwd, mustExist: false });
  }
  const previous = resolved.stat ? (await readRemoteText(adapter, resolved.path)).buffer.toString('utf8') : '';
  return {
    path: resolved.path,
    exists: Boolean(resolved.stat),
    sensitive: isSensitivePath(resolved.path),
    diff: lineDiff(previous, String(content ?? '')),
    previousSize: Buffer.byteLength(previous),
    nextSize: Buffer.byteLength(String(content ?? '')),
  };
}

export async function uploadFile({ serverId, target, cwd = null, stream, size = null, overwrite = false, deviceId = null, actor = 'owner' }) {
  const { adapter, row, root } = await adapterFor(serverId);
  let resolved;
  try {
    resolved = await safePath({ adapter, row, root, target, cwd, mustExist: true });
  } catch (error) {
    if (error.code !== 'REMOTE_NOT_FOUND') throw error;
    resolved = await safePath({ adapter, row, root, target, cwd, mustExist: false });
  }
  if (resolved.stat?.type === 'directory') throw new HttpError(400, 'Target upload adalah direktori.', 'IS_DIRECTORY');
  if (resolved.stat && !overwrite) {
    throw new HttpError(409, `File sudah ada: ${resolved.path}. Kirim overwrite=true untuk mengganti.`, 'OVERWRITE_CONFIRM_REQUIRED');
  }
  if (size !== null && size > config.remoteMaxUploadBytes) {
    throw new HttpError(413, 'Ukuran upload melebihi batas.', 'FILE_TOO_LARGE');
  }

  const transfer = beginTransfer({
    serverId,
    deviceId,
    direction: 'upload',
    remotePath: resolved.path,
    localName: null,
    totalBytes: size,
  });
  let bytes = 0;
  const onAbort = () => stream.destroy(new Error('Transfer dibatalkan.'));
  transfer.attachAbort(onAbort);
  try {
    bytes = await adapter.upload(resolved.path, stream, {
      onProgress: (transferred) => {
        if (transfer.aborted) {
          stream.destroy(new Error('Transfer dibatalkan.'));
          return;
        }
        transfer.progress(transferred);
      },
      mode: resolved.stat?.mode ? Number.parseInt(resolved.stat.mode, 8) & 0o777 : null,
    });
    if (transfer.aborted) throw new Error('Transfer dibatalkan.');
    const stat = await adapter.stat(resolved.path);
    transfer.complete(stat.size ?? bytes);
    emitEvent(resolved.stat ? 'remote.file.updated' : 'remote.file.created', {
      serverId,
      path: resolved.path,
      size: stat.size,
      actor,
    });
    audit(actor, 'remote.file.uploaded', `${row.id}:${resolved.path}`, { bytes: stat.size });
    recordActivity({
      type: 'file',
      title: `Upload file ke ${row.name}`,
      detail: `${resolved.path} (${Math.round((stat.size ?? bytes) / 1024)} KB)`,
      source: actor,
      result: 'ok',
    });
    return { transferId: transfer.id, path: resolved.path, size: stat.size, modifiedAt: stat.modifiedAt, overwritten: Boolean(resolved.stat) };
  } catch (error) {
    transfer.fail(error);
    throw error;
  }
}

export async function downloadTo({ serverId, target, cwd = null, writable, deviceId = null, actor = 'owner' }) {
  const { adapter, row, root } = await adapterFor(serverId);
  const { path: file, stat } = await safePath({ adapter, row, root, target, cwd });
  if (stat.type === 'directory') throw new HttpError(400, 'Path adalah direktori.', 'IS_DIRECTORY');
  const transfer = beginTransfer({
    serverId,
    deviceId,
    direction: 'download',
    remotePath: file,
    localName: posix.basename(file),
    totalBytes: stat.size,
  });
  const onAbort = () => writable.destroy(new Error('Transfer dibatalkan.'));
  transfer.attachAbort(onAbort);
  try {
    if (adapter.protocol !== 'sftp') {
      await adapter.download(file, writable, {
        onProgress: (bytes) => {
          if (transfer.aborted) writable.destroy(new Error('Transfer dibatalkan.'));
          else transfer.progress(bytes);
        },
      });
    } else {
      const source = adapter.readStream(file);
      let bytes = 0;
      await new Promise((resolve, reject) => {
        source.on('data', (chunk) => {
          bytes += chunk.length;
          if (transfer.aborted) {
            source.destroy(new Error('Transfer dibatalkan.'));
            return;
          }
          transfer.progress(bytes);
        });
        source.on('error', reject);
        writable.on('error', reject);
        writable.on('finish', resolve);
        source.pipe(writable);
      });
    }
    transfer.complete(stat.size);
    audit(actor, 'remote.file.downloaded', `${row.id}:${file}`, { bytes: stat.size });
    return { transferId: transfer.id, path: file, size: stat.size, mime: mimeTypeFor(file), name: posix.basename(file) };
  } catch (error) {
    transfer.fail(error);
    throw error;
  }
}

/** HTTP download: headers, then the stream, with a cancellable transfer entry. */
export async function downloadToResponse({ serverId, target, cwd = null, res, deviceId = null, actor = 'owner' }) {
  const { adapter, row, root } = await adapterFor(serverId);
  const { path: file, stat } = await safePath({ adapter, row, root, target, cwd });
  if (stat.type === 'directory') throw new HttpError(400, 'Path adalah direktori.', 'IS_DIRECTORY');
  const name = posix.basename(file);
  const transfer = beginTransfer({ serverId, deviceId, direction: 'download', remotePath: file, localName: name, totalBytes: stat.size });
  const safeName = name.replace(/[\r\n"]/g, '_');
  res.writeHead(200, {
    'Content-Type': mimeTypeFor(file),
    'Content-Length': stat.size,
    'Content-Disposition': `attachment; filename="${safeName.replace(/[^\x20-\x7e]/g, '_')}"; filename*=UTF-8''${encodeURIComponent(name)}`,
    'X-Transfer-Id': transfer.id,
    'X-Remote-Path': encodeURIComponent(file),
    'Cache-Control': 'no-store',
  });
  let closed = false;
  transfer.attachAbort(() => {
    closed = true;
    res.destroy(new Error('Transfer dibatalkan.'));
  });
  try {
    if (adapter.protocol !== 'sftp') {
      await adapter.download(file, res, {
        onProgress: (bytes) => {
          if (transfer.aborted) res.destroy();
          else transfer.progress(bytes);
        },
      });
    } else {
      const source = adapter.readStream(file);
      let bytes = 0;
      await new Promise((resolve, reject) => {
        source.on('data', (chunk) => {
          bytes += chunk.length;
          if (transfer.aborted) {
            source.destroy(new Error('Transfer dibatalkan.'));
            return;
          }
          transfer.progress(bytes);
        });
        source.on('error', reject);
        res.on('error', reject);
        res.on('close', () => {
          if (!res.writableEnded) source.destroy(new Error('Koneksi ditutup klien.'));
        });
        res.on('finish', resolve);
        source.pipe(res);
      });
    }
    if (!closed) transfer.complete(stat.size);
    audit(actor, 'remote.file.downloaded', `${row.id}:${file}`, { bytes: stat.size });
    return { path: file, size: stat.size, transferId: transfer.id, name };
  } catch (error) {
    if (!closed) transfer.fail(error);
    throw error;
  }
}

export async function openPreview({ serverId, target, cwd = null }) {
  const { adapter, root, row } = await adapterFor(serverId);
  const { path: file, stat } = await safePath({ adapter, row, root, target, cwd });
  if (stat.type === 'directory') throw new HttpError(400, 'Path adalah direktori.', 'IS_DIRECTORY');
  if (stat.size > config.remoteMaxPreviewBytes) throw new HttpError(413, 'File terlalu besar untuk preview.', 'FILE_TOO_LARGE');
  return {
    stream: adapter.readStream(file),
    size: stat.size,
    mime: mimeTypeFor(file),
    name: posix.basename(file),
    modifiedAt: stat.modifiedAt,
  };
}

export async function renamePath({ serverId, target, name, cwd = null, overwrite = false, actor = 'owner' }) {
  const { adapter, row, root } = await adapterFor(serverId);
  const { path: source } = await safePath({ adapter, row, root, target, cwd });
  const destination = resolveEntry(parentOf(source), name);
  const exists = await adapter.exists(destination);
  if (exists && !overwrite) throw new HttpError(409, 'Nama tujuan sudah ada.', 'OVERWRITE_CONFIRM_REQUIRED');
  await adapter.rename(source, destination);
  audit(actor, 'remote.file.renamed', `${row.id}:${source}`, { to: destination });
  emitEvent('remote.file.moved', { serverId, from: source, to: destination, actor });
  return { serverId, from: source, to: destination };
}

async function copyRecursive(adapter, from, to, { overwrite = false, depth = 0, counter = { count: 0 }, root, realRoot }) {
  if (depth > MAX_COPY_DEPTH) throw new HttpError(400, 'Struktur direktori terlalu dalam.', 'COPY_TOO_DEEP');
  if (counter.count > MAX_COPY_ENTRIES) throw new HttpError(413, 'Terlalu banyak file untuk disalin.', 'COPY_TOO_LARGE');
  counter.count += 1;
  const stat = await adapter.lstat(from);
  if (stat.type === 'directory') {
    if (!(await adapter.exists(to))) await adapter.mkdir(to);
    for (const entry of await adapter.list(from)) {
      const childFrom = posix.join(from, entry.name);
      const childTo = posix.join(to, entry.name);
      ensureInside(root, realRoot, await adapter.realpath(childFrom).catch(() => childFrom), childFrom);
      await copyRecursive(adapter, childFrom, childTo, { overwrite, depth: depth + 1, counter, root, realRoot });
    }
    return;
  }
  if (!overwrite && (await adapter.exists(to))) throw new HttpError(409, `Tujuan sudah ada: ${to}`, 'OVERWRITE_CONFIRM_REQUIRED');
  const source = adapter.readStream(from);
  const chunks = [];
  // Small files are buffered; big ones are streamed through a temp file.
  await new Promise((resolve, reject) => {
    source.on('data', (chunk) => chunks.push(chunk));
    source.on('error', reject);
    source.on('end', resolve);
  });
  await adapter.writeFile(to, Buffer.concat(chunks));
}

export async function copyPath({ serverId, target, destination, cwd = null, overwrite = false, recursive = false, actor = 'owner' }) {
  const { adapter, row, root } = await adapterFor(serverId);
  const { path: source, stat, realRoot } = await safePath({ adapter, row, root, target, cwd });
  const dest = await safePath({ adapter, row, root, target: destination, cwd, mustExist: false });
  if (source === dest.path) throw new HttpError(400, 'Sumber dan tujuan sama.', 'VALIDATION');
  if (stat.type === 'directory' && !recursive) throw new HttpError(400, 'Salin direktori membutuhkan recursive=true.', 'RECURSIVE_REQUIRED');
  if (dest.path.startsWith(`${source}/`)) throw new HttpError(400, 'Tidak bisa menyalin direktori ke dalam dirinya.', 'VALIDATION');
  await copyRecursive(adapter, source, dest.path, { overwrite, root, realRoot });
  audit(actor, 'remote.file.copied', `${row.id}:${source}`, { to: dest.path });
  emitEvent('remote.file.created', { serverId, path: dest.path, from: source, actor });
  return { serverId, from: source, to: dest.path };
}

export async function movePath({ serverId, target, destination, cwd = null, overwrite = false, actor = 'owner' }) {
  const { adapter, row, root } = await adapterFor(serverId);
  const { path: source, stat, realRoot } = await safePath({ adapter, row, root, target, cwd });
  const dest = await safePath({ adapter, row, root, target: destination, cwd, mustExist: false });
  if (source === dest.path) throw new HttpError(400, 'Sumber dan tujuan sama.', 'VALIDATION');
  if (dest.path.startsWith(`${source}/`)) throw new HttpError(400, 'Tidak bisa memindahkan direktori ke dalam dirinya.', 'VALIDATION');
  const destExists = await adapter.exists(dest.path);
  if (destExists && !overwrite) throw new HttpError(409, 'Tujuan sudah ada. Kirim overwrite=true.', 'OVERWRITE_CONFIRM_REQUIRED');
  try {
    await adapter.rename(source, dest.path);
  } catch (error) {
    logger.warn('remote move fallback to copy', String(error?.message ?? error));
    await copyRecursive(adapter, source, dest.path, { overwrite, root, realRoot });
    await deleteRecursive(adapter, source, { depth: 0 });
  }
  audit(actor, 'remote.file.moved', `${row.id}:${source}`, { to: dest.path, directory: stat.type === 'directory' });
  emitEvent('remote.file.moved', { serverId, from: source, to: dest.path, actor });
  return { serverId, from: source, to: dest.path };
}

export async function makeDirectory({ serverId, target, cwd = null, recursive = false, actor = 'owner' }) {
  const { adapter, row, root } = await adapterFor(serverId);
  const { path: dir } = await safePath({ adapter, row, root, target, cwd, mustExist: false });
  if (await adapter.exists(dir)) throw new HttpError(409, 'Direktori sudah ada.', 'ALREADY_EXISTS');
  if (recursive) {
    const parts = [];
    let current = dir;
    while (current && current !== root && current !== '/') {
      parts.unshift(current);
      current = parentOf(current);
    }
    for (const part of parts) {
      if (!(await adapter.exists(part))) await adapter.mkdir(part);
    }
  } else {
    await adapter.mkdir(dir);
  }
  audit(actor, 'remote.dir.created', `${row.id}:${dir}`);
  emitEvent('remote.file.created', { serverId, path: dir, type: 'directory', actor });
  return { serverId, path: dir };
}

async function deleteRecursive(adapter, target, { depth }) {
  if (depth > MAX_COPY_DEPTH) throw new HttpError(400, 'Struktur direktori terlalu dalam.', 'DELETE_TOO_DEEP');
  const stat = await adapter.lstat(target);
  if (stat.type === 'directory') {
    for (const entry of await adapter.list(target)) {
      await deleteRecursive(adapter, posix.join(target, entry.name), { depth: depth + 1 });
    }
    await adapter.rmdir(target);
    return;
  }
  await adapter.unlink(target);
}

export async function deletePath({ serverId, target, cwd = null, recursive = false, confirm = false, actor = 'owner' }) {
  if (!confirm) throw new HttpError(400, 'Penghapusan harus dikonfirmasi (confirm=true).', 'CONFIRM_REQUIRED');
  const { adapter, row, root } = await adapterFor(serverId);
  const { path: entry, stat } = await safePath({ adapter, row, root, target, cwd });
  if (entry === root) throw new HttpError(403, 'Tidak bisa menghapus root server.', 'ROOT_DELETE');
  if (stat.type === 'directory' && !recursive) {
    const children = await adapter.list(entry);
    if (children.length) throw new HttpError(409, 'Direktori tidak kosong; kirim recursive=true.', 'DIRECTORY_NOT_EMPTY');
  }
  await deleteRecursive(adapter, entry, { depth: 0 });
  audit(actor, 'remote.file.deleted', `${row.id}:${entry}`, { directory: stat.type === 'directory', recursive });
  emitEvent('remote.file.deleted', { serverId, path: entry, type: stat.type, actor });
  recordActivity({
    type: 'file',
    title: `Menghapus ${stat.type === 'directory' ? 'direktori' : 'file'} remote`,
    detail: `${row.name}:${entry}`,
    source: actor,
    risk: 'high',
    result: 'ok',
  });
  return { serverId, path: entry, deleted: true, directory: stat.type === 'directory' };
}

export async function fileMetadata({ serverId, target, cwd = null }) {
  const { adapter, row, root } = await adapterFor(serverId);
  const { path: entry, stat } = await safePath({ adapter, row, root, target, cwd });
  const storage = await adapter.statvfs(entry);
  return {
    serverId,
    protocol: adapter.protocol,
    path: entry,
    name: posix.basename(entry),
    type: stat.type,
    size: stat.size,
    owner: stat.owner,
    group: stat.group,
    uid: stat.uid,
    gid: stat.gid,
    permissions: stat.permissions,
    mode: stat.mode,
    modifiedAt: stat.modifiedAt,
    accessedAt: stat.accessedAt,
    isSymlink: stat.isSymlink,
    symlinkTarget: stat.symlinkTarget ?? null,
    mime: mimeTypeFor(entry),
    sensitive: isSensitivePath(entry),
    editable: stat.type === 'file' && isPreviewableText(entry) && stat.size <= config.remoteMaxEditBytes,
    storage,
    root: row.remote_root,
  };
}

export async function searchFiles({ serverId, base = '.', query, cwd = null, limit = null }) {
  const needle = String(query ?? '').trim();
  if (!needle) throw new HttpError(400, 'Query pencarian wajib.', 'VALIDATION');
  const { adapter, row, root } = await adapterFor(serverId);
  const { path: start } = await safePath({ adapter, row, root, target: base, cwd });
  const max = Math.min(limit ?? config.remoteSearchLimit, config.remoteSearchLimit);
  const results = [];
  let scanned = 0;

  const walk = async (directory, depth) => {
    if (results.length >= max || depth > 12) return;
    let entries;
    try {
      entries = await adapter.list(directory);
    } catch {
      return;
    }
    for (const entry of entries) {
      scanned += 1;
      if (results.length >= max) return;
      if (entry.name.toLowerCase().includes(needle.toLowerCase())) {
        results.push({ ...mapEntry(entry), matchedOn: 'name' });
      }
      if (entry.type === 'directory' && !entry.isSymlink) await walk(posix.join(directory, entry.name), depth + 1);
    }
  };
  await walk(start, 0);
  return {
    serverId,
    base: start,
    query: needle,
    results,
    count: results.length,
    scanned,
    truncated: results.length >= max,
  };
}

export { safePath, adapterFor };

/** Used by the AI tools: keep sensitive files out of model context by default. */
export async function readForAi({ serverId, target, cwd = null, allowSensitive = false }) {
  if (!allowSensitive && isSensitivePath(target)) {
    throw new HttpError(403, 'File sensitif tidak boleh dibaca AI tanpa persetujuan eksplisit.', 'AI_SENSITIVE_DENIED');
  }
  const read = await readFile({ serverId, target, cwd, maxBytes: Math.min(config.remoteMaxEditBytes, 200_000) });
  if (read.binary || read.sensitive === true && !allowSensitive) {
    return { ...read, content: null };
  }
  return read;
}


