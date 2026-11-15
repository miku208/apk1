// Optional FTP/FTPS adapter. Same interface as the SFTP adapter, limited to what
// FTP can actually do (no shell, no PTY, no POSIX ownership).
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { Client, FileType } from 'basic-ftp';
import { posix } from './paths.mjs';

function permissionString(info) {
  // basic-ftp exposes raw unix permissions only on some servers.
  const raw = info?.permissions ?? info?.rawModifiedAt ? info?.permissions : null;
  if (!raw) return null;
  const map = { d: 'd', '-': '-', r: 'r', w: 'w', x: 'x', s: 's', t: 't' };
  return String(raw)
    .split('')
    .map((char) => map[char] ?? '-')
    .join('')
    .slice(0, 10);
}

export function createFtpAdapter({ client, server, secure }) {
  const base = server.remote_root || '/';
  let closed = false;

  async function ensureDir(target) {
    const candidates = [];
    let current = target;
    while (current && current !== '/' && current !== base) {
      candidates.unshift(current);
      const next = posix.dirname(current);
      if (next === current) break;
      current = next;
    }
    for (const dir of candidates) {
      try {
        await client.ensureDir(dir);
      } catch (error) {
        // ensureDir walks the whole path itself; ignore "already exists" noise.
        if (!/exist/i.test(String(error?.message))) throw error;
      }
    }
  }

  return {
    protocol: secure ? 'ftps' : 'ftp',
    server,
    supportsTerminal: false,

    async list(directory) {
      const items = await client.list(directory);
      return items.map((info) => ({
        name: info.name,
        path: posix.join(directory, info.name),
        type: info.type === FileType.Directory ? 'directory' : info.type === FileType.SymbolicLink ? 'symlink' : 'file',
        size: Number(info.size ?? 0),
        mode: null,
        permissions: permissionString(info),
        uid: null,
        gid: null,
        owner: null,
        group: null,
        modifiedAt: info.modifiedAt ? info.modifiedAt.getTime() : null,
        accessedAt: null,
        isSymlink: info.type === FileType.SymbolicLink,
      }));
    },

    async stat(target) {
      if (target === '/' || target === '') {
        // FTP has no stat on the root itself; it is always a directory.
        return {
          name: '/',
          path: '/',
          type: 'directory',
          size: 0,
          mode: null,
          permissions: null,
          uid: null,
          gid: null,
          owner: null,
          group: null,
          modifiedAt: null,
          accessedAt: null,
          isSymlink: false,
        };
      }
      const directory = posix.dirname(target);
      const name = posix.basename(target);
      const items = await client.list(directory);
      const info = items.find((item) => item.name === name);
      if (!info) {
        const error = new Error('Path tidak ditemukan di server FTP.');
        error.code = 'ENOENT';
        error.status = 404;
        throw error;
      }
      return {
        name,
        path: target,
        type: info.type === FileType.Directory ? 'directory' : 'file',
        size: Number(info.size ?? 0),
        mode: null,
        permissions: permissionString(info),
        uid: null,
        gid: null,
        owner: null,
        group: null,
        modifiedAt: info.modifiedAt ? info.modifiedAt.getTime() : null,
        accessedAt: null,
        isSymlink: false,
      };
    },

    async lstat(target) {
      return this.stat(target);
    },

    async exists(target) {
      try {
        await this.stat(target);
        return true;
      } catch {
        return false;
      }
    },

    async realpath(target) {
      // FTP has no realpath; the server's PWD after entering the directory is
      // the best canonical answer available.
      const current = await client.pwd();
      try {
        await client.cd(target);
        const resolved = await client.pwd();
        await client.cd(current);
        return resolved || target;
      } catch {
        return target;
      }
    },

    async mkdir(target) {
      await ensureDir(target);
    },

    async rmdir(target) {
      await client.removeDir(target);
    },

    async unlink(target) {
      await client.remove(target);
    },

    async rename(from, to) {
      await client.rename(from, to);
    },

    async chmod() {
      throw Object.assign(new Error('FTP tidak mendukung chmod.'), { status: 400, code: 'UNSUPPORTED' });
    },

    readStream() {
      throw Object.assign(new Error('Gunakan download() untuk FTP.'), { code: 'UNSUPPORTED' });
    },

    async writeFile(target, buffer) {
      await ensureDir(posix.dirname(target));
      const stream = new PassThrough();
      const done = client.uploadFrom(stream, target);
      stream.end(buffer);
      await done;
    },

    async upload(target, readable, { onProgress = null } = {}) {
      await ensureDir(posix.dirname(target));
      let bytes = 0;
      if (onProgress) {
        client.trackProgress((info) => {
          bytes = Number(info.bytesOverall ?? bytes);
          onProgress(bytes);
        });
      }
      try {
        await client.uploadFrom(readable, target);
      } finally {
        client.trackProgress();
      }
      return bytes;
    },

    async download(target, writable, { onProgress = null } = {}) {
      if (onProgress) {
        client.trackProgress((info) => onProgress(Number(info.bytesOverall ?? 0)));
      }
      try {
        await client.downloadTo(writable, target);
      } finally {
        client.trackProgress();
      }
      return null;
    },

    async statvfs() {
      return null;
    },

    async exec() {
      throw Object.assign(new Error('FTP tidak mendukung eksekusi perintah.'), { status: 400, code: 'UNSUPPORTED' });
    },

    shell() {
      throw Object.assign(new Error('Terminal interaktif hanya tersedia via SSH/SFTP.'), {
        status: 400,
        code: 'TERMINAL_UNSUPPORTED',
      });
    },

    close() {
      if (closed) return;
      closed = true;
      try {
        client.close();
      } catch {
        /* ignore */
      }
    },

    get closed() {
      return closed;
    },
  };
}

export { permissionString };
