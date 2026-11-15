// SFTP adapter over an authenticated ssh2 client. All remote file access for
// this app goes through here; nothing leaks the SSH handle to routes.
import path from 'node:path';
import { posix } from './paths.mjs';

const TYPE_MAP = { 1: 'file', 2: 'directory', 3: 'symlink' };

function modeToPermissions(mode) {
  if (!Number.isFinite(mode)) return null;
  const bits = mode & 0o777;
  const chars = ['r', 'w', 'x'];
  let out = '';
  for (let i = 2; i >= 0; i -= 1) {
    for (let b = 0; b < 3; b += 1) {
      out += (bits >> (i * 3 + (2 - b))) & 1 ? chars[b] : '-';
    }
  }
  return out;
}

function modeToOctal(mode) {
  return Number.isFinite(mode) ? `0${(mode & 0o777).toString(8).padStart(3, '0')}` : null;
}

function typeOf(attrs) {
  if (!attrs) return 'file';
  if (typeof attrs.isDirectory === 'function') {
    if (attrs.isDirectory()) return 'directory';
    if (typeof attrs.isSymbolicLink === 'function' && attrs.isSymbolicLink()) return 'symlink';
    return 'file';
  }
  return TYPE_MAP[attrs.mode & 0o170000] === 'directory' ? 'directory' : 'file';
}

export function createSftpAdapter({ client, sftp, server }) {
  const p = (method, ...args) =>
    new Promise((resolve, reject) => {
      // Called as sftp[method](...) so `this` stays bound to the SFTP wrapper.
      sftp[method](...args, (error, value) => (error ? reject(error) : resolve(value)));
    });

  const owners = { users: null, groups: null };
  let closed = false;

  async function exec(command, { timeoutMs = 15000 } = {}) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Perintah remote melewati batas waktu.')), timeoutMs);
      client.exec(command, (error, stream) => {
        if (error) {
          clearTimeout(timer);
          reject(error);
          return;
        }
        let stdout = '';
        let stderr = '';
        stream.on('data', (chunk) => {
          if (stdout.length < 2_000_000) stdout += chunk.toString('utf8');
        });
        stream.stderr.on('data', (chunk) => {
          if (stderr.length < 200_000) stderr += chunk.toString('utf8');
        });
        stream.on('close', (code) => {
          clearTimeout(timer);
          resolve({ stdout, stderr, exitCode: typeof code === 'number' ? code : null });
        });
        stream.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });
    });
  }

  async function loadOwners() {
    if (owners.users) return;
    try {
      const result = await exec('getent passwd 2>/dev/null || cat /etc/passwd');
      const map = new Map();
      for (const line of result.stdout.split('\n')) {
        const [name, , uid] = line.split(':');
        if (name && uid && /^\d+$/.test(uid)) map.set(Number(uid), name);
      }
      owners.users = map;
    } catch {
      owners.users = new Map();
    }
    try {
      const result = await exec('getent group 2>/dev/null || cat /etc/group');
      const map = new Map();
      for (const line of result.stdout.split('\n')) {
        const [name, , gid] = line.split(':');
        if (name && gid && /^\d+$/.test(gid)) map.set(Number(gid), name);
      }
      owners.groups = map;
    } catch {
      owners.groups = new Map();
    }
  }

  async function describe(target, attrs) {
    const type = typeOf(attrs);
    if (attrs?.uid !== undefined) await loadOwners();
    return {
      name: posix.basename(target),
      path: target,
      type,
      size: Number(attrs?.size ?? 0),
      mode: modeToOctal(attrs?.mode),
      permissions: modeToPermissions(attrs?.mode),
      uid: attrs?.uid ?? null,
      gid: attrs?.gid ?? null,
      owner: attrs?.uid !== undefined ? owners.users.get(attrs.uid) ?? String(attrs.uid) : null,
      group: attrs?.gid !== undefined ? owners.groups.get(attrs.gid) ?? String(attrs.gid) : null,
      modifiedAt: attrs?.mtime ? attrs.mtime * 1000 : null,
      accessedAt: attrs?.atime ? attrs.atime * 1000 : null,
      isSymlink: type === 'symlink',
    };
  }

  return {
    protocol: 'sftp',
    server,
    supportsTerminal: true,

    async list(directory) {
      const items = await p('readdir', directory);
      const entries = await Promise.all(
        items.map(async (item) => {
          const target = posix.join(directory, item.filename);
          const described = await describe(target, item.attrs);
          if (item.attrs?.isSymbolicLink?.()) {
            // Resolve the link target for display; failure is not fatal.
            try {
              described.symlinkTarget = await p('readlink', target);
            } catch {
              described.symlinkTarget = null;
            }
          }
          return described;
        }),
      );
      return entries;
    },

    async stat(target) {
      return describe(target, await p('stat', target));
    },

    async lstat(target) {
      return describe(target, await p('lstat', target));
    },

    async exists(target) {
      try {
        await p('lstat', target);
        return true;
      } catch {
        return false;
      }
    },

    async realpath(target) {
      return p('realpath', target);
    },

    async mkdir(target) {
      await p('mkdir', target);
    },

    async rmdir(target) {
      await p('rmdir', target);
    },

    async unlink(target) {
      await p('unlink', target);
    },

    async rename(from, to) {
      await p('rename', from, to);
    },

    async chmod(target, mode) {
      await p('chmod', target, mode);
    },

    readStream(target) {
      return sftp.createReadStream(target);
    },

    /** Write a whole (small) buffer atomically: tmp file then rename. */
    async writeFile(target, buffer, { mode = null } = {}) {
      const directory = posix.dirname(target);
      const temp = posix.join(directory, `.${posix.basename(target)}.lifeform-${Date.now()}.tmp`);
      const stream = sftp.createWriteStream(temp, mode ? { mode } : {});
      await new Promise((resolve, reject) => {
        stream.on('error', reject);
        stream.on('close', resolve);
        stream.end(buffer);
      });
      try {
        await p('rename', temp, target);
      } catch (error) {
        await p('unlink', temp).catch(() => {});
        throw error;
      }
    },

    /** Stream an upload into a temp file and rename it when complete. */
    async upload(target, readable, { onProgress = null, mode = null } = {}) {
      const directory = posix.dirname(target);
      const temp = posix.join(directory, `.${posix.basename(target)}.lifeform-${Date.now()}.tmp`);
      const stream = sftp.createWriteStream(temp, mode ? { mode } : {});
      let bytes = 0;
      await new Promise((resolve, reject) => {
        readable.on('data', (chunk) => {
          bytes += chunk.length;
          onProgress?.(bytes);
        });
        readable.on('error', reject);
        stream.on('error', reject);
        stream.on('close', resolve);
        readable.pipe(stream);
      });
      try {
        await p('rename', temp, target);
      } catch (error) {
        await p('unlink', temp).catch(() => {});
        throw error;
      }
      return bytes;
    },

    async download(target, writable, { onProgress = null } = {}) {
      const stream = sftp.createReadStream(target);
      let bytes = 0;
      await new Promise((resolve, reject) => {
        stream.on('data', (chunk) => {
          bytes += chunk.length;
          onProgress?.(bytes);
        });
        stream.on('error', reject);
        writable.on('error', reject);
        writable.on('finish', resolve);
        stream.pipe(writable);
      });
      return bytes;
    },

    async statvfs(target) {
      if (typeof sftp.statvfs !== 'function') return null;
      try {
        const stats = await p('statvfs', target);
        const blockSize = Number(stats.f_frsize ?? stats.f_bsize ?? 4096);
        return {
          totalBytes: blockSize * Number(stats.f_blocks ?? 0),
          freeBytes: blockSize * Number(stats.f_bavail ?? stats.f_bfree ?? 0),
        };
      } catch {
        return null;
      }
    },

    exec,

    shell({ cols = 80, rows = 24, term = 'xterm-256color' } = {}) {
      return new Promise((resolve, reject) => {
        client.shell({ term, cols, rows }, (error, stream) => {
          if (error) {
            reject(error);
            return;
          }
          resolve(stream);
        });
      });
    },

    close() {
      if (closed) return;
      closed = true;
      try {
        client.end();
      } catch {
        /* ignore */
      }
    },

    get closed() {
      return closed;
    },
  };
}

/** Probe helper shared by tests: reads a small file entirely (bounded). */
export async function readSmallFile(adapter, target, limit) {
  const stream = adapter.readStream(target);
  const chunks = [];
  let size = 0;
  return new Promise((resolve, reject) => {
    stream.on('data', (chunk) => {
      if (size + chunk.length > limit) {
        stream.destroy();
        resolve({ buffer: Buffer.concat(chunks), truncated: true });
        return;
      }
      chunks.push(chunk);
      size += chunk.length;
    });
    stream.on('error', reject);
    stream.on('end', () => resolve({ buffer: Buffer.concat(chunks), truncated: false }));
  });
}

export { modeToPermissions, modeToOctal, typeOf };
