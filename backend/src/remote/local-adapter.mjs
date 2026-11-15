// Local runtime adapter for the Primary VPS. All operations run directly on
// this host (no SSH), so host keys, fingerprints and remote credentials do not
// apply. The interface matches the SFTP adapter used by the file manager and
// the interactive terminal.
import fs from 'node:fs/promises';
import fssync from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn, execFile } from 'node:child_process';
import { PassThrough } from 'node:stream';
import { posix as remotePosix } from './paths.mjs';

function modeToPermissions(mode) {
  if (!Number.isFinite(mode)) return null;
  const bits = mode & 0o777;
  const chars = ['r', 'w', 'x'];
  let out = '';
  for (let i = 2; i >= 0; i -= 1) {
    for (let b = 0; b < 3; b += 1) out += (bits >> (i * 3 + (2 - b))) & 1 ? chars[b] : '-';
  }
  return out;
}

function modeToOctal(mode) {
  return Number.isFinite(mode) ? `0${(mode & 0o777).toString(8).padStart(3, '0')}` : null;
}

function typeOf(stat) {
  if (stat.isDirectory()) return 'directory';
  if (stat.isSymbolicLink()) return 'symlink';
  return 'file';
}

async function ownerNames(uid, gid) {
  let owner = String(uid ?? '');
  let group = String(gid ?? '');
  try {
    const { stdout } = await new Promise((resolve) => {
      execFile('getent', ['passwd', String(uid)], { timeout: 2000 }, (error, stdout) => resolve({ stdout: error ? '' : stdout }));
    });
    const name = stdout.split(':')[0];
    if (name) owner = name;
  } catch { /* ignore */ }
  try {
    const { stdout } = await new Promise((resolve) => {
      execFile('getent', ['group', String(gid)], { timeout: 2000 }, (error, stdout) => resolve({ stdout: error ? '' : stdout }));
    });
    const name = stdout.split(':')[0];
    if (name) group = name;
  } catch { /* ignore */ }
  return { owner, group };
}

async function describe(target, stat, lstat = null) {
  const lst = lstat ?? stat;
  const type = typeOf(lst);
  const { owner, group } = await ownerNames(lst.uid, lst.gid);
  let symlinkTarget = null;
  if (type === 'symlink') {
    try { symlinkTarget = await fs.readlink(target); } catch { symlinkTarget = null; }
  }
  return {
    name: path.posix.basename(target),
    path: target,
    type,
    size: Number(lst.size ?? 0),
    mode: modeToOctal(lst.mode),
    permissions: modeToPermissions(lst.mode),
    uid: lst.uid ?? null,
    gid: lst.gid ?? null,
    owner,
    group,
    modifiedAt: lst.mtimeMs ? Math.round(lst.mtimeMs) : null,
    accessedAt: lst.atimeMs ? Math.round(lst.atimeMs) : null,
    isSymlink: type === 'symlink',
    symlinkTarget,
  };
}

function normalizeLocal(target) {
  const resolved = path.posix.normalize(String(target ?? '/'));
  return resolved || '/';
}

export function createLocalAdapter({ server } = {}) {
  let closed = false;

  async function exec(command, { timeoutMs = 15000 } = {}) {
    return new Promise((resolve, reject) => {
      const child = spawn('bash', ['-c', String(command ?? '')], {
        cwd: '/',
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => {
        try { child.kill('SIGTERM'); } catch { /* ignore */ }
        reject(new Error('Perintah lokal melewati batas waktu.'));
      }, timeoutMs);
      child.stdout.on('data', (chunk) => { if (stdout.length < 2_000_000) stdout += chunk.toString('utf8'); });
      child.stderr.on('data', (chunk) => { if (stderr.length < 200_000) stderr += chunk.toString('utf8'); });
      child.on('error', (error) => { clearTimeout(timer); reject(error); });
      child.on('close', (code) => { clearTimeout(timer); resolve({ stdout, stderr, exitCode: typeof code === 'number' ? code : null }); });
    });
  }

  return {
    protocol: 'local',
    server,
    supportsTerminal: true,
    runtime: 'local',

    async list(directory) {
      const dir = normalizeLocal(directory);
      const names = await fs.readdir(dir);
      const entries = await Promise.all(names.map(async (name) => {
        const target = remotePosix.join(dir, name);
        try {
          const lst = await fs.lstat(target);
          const st = lst.isSymbolicLink() ? await fs.stat(target).catch(() => lst) : lst;
          return describe(target, st, lst);
        } catch {
          return null;
        }
      }));
      return entries.filter(Boolean);
    },

    async stat(target) {
      const p = normalizeLocal(target);
      const st = await fs.stat(p);
      return describe(p, st, st);
    },

    async lstat(target) {
      const p = normalizeLocal(target);
      const lst = await fs.lstat(p);
      const st = lst.isSymbolicLink() ? await fs.stat(p).catch(() => lst) : lst;
      return describe(p, st, lst);
    },

    async exists(target) {
      try { await fs.lstat(normalizeLocal(target)); return true; } catch { return false; }
    },

    async realpath(target) {
      return fs.realpath(normalizeLocal(target));
    },

    async mkdir(target) {
      await fs.mkdir(normalizeLocal(target));
    },

    async rmdir(target) {
      await fs.rmdir(normalizeLocal(target));
    },

    async unlink(target) {
      await fs.unlink(normalizeLocal(target));
    },

    async rename(from, to) {
      await fs.rename(normalizeLocal(from), normalizeLocal(to));
    },

    async chmod(target, mode) {
      await fs.chmod(normalizeLocal(target), mode);
    },

    readStream(target) {
      return fssync.createReadStream(normalizeLocal(target));
    },

    async writeFile(target, buffer, { mode = null } = {}) {
      const file = normalizeLocal(target);
      const dir = path.posix.dirname(file);
      const temp = path.posix.join(dir, `.${path.posix.basename(file)}.lifeform-${Date.now()}.tmp`);
      await fs.writeFile(temp, buffer, mode ? { mode } : {});
      try {
        await fs.rename(temp, file);
      } catch (error) {
        await fs.unlink(temp).catch(() => {});
        throw error;
      }
    },

    async upload(target, readable, { onProgress = null, mode = null } = {}) {
      const file = normalizeLocal(target);
      const dir = path.posix.dirname(file);
      const temp = path.posix.join(dir, `.${path.posix.basename(file)}.lifeform-${Date.now()}.tmp`);
      const writable = fssync.createWriteStream(temp, mode ? { mode } : {});
      let bytes = 0;
      await new Promise((resolve, reject) => {
        readable.on('data', (chunk) => { bytes += chunk.length; onProgress?.(bytes); });
        readable.on('error', reject);
        writable.on('error', reject);
        writable.on('close', resolve);
        readable.pipe(writable);
      });
      try {
        await fs.rename(temp, file);
      } catch (error) {
        await fs.unlink(temp).catch(() => {});
        throw error;
      }
      return bytes;
    },

    async download(target, writable, { onProgress = null } = {}) {
      const stream = fssync.createReadStream(normalizeLocal(target));
      let bytes = 0;
      await new Promise((resolve, reject) => {
        stream.on('data', (chunk) => { bytes += chunk.length; onProgress?.(bytes); });
        stream.on('error', reject);
        writable.on('error', reject);
        writable.on('finish', resolve);
        stream.pipe(writable);
      });
      return bytes;
    },

    async statvfs(target) {
      try {
        const stats = await fs.statfs(normalizeLocal(target));
        const blockSize = Number(stats.bsize ?? 4096);
        return {
          totalBytes: blockSize * Number(stats.blocks ?? 0),
          freeBytes: blockSize * Number(stats.bavail ?? stats.bfree ?? 0),
        };
      } catch {
        return null;
      }
    },

    exec,

    shell({ cols = 80, rows = 24, term = 'xterm-256color' } = {}) {
      return new Promise((resolve, reject) => {
        const safeCols = Math.max(20, Math.min(400, Number(cols) || 80));
        const safeRows = Math.max(5, Math.min(200, Number(rows) || 24));
        // Real PTY via python: job control, Ctrl+C, arrows, resize via control fd.
        const code = [
          'import pty,os,sys,fcntl,termios,struct,select',
          'pid,fd=pty.fork()',
          'if pid==0:',
          '  os.environ["TERM"]=' + JSON.stringify(term),
          `  fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", ${safeRows}, ${safeCols}, 0, 0))`,
          '  shell=os.environ.get("SHELL") or "/bin/bash"',
          '  os.execvp(shell,[shell,"-l"])',
          'ctl=os.fdopen(3,"r",1)',
          'ctlbuf=""',
          'def handle_ctl():',
          '  global ctlbuf',
          '  try: d=os.read(3,4096)',
          '  except Exception: return False',
          '  if not d: return False',
          '  ctlbuf += d.decode("utf8","ignore")',
          '  while "\\n" in ctlbuf:',
          '    line,ctlbuf = ctlbuf.split("\\n",1)',
          '    parts=line.strip().split()',
          '    if len(parts)==2:',
          '      try:',
          '        r=int(parts[0]); c=int(parts[1])',
          '        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", max(5,min(200,r)), max(20,min(400,c)), 0, 0))',
          '      except Exception: pass',
          '  return True',
          'sys.stdout.write("READY\\n")',
          'sys.stdout.flush()',
          'alive=True',
          'try:',
          '  while alive:',
          '    watch=[0,fd,3]',
          '    r,_,_=select.select(watch,[],[],30)',
          '    if 0 in r:',
          '      d=os.read(0,65536)',
          '      if not d: break',
          '      if d: os.write(fd,d)',
          '    if 3 in r:',
          '      alive = handle_ctl()',
          '    if fd in r:',
          '      try: d=os.read(fd,65536)',
          '      except OSError: break',
          '      if not d: break',
          '      os.write(1,d)',
          'except Exception: pass',
          'try: os.kill(pid,15)',
          'except Exception: pass',
        ].join('\n');

        const child = spawn('python3', ['-u', '-c', code], {
          cwd: '/',
          env: { ...process.env, TERM: term },
          stdio: ['pipe', 'pipe', 'pipe', 'pipe'],
        });

        let headerDone = false;
        let headerBuf = '';
        const out = new PassThrough();
        const err = new PassThrough();
        const ctl = child.stdio[3];

        const fail = (error) => { try { child.kill('SIGTERM'); } catch { /* */ } reject(error); };
        child.on('error', fail);
        child.stderr.on('data', (chunk) => err.write(chunk));

        // `stream.write` is the shell's input, so the readable side must not go
        // through that override: write PTY output straight to the PassThrough.
        const emitOut = (chunk) => PassThrough.prototype.write.call(out, chunk);
        const endOut = () => PassThrough.prototype.end.call(out);

        child.stdout.on('data', (chunk) => {
          if (headerDone) { emitOut(chunk); return; }
          headerBuf += chunk.toString('utf8');
          if (headerBuf.startsWith('READY\n')) {
            headerDone = true;
            const rest = headerBuf.slice('READY\n'.length);
            if (rest) emitOut(Buffer.from(rest, 'utf8'));

            const stream = out;
            stream.stderr = err;
            stream.write = (data) => child.stdin.write(data);
            stream.end = () => { try { child.stdin.end(); } catch { /* */ } try { ctl?.end?.(); } catch { /* */ } };
            stream.destroy = () => { try { child.kill('SIGTERM'); } catch { /* */ } };
            stream.setWindow = (rows2, cols2) => {
              try {
                const r = Math.max(5, Math.min(200, Number(rows2) || safeRows));
                const c = Math.max(20, Math.min(400, Number(cols2) || safeCols));
                ctl.write(`${r} ${c}\n`);
              } catch { /* ignore */ }
            };
            child.on('close', () => { endOut(); err.end(); });
            resolve(stream);
          }
        });

        setTimeout(() => {
          if (!headerDone) fail(new Error('Gagal memulai terminal lokal (timeout).'));
        }, 5000);
      });
    },

    close() {
      closed = true;
    },

    get closed() {
      return closed;
    },
  };
}
