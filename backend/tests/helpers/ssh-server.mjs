// In-process SSH/SFTP/PTY server for integration tests. It serves a real
// temporary directory and a real bash shell, so the client code under test is
// exercised end to end without touching the host's sshd.
import ssh2 from 'ssh2';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';

const { Server, utils } = ssh2;

// ssh2 OPEN flags
const FLAG = { READ: 0x1, WRITE: 0x2, APPEND: 0x4, CREAT: 0x8, TRUNC: 0x10, EXCL: 0x20 };

function openFlagsToString(flags) {
  const write = Boolean(flags & FLAG.WRITE);
  if (flags & FLAG.APPEND) return write ? 'a+' : 'a';
  if (write && flags & FLAG.CREAT) {
    if (flags & FLAG.TRUNC) return flags & FLAG.EXCL ? 'wx' : 'w+';
    return 'r+';
  }
  if (flags & FLAG.CREAT) return 'w';
  return 'r';
}

function statAttrs(target) {
  const stat = fs.lstatSync(target);
  return {
    mode: stat.mode,
    uid: stat.uid,
    gid: stat.gid,
    size: stat.size,
    atime: Math.floor(stat.atimeMs / 1000),
    mtime: Math.floor(stat.mtimeMs / 1000),
  };
}

function sftpEntries(directory) {
  return fs.readdirSync(directory).map((name) => {
    const full = path.join(directory, name);
    const stat = fs.lstatSync(full);
    const type = stat.isDirectory() ? 'd' : stat.isSymbolicLink() ? 'l' : '-';
    return {
      filename: name,
      longname: `${type}rw-r--r-- 1 tester tester ${stat.size} ${name}`,
      attrs: {
        mode: stat.mode,
        uid: stat.uid,
        gid: stat.gid,
        size: stat.size,
        atime: Math.floor(stat.atimeMs / 1000),
        mtime: Math.floor(stat.mtimeMs / 1000),
      },
    };
  });
}

function handleSftp(sftp, root, { chroot = true } = {}) {
  const handles = new Map();
  let nextHandle = 1;
  // chroot=true maps SFTP "/x" onto <root>/x (like an isolated SFTP account).
  // chroot=false serves the real filesystem, which lets the PTY shell use the
  // same absolute paths as SFTP (needed to test "open directory in terminal").
  const resolve = (raw) =>
    chroot
      ? path.resolve(root, `.${path.posix.resolve('/', raw)}`)
      : path.resolve('/', path.posix.resolve('/', raw));
  const ok = (reqid) => sftp.status(reqid, ssh2.utils.sftp.STATUS_CODE.OK);
  const fail = (reqid, code = ssh2.utils.sftp.STATUS_CODE.FAILURE) => sftp.status(reqid, code);

  sftp.on('REALPATH', (reqid, name) => {
    const target = resolve(name || '/');
    try {
      const real = fs.realpathSync(target);
      sftp.name(reqid, [{ filename: real, longname: real, attrs: statAttrs(real) }]);
    } catch {
      fail(reqid, ssh2.utils.sftp.STATUS_CODE.NO_SUCH_FILE);
    }
  });

  sftp.on('STAT', (reqid, name) => {
    try {
      sftp.attrs(reqid, statAttrs(resolve(name)));
    } catch {
      fail(reqid, ssh2.utils.sftp.STATUS_CODE.NO_SUCH_FILE);
    }
  });

  sftp.on('LSTAT', (reqid, name) => {
    try {
      sftp.attrs(reqid, statAttrs(resolve(name)));
    } catch {
      fail(reqid, ssh2.utils.sftp.STATUS_CODE.NO_SUCH_FILE);
    }
  });

  sftp.on('FSTAT', (reqid, handle) => {
    const entry = handles.get(handle.toString());
    if (!entry) return fail(reqid);
    try {
      sftp.attrs(reqid, statAttrs(entry.path));
    } catch {
      fail(reqid);
    }
  });

  sftp.on('OPENDIR', (reqid, name) => {
    const target = resolve(name);
    try {
      if (!fs.statSync(target).isDirectory()) return fail(reqid);
      const id = String(nextHandle++);
      handles.set(id, { type: 'dir', path: target });
      sftp.handle(reqid, Buffer.from(id));
    } catch {
      fail(reqid, ssh2.utils.sftp.STATUS_CODE.NO_SUCH_FILE);
    }
  });

  sftp.on('READDIR', (reqid, handle) => {
    const entry = handles.get(handle.toString());
    if (!entry || entry.type !== 'dir') return fail(reqid);
    if (entry.read) {
      return fail(reqid, ssh2.utils.sftp.STATUS_CODE.EOF);
    }
    entry.read = true;
    try {
      sftp.name(reqid, sftpEntries(entry.path));
    } catch {
      fail(reqid);
    }
  });

  sftp.on('OPEN', (reqid, name, flags) => {
    const target = resolve(name);
    try {
      const fd = fs.openSync(target, openFlagsToString(flags));
      const id = String(nextHandle++);
      handles.set(id, { type: 'file', path: target, fd });
      sftp.handle(reqid, Buffer.from(id));
    } catch (error) {
      const code = error.code === 'ENOENT' ? ssh2.utils.sftp.STATUS_CODE.NO_SUCH_FILE : ssh2.utils.sftp.STATUS_CODE.FAILURE;
      fail(reqid, code);
    }
  });

  sftp.on('READ', (reqid, handle, offset, length) => {
    const entry = handles.get(handle.toString());
    if (!entry || entry.type !== 'file') return fail(reqid);
    const buffer = Buffer.alloc(length);
    const bytes = fs.readSync(entry.fd, buffer, 0, length, offset);
    if (bytes === 0) return fail(reqid, ssh2.utils.sftp.STATUS_CODE.EOF);
    sftp.data(reqid, buffer.subarray(0, bytes));
  });

  sftp.on('WRITE', (reqid, handle, offset, data) => {
    const entry = handles.get(handle.toString());
    if (!entry || entry.type !== 'file') return fail(reqid);
    fs.writeSync(entry.fd, data, 0, data.length, offset);
    ok(reqid);
  });

  sftp.on('CLOSE', (reqid, handle) => {
    const id = handle.toString();
    const entry = handles.get(id);
    if (!entry) return fail(reqid);
    if (entry.type === 'file') fs.closeSync(entry.fd);
    handles.delete(id);
    ok(reqid);
  });

  sftp.on('MKDIR', (reqid, name) => {
    try {
      fs.mkdirSync(resolve(name));
      ok(reqid);
    } catch {
      fail(reqid);
    }
  });

  sftp.on('RMDIR', (reqid, name) => {
    try {
      fs.rmdirSync(resolve(name));
      ok(reqid);
    } catch {
      fail(reqid);
    }
  });

  sftp.on('REMOVE', (reqid, name) => {
    try {
      fs.unlinkSync(resolve(name));
      ok(reqid);
    } catch {
      fail(reqid);
    }
  });

  sftp.on('RENAME', (reqid, from, to) => {
    try {
      fs.renameSync(resolve(from), resolve(to));
      ok(reqid);
    } catch {
      fail(reqid);
    }
  });

  sftp.on('SETSTAT', (reqid, name, attrs) => {
    try {
      if (attrs?.mode) fs.chmodSync(resolve(name), attrs.mode);
      ok(reqid);
    } catch {
      fail(reqid);
    }
  });

  sftp.on('READLINK', (reqid, name) => {
    try {
      sftp.name(reqid, [{ filename: fs.readlinkSync(resolve(name)), longname: '', attrs: {} }]);
    } catch {
      fail(reqid);
    }
  });

  sftp.on('EXTENDED', (reqid) => fail(reqid, ssh2.utils.sftp.STATUS_CODE.OP_UNSUPPORTED));
}

export async function startTestSshServer({ root, username = 'tester', password = 'secret', shellCwd = null, chroot = true } = {}) {
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  const children = new Set();

  const server = new Server({ hostKeys: [privateKey] }, (client) => {
    // A client may abort during key exchange (that is exactly what the
    // fingerprint probe does), so never let that crash the test process.
    client.on('error', () => {});
    client.on('close', () => {});
    client.on('authentication', (ctx) => {
      if (ctx.method === 'password' && ctx.username === username && ctx.password === password) ctx.accept();
      else ctx.reject(['password']);
    });
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept();
        let pty = null;
        session.on('pty', (acceptPty) => {
          pty = true;
          acceptPty?.();
        });
        session.on('window-change', (acceptChange) => acceptChange?.());
        session.on('shell', (acceptShell) => {
          const stream = acceptShell();
          const child = spawn('bash', ['--norc', '-i'], {
            cwd: shellCwd ?? root,
            env: { ...process.env, PS1: 'test$ ', TERM: 'xterm-256color', HOME: root },
            detached: true, // own process group so Ctrl+C can signal the foreground job
          });
          children.add(child);
          child.stdout.pipe(stream);
          child.stderr.pipe(stream);
          stream.pipe(child.stdin);
          // Emulate the kernel PTY line discipline for the one control character
          // the tests rely on: Ctrl+C must signal the foreground child.
          stream.on('data', (chunk) => {
            if (chunk.includes(3)) {
              try {
                process.kill(-child.pid, 'SIGINT');
              } catch {
                try {
                  child.kill('SIGINT');
                } catch {
                  /* ignore */
                }
              }
            }
          });
          stream.on('close', () => {
            try {
              process.kill(-child.pid, 'SIGKILL');
            } catch {
              child.kill('SIGKILL');
            }
            children.delete(child);
          });
          child.on('exit', () => {
            try {
              stream.exit(0);
              stream.end();
            } catch {
              /* ignore */
            }
          });
        });
        session.on('exec', (acceptExec, rejectExec, info) => {
          const stream = acceptExec();
          const child = spawn('bash', ['-c', info.command], { cwd: root });
          children.add(child);
          child.stdout.pipe(stream);
          child.stderr.pipe(stream);
          child.on('exit', (code) => {
            children.delete(child);
            stream.exit(code ?? 0);
            stream.end();
          });
        });
        session.on('sftp', (acceptSftp) => {
          const sftp = acceptSftp();
          handleSftp(sftp, root, { chroot });
        });
      });
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const hostKey = utils.parseKey(privateKey);
  const fingerprint = `SHA256:${crypto.createHash('sha256').update(hostKey.getPublicSSH()).digest('base64').replace(/=+$/, '')}`;

  return {
    server,
    port,
    host: '127.0.0.1',
    username,
    password,
    fingerprint,
    async close() {
      for (const child of children) {
        try {
          process.kill(-child.pid, 'SIGKILL');
        } catch {
          child.kill('SIGKILL');
        }
      }
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
