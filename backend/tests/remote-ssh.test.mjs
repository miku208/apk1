import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { Readable } from 'node:stream';

// Isolated database + short timeouts for the test run.
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lifeform-remote-test-'));
process.env.DATA_DIR = dataDir;
process.env.NODE_ENV = 'test';
process.env.REMOTE_TERMINAL_IDLE_MS = '600000';

const { openDatabase, closeDatabase, query } = await import('../src/db.mjs');
const { startTestSshServer } = await import('./helpers/ssh-server.mjs');

openDatabase();
const servers = await import('../src/remote/servers.mjs');
const connection = await import('../src/remote/connection.mjs');
const files = await import('../src/remote/files.mjs');
const terminal = await import('../src/remote/terminal.mjs');
const transfers = await import('../src/remote/transfers.mjs');
const { subscribe } = await import('../src/events.mjs');

const baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lifeform-remote-'));
const served = fs.realpathSync(fs.mkdtempSync(path.join(baseDir, 'served-')));
fs.mkdirSync(path.join(served, 'work'), { recursive: true });
fs.mkdirSync(path.join(served, 'work', 'sub'), { recursive: true });
fs.writeFileSync(path.join(served, 'work', 'hello.txt'), 'hello world\nsecond line\n');
fs.writeFileSync(path.join(baseDir, 'secret.txt'), 'outside the allowed root\n');
fs.symlinkSync('/etc', path.join(served, 'work', 'escape-link'));
fs.symlinkSync('/etc/passwd', path.join(served, 'work', 'passwd-link'));

const W = (...parts) => path.join(served, ...parts);
const sshd = await startTestSshServer({ root: served, chroot: false });

const events = [];
subscribe((event) => {
  if (event.type.startsWith('remote.')) events.push(event);
});

const auth = { deviceId: 'test-device', deviceName: 'test-device' };
const server = servers.createServer(
  {
    name: 'Local test VPS',
    protocol: 'sftp',
    host: sshd.host,
    port: sshd.port,
    username: sshd.username,
    authType: 'password',
    password: sshd.password,
    remoteRoot: served,
    connectTimeoutMs: 8000,
  },
  auth,
);

test('credentials are stored encrypted and never returned', () => {
  const row = query.get('SELECT * FROM remote_servers WHERE id = ?', server.id);
  assert.ok(row.password_encrypted?.startsWith('v1.'));
  assert.ok(!row.password_encrypted.includes('secret'));
  const pub = servers.publicServer(row);
  assert.equal(pub.hasPassword, true);
  assert.equal(pub.password, undefined);
  assert.equal(JSON.stringify(pub).includes('"secret"'), false);
});

test('host key is not trusted before the owner confirms the fingerprint', async () => {
  const probe = await connection.testServer(server.id);
  assert.equal(probe.ok, false);
  assert.equal(probe.needsTrust, true);
  assert.equal(probe.fingerprint, sshd.fingerprint);

  // A wrong pin must never connect.
  servers.updateServer(server.id, { hostFingerprint: 'SHA256:' + 'A'.repeat(43) }, auth);
  const wrong = await connection.testServer(server.id);
  assert.equal(wrong.ok, false);
  assert.equal(wrong.code, 'HOST_KEY_MISMATCH');

  servers.updateServer(server.id, { hostFingerprint: sshd.fingerprint }, auth);
  const trusted = await connection.testServer(server.id);
  assert.equal(trusted.ok, true, trusted.message);
  assert.equal(trusted.protocol, 'sftp');
});

test('directory listing includes metadata, permissions and owner', async () => {
  const listing = await files.listDirectory({ serverId: server.id, target: W('work') });
  assert.equal(listing.path, W('work'));
  const hello = listing.entries.find((entry) => entry.name === 'hello.txt');
  assert.ok(hello);
  assert.equal(hello.type, 'file');
  assert.equal(hello.size, 24);
  assert.match(hello.permissions, /^[r-][w-][x-]/);
  assert.ok(hello.owner);
  // Breadcrumbs always start at the configured root, then the current dir.
  assert.deepEqual(
    listing.breadcrumbs.map((crumb) => crumb.path),
    [served, W('work')],
  );
});

test('path traversal and symlink escapes are rejected', async () => {
  await assert.rejects(
    () => files.listDirectory({ serverId: server.id, target: '../../etc' }),
    (error) => error.code === 'PATH_ESCAPE',
  );
  await assert.rejects(
    () => files.readFile({ serverId: server.id, target: W('work/escape-link/passwd') }),
    (error) => error.code === 'PATH_ESCAPE',
  );
  await assert.rejects(
    () => files.readFile({ serverId: server.id, target: W('work/passwd-link') }),
    (error) => error.code === 'PATH_ESCAPE',
  );
});

test('read, write with backup + diff, and conflict detection', async () => {
  const before = await files.readFile({ serverId: server.id, target: W('work/hello.txt') });
  assert.equal(before.content, 'hello world\nsecond line\n');
  assert.equal(before.binary, false);

  const preview = await files.previewWrite({
    serverId: server.id,
    target: W('work/hello.txt'),
    content: 'hello world\nsecond line\nthird line\n',
  });
  assert.equal(preview.diff.added, 1);
  assert.equal(preview.diff.removed, 0);

  const written = await files.writeFile({
    serverId: server.id,
    target: W('work/hello.txt'),
    content: 'hello world\nsecond line\nthird line\n',
    expectedModifiedAt: before.modifiedAt,
  });
  assert.ok(written.backupPath);
  assert.ok(fs.existsSync(written.backupPath));
  assert.equal(fs.readFileSync(written.backupPath, 'utf8'), 'hello world\nsecond line\n');
  assert.equal(fs.readFileSync(W('work/hello.txt'), 'utf8'), 'hello world\nsecond line\nthird line\n');

  fs.utimesSync(W('work/hello.txt'), new Date(), new Date(Date.now() + 5000));
  await assert.rejects(
    () =>
      files.writeFile({
        serverId: server.id,
        target: W('work/hello.txt'),
        content: 'stale write',
        expectedModifiedAt: before.modifiedAt,
      }),
    (error) => error.code === 'CONFLICT_MODIFIED',
  );
});

test('sensitive files require explicit confirmation', async () => {
  fs.writeFileSync(W('work/.env'), 'TOKEN=abc\n');
  const read = await files.readFile({ serverId: server.id, target: W('work/.env') });
  assert.equal(read.sensitive, true);
  await assert.rejects(
    () => files.writeFile({ serverId: server.id, target: W('work/.env'), content: 'TOKEN=xyz\n' }),
    (error) => error.code === 'SENSITIVE_CONFIRM_REQUIRED',
  );
  await assert.rejects(() => files.readForAi({ serverId: server.id, target: W('work/.env') }), /sensitif/i);
});

test('upload and download stream through without buffering the whole file', async () => {
  const payload = Buffer.alloc(2 * 1024 * 1024);
  for (let i = 0; i < payload.length; i += 1) payload[i] = i % 251;

  const uploaded = await files.uploadFile({
    serverId: server.id,
    target: W('work/large.bin'),
    stream: Readable.from([payload.subarray(0, 1_000_000), payload.subarray(1_000_000)]),
    size: payload.length,
    deviceId: auth.deviceId,
  });
  assert.equal(uploaded.size, payload.length);
  assert.deepEqual(fs.readFileSync(W('work/large.bin')), payload);

  const sink = new PassThrough();
  const chunks = [];
  sink.on('data', (chunk) => chunks.push(chunk));
  const done = new Promise((resolve) => sink.on('finish', resolve));
  await files.downloadTo({ serverId: server.id, target: W('work/large.bin'), writable: sink, deviceId: auth.deviceId });
  await done;
  const received = Buffer.concat(chunks);
  assert.equal(received.length, payload.length);
  assert.deepEqual(received, payload);

  const listed = transfers.listTransfers({ limit: 10, serverId: server.id });
  assert.ok(listed.some((item) => item.direction === 'upload' && item.status === 'completed'));
  assert.ok(listed.some((item) => item.direction === 'download' && item.status === 'completed'));
  assert.ok(events.some((event) => event.type === 'remote.transfer.completed'));
});

test('upload refuses to overwrite without permission', async () => {
  await assert.rejects(
    () =>
      files.uploadFile({
        serverId: server.id,
        target: W('work/hello.txt'),
        stream: Readable.from([Buffer.from('x')]),
        size: 1,
      }),
    (error) => error.code === 'OVERWRITE_CONFIRM_REQUIRED',
  );
});

test('rename, copy, move, mkdir, search and delete', async () => {
  await files.makeDirectory({ serverId: server.id, target: W('work/newdir') });
  await files.writeFile({ serverId: server.id, target: W('work/newdir/a.txt'), content: 'a' });
  await files.renamePath({ serverId: server.id, target: W('work/newdir/a.txt'), name: 'b.txt' });
  assert.ok(fs.existsSync(W('work/newdir/b.txt')));

  await files.copyPath({ serverId: server.id, target: W('work/newdir/b.txt'), destination: W('work/newdir/c.txt') });
  assert.equal(fs.readFileSync(W('work/newdir/c.txt'), 'utf8'), 'a');

  await files.movePath({ serverId: server.id, target: W('work/newdir/c.txt'), destination: W('work/moved.txt') });
  assert.ok(fs.existsSync(W('work/moved.txt')));

  const found = await files.searchFiles({ serverId: server.id, base: W('work'), query: 'moved' });
  assert.equal(found.count, 1);
  assert.equal(found.results[0].path, W('work/moved.txt'));

  await assert.rejects(() => files.deletePath({ serverId: server.id, target: W('work/moved.txt'), confirm: false }), /konfirmasi/i);
  await files.deletePath({ serverId: server.id, target: W('work/moved.txt'), confirm: true });
  assert.equal(fs.existsSync(W('work/moved.txt')), false);

  await assert.rejects(
    () => files.deletePath({ serverId: server.id, target: W('work/newdir'), confirm: true }),
    (error) => error.code === 'DIRECTORY_NOT_EMPTY',
  );
  await files.deletePath({ serverId: server.id, target: W('work/newdir'), confirm: true, recursive: true });
  assert.equal(fs.existsSync(W('work/newdir')), false);
});

test('interactive PTY keeps state, reports output, resize and Ctrl+C', async () => {
  const session = await terminal.createSession({
    serverId: server.id,
    deviceId: auth.deviceId,
    cwd: W('work/sub'),
    cols: 100,
    rows: 30,
  });
  assert.equal(session.status, 'active');
  assert.equal(session.cols, 100);

  const waitFor = (needle, timeout = 8000) =>
    new Promise((resolve, reject) => {
      const started = Date.now();
      const timer = setInterval(() => {
        const buffer = terminal.sessionBuffer(session.id) ?? '';
        if (buffer.includes(needle)) {
          clearInterval(timer);
          resolve(buffer);
        } else if (Date.now() - started > timeout) {
          clearInterval(timer);
          reject(new Error(`timeout menunggu "${needle}" di: ${buffer.slice(-400)}`));
        }
      }, 50);
    });

  // The PID marker line is consumed by the backend, so wait for the parsed pid.
  const readyDeadline = Date.now() + 8000;
  while (!terminal.getSession(session.id, { deviceId: auth.deviceId }).ptyPid) {
    if (Date.now() > readyDeadline) throw new Error('shell tidak pernah siap');
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  terminal.writeInput(session.id, 'pwd\n', { deviceId: auth.deviceId });
  const afterPwd = await waitFor(W('work/sub'));
  assert.ok(afterPwd.includes(W('work/sub')));

  // State persists between writes: cd then read it back in a second command.
  terminal.writeInput(session.id, `cd ${W('work/newdir2')} 2>/dev/null || mkdir -p ${W('work/newdir2')} && cd ${W('work/newdir2')}\n`, {
    deviceId: auth.deviceId,
  });
  terminal.writeInput(session.id, 'echo MARKER-$(basename "$PWD")\n', { deviceId: auth.deviceId });
  const afterCd = await waitFor('MARKER-newdir2');
  assert.ok(afterCd.includes('MARKER-newdir2'));

  const resized = terminal.resizeSession(session.id, { cols: 120, rows: 40, deviceId: auth.deviceId });
  assert.deepEqual(resized, { cols: 120, rows: 40 });

  // A long-running process must be interruptible with Ctrl+C.
  terminal.writeInput(session.id, 'sleep 30\n', { deviceId: auth.deviceId });
  await new Promise((resolve) => setTimeout(resolve, 300));
  terminal.interruptSession(session.id, { deviceId: auth.deviceId });
  terminal.writeInput(session.id, 'echo AFTER-INT\n', { deviceId: auth.deviceId });
  const afterInt = await waitFor('AFTER-INT');
  assert.ok(afterInt.includes('AFTER-INT'));

  const detail = terminal.getSession(session.id, { deviceId: auth.deviceId });
  assert.equal(detail.live, true);
  assert.ok(detail.ptyPid > 0);
  assert.ok(events.some((event) => event.type === 'remote.terminal.output'));

  terminal.closeSession(session.id, 'test-done');
  assert.equal(terminal.getSession(session.id).live, false);
});

test('terminal output is bounded', async () => {
  const session = await terminal.createSession({ serverId: server.id, deviceId: auth.deviceId, cwd: W('work') });
  await new Promise((resolve) => setTimeout(resolve, 400));
  terminal.writeInput(session.id, "for i in $(seq 1 20000); do echo 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; done\n", {
    deviceId: auth.deviceId,
  });
  await new Promise((resolve) => setTimeout(resolve, 2500));
  const buffer = terminal.sessionBuffer(session.id);
  assert.ok(Buffer.byteLength(buffer) <= 256 * 1024, `buffer ${Buffer.byteLength(buffer)} bytes`);
  terminal.closeSession(session.id, 'bounded-test');
});

test('restart recovery never claims dead sessions are alive', async () => {
  const session = await terminal.createSession({ serverId: server.id, deviceId: auth.deviceId, cwd: W('work') });
  terminal.closeSession(session.id, 'simulate-crash', { silent: true });
  query.run("UPDATE remote_terminal_sessions SET status = 'active' WHERE id = ?", session.id);
  const recovered = terminal.recoverSessionsOnStartup();
  assert.ok(recovered >= 1);
  const row = query.get('SELECT status, close_reason FROM remote_terminal_sessions WHERE id = ?', session.id);
  assert.equal(row.status, 'disconnected');
  assert.equal(row.close_reason, 'backend-restart');
});

test('unauthenticated SSH credentials are rejected', async () => {
  servers.updateServer(server.id, { password: 'wrong-password' }, auth);
  connection.closeServer(server.id, 'test');
  const result = await connection.testServer(server.id);
  assert.equal(result.ok, false);
  assert.notEqual(result.code, undefined);
  // Restore for any later run.
  servers.updateServer(server.id, { password: sshd.password }, auth);
});

test.after(async () => {
  terminal.stopTerminalSweeper();
  terminal.closeAllSessions('test-over');
  connection.closeAllConnections();
  await sshd.close();
  closeDatabase();
  fs.rmSync(dataDir, { recursive: true, force: true });
  fs.rmSync(baseDir, { recursive: true, force: true });
});
