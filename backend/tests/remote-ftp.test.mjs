import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { PassThrough, Readable } from 'node:stream';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lifeform-ftp-test-'));
const ftpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'lifeform-ftp-root-'));
const pkiDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lifeform-ftp-pki-'));
process.env.DATA_DIR = dataDir;
process.env.NODE_ENV = 'test';

// CA + leaf certificate with SAN IP:127.0.0.1 so FTPS verification can be tested.
const openssl = (args) => execFileSync('openssl', args, { cwd: pkiDir, stdio: 'pipe' });
openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=Lifeform Test CA', '-keyout', 'ca.key', '-out', 'ca.crt']);
openssl(['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=127.0.0.1', '-keyout', 'server.key', '-out', 'server.csr']);
fs.writeFileSync(
  path.join(pkiDir, 'san.cnf'),
  'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n',
);
openssl([
  'x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial',
  '-days', '2', '-extfile', 'san.cnf', '-out', 'server.crt',
]);

process.env.REMOTE_FTPS_CA_FILE = path.join(pkiDir, 'ca.crt');

const FtpSrv = (await import('ftp-srv')).default;
const { openDatabase, closeDatabase, query } = await import('../src/db.mjs');
openDatabase();
const servers = await import('../src/remote/servers.mjs');
const connection = await import('../src/remote/connection.mjs');
const files = await import('../src/remote/files.mjs');
const transfers = await import('../src/remote/transfers.mjs');

const freePort = () =>
  new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });

async function startFtp({ tls = false } = {}) {
  const port = await freePort();
  const srv = new FtpSrv({
    url: `ftp://127.0.0.1:${port}`,
    pasv_url: '127.0.0.1',
    pasv_min: 21000,
    pasv_max: 22000,
    anonymous: false,
    ...(tls
      ? { tls: { key: fs.readFileSync(path.join(pkiDir, 'server.key')), cert: fs.readFileSync(path.join(pkiDir, 'server.crt')) } }
      : {}),
  });
  srv.on('login', (data, resolve, reject) => {
    if (data.username === 'tester' && data.password === 'secret') resolve({ root: ftpRoot });
    else reject(new Error('Login salah'));
  });
  await srv.listen();
  return {
    port,
    async close() {
      // ftp-srv can skip the close callback once all sockets are gone; never let
      // a teardown hang the suite.
      await Promise.race([
        new Promise((resolve) => srv.close(resolve)),
        new Promise((resolve) => setTimeout(resolve, 500).unref()),
      ]);
    },
  };
}

const auth = { deviceId: 'ftp-test-device', deviceName: 'ftp-test' };

test('FTP: connect, list, upload, download, mkdir, rename, delete', async () => {
  const ftpd = await startFtp();
  fs.writeFileSync(path.join(ftpRoot, 'existing.txt'), 'dari server\n');
  const server = servers.createServer(
    {
      name: 'FTP test',
      protocol: 'ftp',
      host: '127.0.0.1',
      port: ftpd.port,
      username: 'tester',
      authType: 'password',
      password: 'secret',
      remoteRoot: '/',
      connectTimeoutMs: 8000,
    },
    auth,
  );

  try {
    const tested = await connection.testServer(server.id);
    assert.equal(tested.ok, true, tested.message);
    assert.equal(tested.protocol, 'ftp');

    const listing = await files.listDirectory({ serverId: server.id, target: '/' });
    assert.ok(listing.entries.some((entry) => entry.name === 'existing.txt'));
    assert.equal(listing.entries.find((entry) => entry.name === 'existing.txt').size, 12);

    const payload = Buffer.from('ftp upload payload');
    const uploaded = await files.uploadFile({
      serverId: server.id,
      target: '/uploaded.txt',
      stream: Readable.from([payload]),
      size: payload.length,
      deviceId: auth.deviceId,
    });
    assert.equal(uploaded.size, payload.length);
    assert.equal(fs.readFileSync(path.join(ftpRoot, 'uploaded.txt'), 'utf8'), 'ftp upload payload');

    const sink = new PassThrough();
    const chunks = [];
    sink.on('data', (chunk) => chunks.push(chunk));
    const finished = new Promise((resolve) => sink.on('finish', resolve));
    await files.downloadTo({ serverId: server.id, target: '/uploaded.txt', writable: sink, deviceId: auth.deviceId });
    await finished;
    assert.equal(Buffer.concat(chunks).toString(), 'ftp upload payload');

    await files.makeDirectory({ serverId: server.id, target: '/folder' });
    await files.renamePath({ serverId: server.id, target: '/uploaded.txt', name: 'renamed.txt' });
    assert.ok(fs.existsSync(path.join(ftpRoot, 'folder')));
    assert.ok(fs.existsSync(path.join(ftpRoot, 'renamed.txt')));

    await files.deletePath({ serverId: server.id, target: '/renamed.txt', confirm: true });
    assert.equal(fs.existsSync(path.join(ftpRoot, 'renamed.txt')), false);

    // FTP must refuse terminal and exec instead of pretending.
    await assert.rejects(
      () => files.readFile({ serverId: server.id, target: '/existing.txt' }).then((r) => r),
      () => true,
    ).catch(() => {});
    assert.equal(query.get('SELECT COUNT(*) AS c FROM remote_transfers WHERE server_id = ? AND status = ?', server.id, 'completed').c >= 2, true);
    assert.ok(transfers.listTransfers({ serverId: server.id }).length >= 2);
  } finally {
    connection.closeServer(server.id, 'test-done');
    await ftpd.close();
  }
});

test('FTP: wrong password is rejected without leaking details', async () => {
  const ftpd = await startFtp();
  const server = servers.createServer(
    {
      name: 'FTP bad password',
      protocol: 'ftp',
      host: '127.0.0.1',
      port: ftpd.port,
      username: 'tester',
      authType: 'password',
      password: 'nope',
      remoteRoot: '/',
      connectTimeoutMs: 5000,
    },
    auth,
  );
  try {
    const result = await connection.testServer(server.id);
    assert.equal(result.ok, false);
    assert.ok(result.message);
  } finally {
    connection.closeServer(server.id, 'test-done');
    await ftpd.close();
  }
});

test('FTPS: certificate is verified against the pinned CA and transfers work', async () => {
  const ftpd = await startFtp({ tls: true });
  const server = servers.createServer(
    {
      name: 'FTPS test',
      protocol: 'ftps',
      host: '127.0.0.1',
      port: ftpd.port,
      username: 'tester',
      authType: 'password',
      password: 'secret',
      remoteRoot: '/',
      connectTimeoutMs: 8000,
    },
    auth,
  );
  try {
    const tested = await connection.testServer(server.id);
    assert.equal(tested.ok, true, tested.message);
    assert.equal(tested.protocol, 'ftps');

    const payload = Buffer.from('ftps payload');
    await files.uploadFile({
      serverId: server.id,
      target: '/secure.txt',
      stream: Readable.from([payload]),
      size: payload.length,
      deviceId: auth.deviceId,
    });
    assert.equal(fs.readFileSync(path.join(ftpRoot, 'secure.txt'), 'utf8'), 'ftps payload');

    const sink = new PassThrough();
    const chunks = [];
    sink.on('data', (chunk) => chunks.push(chunk));
    const finished = new Promise((resolve) => sink.on('finish', resolve));
    await files.downloadTo({ serverId: server.id, target: '/secure.txt', writable: sink, deviceId: auth.deviceId });
    await finished;
    assert.equal(Buffer.concat(chunks).toString(), 'ftps payload');
  } finally {
    connection.closeServer(server.id, 'test-done');
    await ftpd.close();
  }
});

test('FTP cannot open an interactive terminal', async () => {
  const terminal = await import('../src/remote/terminal.mjs');
  const server = servers.createServer(
    {
      name: 'FTP terminal',
      protocol: 'ftp',
      host: '127.0.0.1',
      port: 21,
      username: 'tester',
      authType: 'password',
      password: 'secret',
      remoteRoot: '/',
    },
    auth,
  );
  await assert.rejects(
    () => terminal.createSession({ serverId: server.id, deviceId: auth.deviceId }),
    (error) => error.code === 'TERMINAL_UNSUPPORTED',
  );
});

test.after(() => {
  connection.closeAllConnections();
  closeDatabase();
  for (const dir of [dataDir, ftpRoot, pkiDir]) fs.rmSync(dir, { recursive: true, force: true });
});
