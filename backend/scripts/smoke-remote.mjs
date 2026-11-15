#!/usr/bin/env node
// End-to-end check of VPS Remote Control over the real HTTP API.
// Starts a throwaway SSH/SFTP server locally, registers it through the API,
// then exercises file transfer, search, terminal and audit endpoints.
//
// Usage: node scripts/smoke-remote.mjs <pairing-code> [baseUrl]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import WebSocket from 'ws';
import { startTestSshServer } from '../tests/helpers/ssh-server.mjs';

const code = process.argv[2];
const base = (process.argv[3] ?? 'http://127.0.0.1:8888').replace(/\/+$/, '');
if (!code) {
  console.error('usage: node scripts/smoke-remote.mjs <pairing-code> [baseUrl]');
  process.exit(1);
}

const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
};

let token = null;
async function api(method, route, body, extraHeaders = {}) {
  const res = await fetch(`${base}/api/v1${route}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...extraHeaders,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json, headers: res.headers };
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lifeform-smoke-remote-'));
fs.mkdirSync(path.join(root, 'work', 'logs'), { recursive: true });
fs.writeFileSync(path.join(root, 'work', 'app.js'), 'console.log("hello");\n');
fs.writeFileSync(path.join(root, 'work', 'logs', 'app.log'), 'boot ok\n');
// chroot:false keeps SFTP paths identical to the real paths the PTY shell sees.
const sshd = await startTestSshServer({ root, chroot: false });

async function main() {
  const paired = await api('POST', '/auth/pair', { code, deviceName: 'remote-smoke' });
  token = paired.json?.accessToken;
  check('pairing', Boolean(token));

  // --server management--
  const created = await api('POST', '/remote/servers', {
    name: 'Smoke VPS',
    protocol: 'sftp',
    host: sshd.host,
    port: sshd.port,
    username: sshd.username,
    authType: 'password',
    password: sshd.password,
    remoteRoot: root,
    connectTimeoutMs: 8000,
  });
  const serverId = created.json?.server?.id;
  check('create server', created.status === 201 && Boolean(serverId));
  check('password tidak dikembalikan', !JSON.stringify(created.json).includes(sshd.password));

  const untrusted = await api('POST', `/remote/servers/${serverId}/test`);
  check(
    'host key harus dipercaya dulu',
    untrusted.json?.needsTrust === true && untrusted.json?.fingerprint === sshd.fingerprint,
    untrusted.json?.fingerprint,
  );

  await api('PUT', `/remote/servers/${serverId}`, { hostFingerprint: sshd.fingerprint });
  const tested = await api('POST', `/remote/servers/${serverId}/test`);
  check('test connection setelah trust', tested.json?.ok === true, `${tested.json?.latencyMs}ms`);

  // --file manager--
  const list = await api('GET', `/remote/files/list?serverId=${serverId}&path=${encodeURIComponent(`${root}/work`)}&sort=name`);
  const names = (list.json?.entries ?? []).map((entry) => entry.name);
  check('list direktori', names.includes('app.js') && names.includes('logs'), names.join(', '));

  const read = await api('GET', `/remote/files/read?serverId=${serverId}&path=${encodeURIComponent(`${root}/work/app.js`)}`);
  check('baca file', read.json?.content?.includes('hello'));

  const diff = await api('POST', '/remote/files/diff', {
    serverId,
    path: `${root}/work/app.js`,
    content: 'console.log("hello world");\n',
  });
  check('preview diff', diff.json?.diff?.added === 1 && diff.json?.diff?.removed === 1);

  const wrote = await api('POST', '/remote/files/write', {
    serverId,
    path: `${root}/work/app.js`,
    content: 'console.log("hello world");\n',
    expectedModifiedAt: read.json?.modifiedAt,
  });
  check('simpan file + backup', wrote.status === 200 && Boolean(wrote.json?.backupPath));

  // streaming upload as raw binary body
  const uploadBody = Buffer.from('a'.repeat(300_000));
  const upload = await fetch(
    `${base}/api/v1/remote/files/upload?serverId=${serverId}&path=${encodeURIComponent(`${root}/work/big.txt`)}&overwrite=true`,
    {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream', 'Content-Length': String(uploadBody.length) },
      body: uploadBody,
    },
  );
  const uploadJson = await upload.json().catch(() => null);
  check('upload streaming', upload.status === 200 && uploadJson?.size === uploadBody.length);

  const download = await fetch(
    `${base}/api/v1/remote/files/download?serverId=${serverId}&path=${encodeURIComponent(`${root}/work/big.txt`)}`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  const downloaded = Buffer.from(await download.arrayBuffer());
  check(
    'download streaming',
    download.status === 200 && downloaded.equals(uploadBody),
    `${downloaded.length} bytes, transfer ${download.headers.get('x-transfer-id') ? 'tercatat' : 'tidak tercatat'}`,
  );

  const traversal = await api('GET', `/remote/files/list?serverId=${serverId}&path=${encodeURIComponent('../../etc')}`);
  check('path traversal ditolak', traversal.status === 403, traversal.json?.error?.code);

  const search = await api('POST', '/remote/files/search', { serverId, path: `${root}/work`, query: 'app' });
  check('search', (search.json?.results ?? []).length >= 2, `${search.json?.count} hasil`);

  const meta = await api('GET', `/remote/files/metadata?serverId=${serverId}&path=${encodeURIComponent(`${root}/work/app.js`)}`);
  check('metadata + permission', Boolean(meta.json?.permissions) && meta.json?.type === 'file');

  const madeDir = await api('POST', '/remote/files/mkdir', { serverId, path: `${root}/work/newdir` });
  const renamed = await api('POST', '/remote/files/rename', {
    serverId,
    path: `${root}/work/newdir`,
    name: 'renamed',
  });
  const deleted = await api('DELETE', `/remote/files/delete?serverId=${serverId}&path=${encodeURIComponent(`${root}/work/renamed`)}&confirm=true&recursive=true`);
  check('mkdir/rename/delete', madeDir.status === 200 && renamed.status === 200 && deleted.json?.deleted === true);

  // --terminal over the shared WebSocket--
  const wsEvents = [];
  const socket = new WebSocket(`${base.replace(/^http/, 'ws')}/ws?token=${token}`);
  await new Promise((resolve, reject) => {
    socket.on('open', resolve);
    socket.on('error', reject);
  });
  socket.send(JSON.stringify({ type: 'subscribe', events: ['remote'] }));
  socket.on('message', (raw) => {
    try {
      wsEvents.push(JSON.parse(String(raw)));
    } catch {
      /* ignore */
    }
  });
  await new Promise((resolve) => setTimeout(resolve, 250));

  const session = await api('POST', '/remote/terminal/sessions', { serverId, cwd: `${root}/work`, cols: 100, rows: 30 });
  const sessionId = session.json?.session?.id;
  check('buat session terminal', session.status === 201 && Boolean(sessionId));

  socket.on('message', (raw) => {
    try {
      wsEvents.push(JSON.parse(String(raw)));
    } catch {
      /* ignore */
    }
  });
  await new Promise((resolve) => setTimeout(resolve, 300));
  socket.send(JSON.stringify({ type: 'remote.terminal.input', sessionId, data: 'echo REMOTE-SMOKE-OK\\n' }));
  socket.send(JSON.stringify({ type: 'remote.terminal.resize', sessionId, cols: 120, rows: 40 }));
  await new Promise((resolve) => setTimeout(resolve, 250));

  const output = await new Promise((resolve) => {
    const started = Date.now();
    const timer = setInterval(() => {
      const text = wsEvents
        .filter((event) => event.type === 'remote.terminal.output')
        .map((event) => event.payload?.data ?? '')
        .join('');
      if (text.includes('REMOTE-SMOKE-OK') || Date.now() - started > 8000) {
        clearInterval(timer);
        resolve(text);
      }
    }, 100);
  });
  check('output terminal real-time', output.includes('REMOTE-SMOKE-OK'));
  check(
    'event terminal lewat WebSocket',
    wsEvents.some((event) => event.type === 'remote.terminal.session.created') &&
      wsEvents.some((event) => event.type === 'remote.terminal.resize'),
  );

  socket.send(JSON.stringify({ type: 'remote.terminal.interrupt', sessionId }));
  await new Promise((resolve) => setTimeout(resolve, 200));
  const closed = await api('DELETE', `/remote/terminal/sessions/${sessionId}`);
  check('tutup session terminal', closed.json?.closed === true);
  socket.close();

  // --transfers + audit--
  const transfers = await api('GET', '/remote/transfers?limit=10');
  check('riwayat transfer', (transfers.json?.transfers ?? []).some((item) => item.status === 'completed'));

  const audit = await api('GET', '/remote/audit?limit=40');
  check(
    'audit log remote',
    (audit.json?.actions ?? []).length > 0 && (audit.json?.connections ?? []).length > 0,
    `${audit.json?.actions?.length ?? 0} aksi, ${audit.json?.connections?.length ?? 0} event koneksi`,
  );

  await api('DELETE', `/remote/servers/${serverId}`);
  return finish();
}

function finish() {
  const failed = results.filter((result) => !result.ok).length;
  console.log(`\n${results.length - failed}/${results.length} pemeriksaan lolos`);
  return failed;
}

try {
  const failed = await main();
  await sshd.close();
  fs.rmSync(root, { recursive: true, force: true });
  process.exit(failed ? 1 : 0);
} catch (error) {
  console.error('smoke remote error:', error?.stack ?? error);
  await sshd.close().catch(() => {});
  fs.rmSync(root, { recursive: true, force: true });
  process.exit(1);
}
