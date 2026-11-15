#!/usr/bin/env node
// End-to-end check of the Primary Node over the real HTTP API.
// The Primary Node is this host: it must answer through the Local Runtime,
// without SSH, SFTP, host keys or fingerprint pinning.
//
// Usage: node scripts/smoke-primary.mjs <pairing-code> [baseUrl]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import WebSocket from 'ws';

const codeArg = process.argv[2];
const base = (process.argv[3] ?? 'http://127.0.0.1:8888').replace(/\/+$/, '');

const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
};

let token = null;
async function api(method, route, body) {
  const res = await fetch(`${base}/api/v1${route}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
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
  return { status: res.status, json };
}

const workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'lifeform-smoke-primary-'));
const probeFile = path.join(workdir, 'probe.txt');

async function main() {
  // Pairing codes can only be minted from the box itself; mint one when the
  // caller did not pass a code.
  let code = codeArg;
  if (!code) {
    const pairing = await api('GET', '/auth/pairing');
    code = pairing.json?.code;
    check('pairing code lokal dibuat', Boolean(code));
  }
  const paired = await api('POST', '/auth/pair', { code, deviceName: 'primary-smoke' });
  token = paired.json?.accessToken;
  check('pairing', Boolean(token));
  if (!token) throw new Error('pairing failed');

  const servers = await api('GET', '/remote/servers');
  const list = servers.json?.servers ?? [];
  const primary = list.find((item) => item.isPrimary);
  check('primary node terdeteksi', Boolean(primary), primary ? primary.name : 'tidak ada');
  check('primary memakai Local Runtime', primary?.runtime === 'local' && primary?.isLocal === true);
  check('primary tanpa kredensial SSH/SFTP', primary?.authType === 'local' && !primary?.hostFingerprint);
  check('primary berstatus connected dari backend', primary?.lastStatus === 'connected');
  const node = primary?.node ?? null;
  check(
    'identitas host dari local runtime',
    Boolean(node?.hostname) && node.hostname === os.hostname() && node.isRoot === (process.getuid() === 0),
    node ? `${node.hostname} uid=${node.effectiveUid} root=${node.isRoot}` : 'tidak ada',
  );
  const primaryId = primary?.id;

  const overview = await api('GET', '/remote/overview');
  check(
    'overview memuat primary node',
    (overview.json?.servers ?? []).some((item) => item.isPrimary && item.runtime === 'local') &&
      Boolean(overview.json?.primary?.id),
  );

  const tested = await api('POST', `/remote/servers/${primaryId}/test`);
  check('tes koneksi tanpa SSH', tested.json?.ok === true, tested.json?.message ?? '');

  const trust = await api('POST', `/remote/servers/${primaryId}/trust`);
  check(
    'trust dijawab tanpa fingerprint',
    trust.status === 200 && trust.json?.trusted === true && trust.json?.local === true && !trust.json?.server?.hostFingerprint,
  );

  const files = await api('GET', `/remote/files/list?serverId=${primaryId}&path=${encodeURIComponent(workdir)}`);
  check('file manager lokal', files.status === 200 && Array.isArray(files.json?.entries));

  fs.writeFileSync(probeFile, 'PRIMARY-LOCAL-OK\n');
  const read = await api('GET', `/remote/files/read?serverId=${primaryId}&path=${encodeURIComponent(probeFile)}`);
  check('baca file lewat local filesystem', read.status === 200 && String(read.json?.content ?? '').includes('PRIMARY-LOCAL-OK'));

  const written = await api('POST', '/remote/files/write', {
    serverId: primaryId,
    path: probeFile,
    content: 'PRIMARY-LOCAL-WRITE-OK\n',
  });
  check(
    'tulis file atomik',
    written.status === 200 && fs.readFileSync(probeFile, 'utf8').includes('PRIMARY-LOCAL-WRITE-OK'),
  );

  // --terminal through the shared WebSocket--
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

  const session = await api('POST', '/remote/terminal/sessions', { serverId: primaryId, cwd: workdir, cols: 100, rows: 30 });
  const sessionId = session.json?.session?.id;
  check('session terminal lokal dibuat', session.status === 201 && Boolean(sessionId));
  socket.send(JSON.stringify({ type: 'remote.terminal.input', sessionId, data: 'echo PRIMARY-PTY-OK\\n' }));
  socket.send(JSON.stringify({ type: 'remote.terminal.resize', sessionId, cols: 120, rows: 40 }));
  const output = await new Promise((resolve) => {
    const started = Date.now();
    const timer = setInterval(() => {
      const text = wsEvents
        .filter((event) => event.type === 'remote.terminal.output')
        .map((event) => event.payload?.data ?? '')
        .join('');
      if (text.includes('PRIMARY-PTY-OK') || Date.now() - started > 10000) {
        clearInterval(timer);
        resolve(text);
      }
    }, 100);
  });
  check('output PTY lokal real-time', output.includes('PRIMARY-PTY-OK'));
  const closed = await api('DELETE', `/remote/terminal/sessions/${sessionId}`);
  check('session terminal lokal ditutup', closed.json?.closed === true);
  socket.close();

  const autonomy = await api('GET', '/autonomy');
  check('level 3 terbaca backend', Number(autonomy.json?.level) === 3, `level=${autonomy.json?.level}`);
  const runtime = autonomy.json?.runtime ?? null;
  check(
    'privilege runtime berasal dari host sebenarnya',
    runtime?.effectiveUid === process.getuid() && runtime?.isRoot === (process.getuid() === 0),
    runtime ? `uid=${runtime.effectiveUid} gid=${runtime.effectiveGid} root=${runtime.isRoot}` : 'tidak ada',
  );
  const settings = await api('GET', '/settings');
  check('settings memuat runtime lokal', Boolean(settings.json?.runtime?.hostname));

  fs.rmSync(workdir, { recursive: true, force: true });
  const failed = results.filter((item) => !item.ok);
  console.log(`\n${results.length - failed.length}/${results.length} PASS`);
  if (failed.length) process.exitCode = 1;
}

main().catch((error) => {
  console.error('smoke failed:', error?.message ?? error);
  process.exitCode = 1;
});
