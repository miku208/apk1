#!/usr/bin/env node
// End-to-end smoke test against a running backend.
// Usage: node scripts/smoke.mjs <pairing-code> [baseUrl]
import WebSocket from 'ws';

const code = process.argv[2];
const base = (process.argv[3] ?? 'http://127.0.0.1:8888/lifeform').replace(/\/+$/, '');
if (!code) {
  console.error('usage: node scripts/smoke.mjs <pairing-code> [baseUrl]');
  process.exit(1);
}

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
}

async function api(method, path, body, token) {
  const res = await fetch(`${base}/api/v1${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json, text };
}

async function main() {
  const health = await api('GET', '/health');
  check('health', health.status === 200 && health.json?.status === 'ok', health.json?.service);

  const unauth = await fetch(`${base}/api/v1/servers`);
  check('endpoint tanpa token ditolak', unauth.status === 401, `HTTP ${unauth.status}`);

  const pair = await api('POST', '/auth/pair', { code, deviceName: 'smoke-test', platform: 'cli' });
  check('pairing', pair.status === 201 && Boolean(pair.json?.accessToken), pair.json?.error?.message ?? '');
  const token = pair.json?.accessToken;
  if (!token) return finish();

  const servers = await api('GET', '/servers', null, token);
  check(
    'servers + aggregate',
    servers.status === 200 && Array.isArray(servers.json?.servers),
    `nodes=${servers.json?.servers?.length} cpu=${servers.json?.aggregate?.cpuAvg}%`,
  );

  const metrics = await api('GET', '/servers/primary/metrics?minutes=10', null, token);
  check('metrics history', metrics.status === 200 && metrics.json?.count >= 0, `points=${metrics.json?.count}`);

  const status = await api('GET', '/lifeform/status', null, token);
  check('lifeform status', status.status === 200 && Boolean(status.json?.identity?.name), status.json?.state?.state ?? '');

  const providers = await api('GET', '/ai/providers', null, token);
  const withKey = providers.json?.providers?.filter((item) => item.hasKey).map((item) => item.id) ?? [];
  check('provider registry', providers.status === 200, `providers dengan key: ${withKey.join(', ') || '-'}`);

  const terminal = await api('POST', '/terminal/execute', { command: 'df -h / | tail -1' }, token);
  check(
    'terminal read-only dijalankan',
    terminal.status === 200 && terminal.json?.status === 'completed',
    `status=${terminal.json?.status} output=${String(terminal.json?.output ?? '').trim().slice(0, 60)}`,
  );

  const blocked = await api('POST', '/terminal/execute', { command: 'rm -rf /' }, token);
  check(
    'perintah destruktif ditahan',
    blocked.status === 200 && blocked.json?.status === 'blocked',
    blocked.json?.error?.slice(0, 70) ?? '',
  );

  const autonomy = await api('GET', '/autonomy', null, token);
  check('autonomy level', autonomy.status === 200, `Lv${autonomy.json?.level}`);

  // WebSocket: subscribe and expect a metrics event after a manual collect.
  const wsToken = token;
  const wsUrl = `${base.replace('http://', 'ws://').replace('https://', 'wss://')}/ws?token=${wsToken}`;
  const events = await new Promise((resolve) => {
    const socket = new WebSocket(wsUrl);
    const received = [];
    const timer = setTimeout(() => {
      socket.close();
      resolve(received);
    }, 12_000);
    socket.on('open', () => {
      socket.send(JSON.stringify({ type: 'subscribe', events: ['all'] }));
      setTimeout(() => api('POST', '/monitor/collect', null, token).catch(() => {}), 400);
    });
    socket.on('message', (raw) => {
      try {
        const event = JSON.parse(String(raw));
        received.push(event.type);
        if (event.type === 'server.metrics') {
          clearTimeout(timer);
          socket.close();
          resolve(received);
        }
      } catch {
        /* ignore */
      }
    });
    socket.on('error', () => {
      clearTimeout(timer);
      resolve(received);
    });
  });
  check('websocket subscribe + event', events.includes('server.metrics'), `events: ${Array.from(new Set(events)).join(', ')}`);

  return finish();
}

function finish() {
  const failed = results.filter((result) => !result.ok).length;
  console.log(`\n${results.length - failed}/${results.length} pemeriksaan lolos`);
  process.exit(failed ? 1 : 0);
}

main().catch((error) => {
  console.error('smoke test error:', error.message);
  process.exit(1);
});
