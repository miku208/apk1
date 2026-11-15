// Identity of the Primary Node (the host running this backend). Cached briefly
// because the remote overview is polled by the app.
import os from 'node:os';
import { execFile } from 'node:child_process';

const CACHE_MS = 15_000;
let cache = { at: 0, value: null };

function run(command, args = []) {
  return new Promise((resolve) => {
    execFile(command, args, { timeout: 4000, maxBuffer: 256 * 1024 }, (error, stdout, stderr) => {
      resolve({
        ok: !error,
        exitCode: typeof error?.code === 'number' ? error.code : error ? 1 : 0,
        stdout: String(stdout ?? '').trim(),
        stderr: String(stderr ?? '').trim(),
      });
    });
  });
}

/** Real executor identity: never claim root unless the runtime really is root. */
export async function localNodeInfo({ fresh = false } = {}) {
  if (!fresh && cache.value && Date.now() - cache.at < CACHE_MS) return cache.value;

  const [who, idOut, uid, gid, host, kernel, pm2] = await Promise.all([
    run('whoami'),
    run('id'),
    run('id', ['-u']),
    run('id', ['-g']),
    run('hostname'),
    run('uname', ['-srm']),
    run('pm2', ['ping']),
  ]);

  const effectiveUid = Number(uid.stdout);
  const effectiveGid = Number(gid.stdout);
  const value = {
    runtime: 'local',
    protocol: 'local',
    kind: 'primary',
    hostname: host.stdout || os.hostname(),
    kernel: kernel.stdout || null,
    platform: os.platform(),
    arch: os.arch(),
    release: os.release(),
    cpuCores: os.cpus().length,
    totalMemoryBytes: os.totalmem(),
    uptimeSeconds: Math.round(os.uptime()),
    user: who.stdout || null,
    id: idOut.stdout || null,
    effectiveUid: Number.isFinite(effectiveUid) ? effectiveUid : null,
    effectiveGid: Number.isFinite(effectiveGid) ? effectiveGid : null,
    isRoot: effectiveUid === 0,
    pm2Access: pm2.ok,
    pm2Version: pm2.ok ? (pm2.stdout.split('\n')[0] || null) : null,
    capturedAt: new Date().toISOString(),
  };
  cache = { at: Date.now(), value };
  return value;
}

export function clearLocalNodeCache() {
  cache = { at: 0, value: null };
}
