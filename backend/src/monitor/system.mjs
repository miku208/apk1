// Real host metrics read from /proc, df, pm2 and docker. No dummy values:
// anything unavailable is reported as null.
import fs from 'node:fs';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { config } from '../config.mjs';

function readFile(file, fallback = '') {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return fallback;
  }
}

/**
 * CPU usage is derived from the aggregate `cpu` line of /proc/stat, never from
 * an uptime counter or from load average.
 *
 * Exactly one owner samples /proc/stat (see startCpuSampler) and every consumer
 * reads the cached result. Before this, each caller kept its own delta baseline
 * in a module-global, so two reads a few milliseconds apart produced a 1-2
 * jiffy window and bogus values (0%, 33%, 50%, 100%).
 */
const CPU_COUNTER_FIELDS = 8; // user nice system idle iowait irq softirq steal

/** Parse the aggregate line into cumulative counters. Returns null if unusable. */
export function parseCpuCounters(line) {
  if (!line || !line.startsWith('cpu ')) return null;
  const parts = line.trim().split(/\s+/).slice(1).map(Number);
  if (parts.length < 4 || parts.slice(0, CPU_COUNTER_FIELDS).some((n) => !Number.isFinite(n) || n < 0)) return null;
  const [user, nice, system, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0] = parts;
  // guest/guest_nice are already accounted inside user/nice on Linux, so they
  // are deliberately not added a second time.
  return {
    total: user + nice + system + idle + iowait + irq + softirq + steal,
    // iowait counts as idle: the CPU was not executing any task.
    idle: idle + iowait,
  };
}

/**
 * Usage between two absolute samples, in percent of the aggregate capacity
 * (multi-core is already normalised: /proc/stat reports summed jiffies).
 * Returns null whenever the delta cannot produce an honest number.
 */
export function computeCpuUsage(previous, current, { minWindowMs = 0 } = {}) {
  if (!previous || !current) return null;
  if (minWindowMs > 0 && current.at - previous.at < minWindowMs) return null;
  const deltaTotal = current.total - previous.total;
  const deltaIdle = current.idle - previous.idle;
  // Zero delta (no tick elapsed), negative delta (counter reset / reboot) or
  // an impossible idle delta must never be turned into a percentage.
  if (!(deltaTotal > 0)) return null;
  if (deltaIdle < 0 || deltaIdle > deltaTotal) return null;
  const usage = ((deltaTotal - deltaIdle) / deltaTotal) * 100;
  return Math.max(0, Math.min(100, Math.round(usage * 10) / 10));
}

/** Counter reset / reboot detection: uptime or a counter went backwards. */
export function isCpuSampleReset(previous, current) {
  if (!previous || !current) return false;
  if (current.total < previous.total || current.idle < previous.idle) return true;
  if (previous.uptime !== null && previous.uptime !== undefined && current.uptime !== null && current.uptime !== undefined) {
    return current.uptime < previous.uptime;
  }
  return false;
}

function readCpuSample() {
  const line = readFile('/proc/stat').split('\n').find((row) => row.startsWith('cpu '));
  const counters = parseCpuCounters(line);
  if (!counters) return null;
  const uptime = Number(readFile('/proc/uptime').split(' ')[0]);
  return { ...counters, at: Date.now(), uptime: Number.isFinite(uptime) ? uptime : null };
}

let previousCpuSample = null;
let cpuCache = { usagePercent: null, capturedAt: null, windowMs: null, reason: 'not-sampled' };
let cpuSampler = null;
let cpuPrimeTimer = null;

/**
 * Take one CPU sample. Invalid windows are dropped instead of being clamped
 * into a plausible-looking number, and the baseline is only advanced when the
 * window was long enough to be meaningful.
 */
export function sampleCpu({ minWindowMs = 250, maxWindowMs = 120_000 } = {}) {
  const current = readCpuSample();
  if (!current) {
    cpuCache = { usagePercent: null, capturedAt: null, windowMs: null, reason: 'proc-unavailable' };
    return cpuCache;
  }
  const previous = previousCpuSample;
  const reset = isCpuSampleReset(previous, current);

  if (!previous || reset) {
    previousCpuSample = current;
    cpuCache = {
      usagePercent: null,
      capturedAt: null,
      windowMs: null,
      reason: reset ? 'counter-reset' : 'warming-up',
    };
    return cpuCache;
  }

  const windowMs = current.at - previous.at;
  if (windowMs < minWindowMs) {
    // Too short to be meaningful: keep the baseline so the next tick still has
    // a usable window, and keep serving the previous valid value.
    return cpuCache;
  }

  const usagePercent = computeCpuUsage(previous, current, { minWindowMs });
  previousCpuSample = current;
  if (usagePercent === null || windowMs > maxWindowMs) {
    cpuCache = {
      usagePercent: null,
      capturedAt: null,
      windowMs,
      reason: windowMs > maxWindowMs ? 'stale-window' : 'invalid-delta',
    };
    return cpuCache;
  }
  cpuCache = { usagePercent, capturedAt: current.at, windowMs, reason: 'ok' };
  return cpuCache;
}

export function startCpuSampler({ intervalMs = config.cpuSampleIntervalMs } = {}) {
  if (cpuSampler) return cpuSampler;
  sampleCpu(); // baseline only; usage stays null until the next tick
  const primeAfter = Math.min(1000, Math.max(250, Math.floor(intervalMs / 4)));
  cpuPrimeTimer = setTimeout(() => sampleCpu(), primeAfter);
  cpuPrimeTimer.unref?.();
  cpuSampler = setInterval(() => sampleCpu(), intervalMs);
  cpuSampler.unref?.();
  return cpuSampler;
}

export function stopCpuSampler() {
  if (cpuSampler) clearInterval(cpuSampler);
  if (cpuPrimeTimer) clearTimeout(cpuPrimeTimer);
  cpuSampler = null;
  cpuPrimeTimer = null;
  previousCpuSample = null;
  cpuCache = { usagePercent: null, capturedAt: null, windowMs: null, reason: 'not-sampled' };
}

/** Cached CPU reading. Cheap and side-effect free: it never touches /proc. */
export function cpuSnapshot() {
  const loadAverage = os.loadavg();
  const sampleAgeMs = cpuCache.capturedAt ? Date.now() - cpuCache.capturedAt : null;
  const stale = sampleAgeMs !== null && sampleAgeMs > config.cpuSampleStaleMs;
  return {
    usagePercent: stale ? null : cpuCache.usagePercent,
    capturedAt: cpuCache.capturedAt,
    sampleAgeMs,
    windowMs: cpuCache.windowMs,
    stale,
    reason: stale ? 'stale' : cpuCache.reason,
    cores: os.cpus().length,
    loadAvg: loadAverage,
    loadAverage,
    model: os.cpus()[0]?.model?.trim() ?? null,
    speedMhz: os.cpus()[0]?.speed ?? null,
  };
}

export function memorySnapshot() {
  const info = readFile('/proc/meminfo');
  const values = {};
  for (const line of info.split('\n')) {
    const match = line.match(/^(\w+):\s+(\d+)\s*kB/);
    if (match) values[match[1]] = Number(match[2]) * 1024;
  }
  const total = values.MemTotal ?? os.totalmem();
  const available = values.MemAvailable ?? os.freemem();
  const used = total - available;
  const swapTotal = values.SwapTotal ?? 0;
  const swapFree = values.SwapFree ?? 0;
  return {
    total,
    used,
    available,
    free: values.MemFree ?? os.freemem(),
    usedPercent: total ? Math.round((used / total) * 1000) / 10 : null,
    cached: values.Cached ?? null,
    buffers: values.Buffers ?? null,
    swap: { total: swapTotal, used: swapTotal - swapFree, free: swapFree },
  };
}

function exec(command, args, timeout = 8000) {
  return new Promise((resolve) => {
    execFile(command, args, { timeout, maxBuffer: 4 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error && !stdout) resolve({ ok: false, stdout: '', stderr: String(stderr || error.message) });
      else resolve({ ok: true, stdout: String(stdout), stderr: String(stderr) });
    });
  });
}

export async function diskSnapshot() {
  const result = await exec('df', ['-P', '-B1', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'squashfs']);
  if (!result.ok) return { partitions: [], usagePercent: null };
  const lines = result.stdout.trim().split('\n').slice(1);
  const partitions = lines
    .map((line) => {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 6) return null;
      const [filesystem, size, used, available, capacity, ...mountParts] = parts;
      const mount = mountParts.join(' ');
      if (!mount || mount.startsWith('/snap') || mount.startsWith('/boot')) return null;
      return {
        filesystem,
        mount,
        size: Number(size),
        used: Number(used),
        available: Number(available),
        usagePercent: Number(String(capacity).replace('%', '')) || 0,
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.size - a.size);
  const root = partitions.find((part) => part.mount === '/') ?? partitions[0] ?? null;
  return { partitions, usagePercent: root?.usagePercent ?? null, root };
}

function readNetwork() {
  const lines = readFile('/proc/net/dev').split('\n');
  let rx = 0;
  let tx = 0;
  for (const line of lines) {
    const match = line.match(/^\s*([^:]+):\s*(.*)$/);
    if (!match) continue;
    const iface = match[1].trim();
    if (iface === 'lo' || iface.startsWith('veth') || iface.startsWith('docker')) continue;
    const fields = match[2].trim().split(/\s+/).map(Number);
    rx += fields[0] ?? 0;
    tx += fields[8] ?? 0;
  }
  return { rxBytes: rx, txBytes: tx, at: Date.now() };
}

let lastNetwork = null;
export function networkSnapshot() {
  const current = readNetwork();
  let rate = { rxPerSec: null, txPerSec: null };
  if (lastNetwork && current.at > lastNetwork.at) {
    const seconds = (current.at - lastNetwork.at) / 1000;
    rate = {
      rxPerSec: Math.max(0, Math.round((current.rxBytes - lastNetwork.rxBytes) / seconds)),
      txPerSec: Math.max(0, Math.round((current.txBytes - lastNetwork.txBytes) / seconds)),
    };
  }
  lastNetwork = current;
  const interfaces = [];
  for (const [name, addresses] of Object.entries(os.networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (address.internal) continue;
      interfaces.push({ name, address: address.address, family: address.family, mac: address.mac });
    }
  }
  return { ...current, ...rate, interfaces: interfaces.filter((item) => item.family === 'IPv4') };
}

export function uptimeSnapshot() {
  const seconds = Number(readFile('/proc/uptime').split(' ')[0]) || os.uptime();
  return { seconds: Math.round(seconds), hostname: os.hostname() };
}

export function systemSnapshot() {
  return {
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    hostname: os.hostname(),
    nodeVersion: process.version,
    cpu: cpuSnapshot(),
    memory: memorySnapshot(),
    uptime: uptimeSnapshot(),
    loadAverage: os.loadavg(),
  };
}

/** Top processes by RSS from /proc/<pid>/stat. */
export async function processesSnapshot(limit = config.processLimit) {
  const result = await exec('ps', ['-eo', 'pid,ppid,user,pcpu,pmem,rss,etime,stat,args', '--sort=-rss', '--no-headers']);
  if (!result.ok) return [];
  const totalMem = os.totalmem();
  return result.stdout
    .split('\n')
    .filter(Boolean)
    .slice(0, limit)
    .map((line) => {
      const parts = line.trim().split(/\s+/);
      const [pid, ppid, user, cpu, mem, rss, etime, stat, ...args] = parts;
      return {
        pid: Number(pid),
        ppid: Number(ppid),
        user,
        cpuPercent: Number(cpu),
        memoryPercent: Number(mem),
        rssBytes: Number(rss) * 1024,
        memoryShare: totalMem ? Math.round((Number(rss) * 1024 * 10000) / totalMem) / 100 : null,
        runtime: etime,
        state: stat,
        command: args.join(' ').slice(0, 240),
      };
    })
    .filter((item) => Number.isFinite(item.pid));
}

export async function pm2Snapshot() {
  const result = await exec('pm2', ['jlist'], 10_000);
  if (!result.ok) return { available: false, processes: [] };
  try {
    const list = JSON.parse(result.stdout);
    return {
      available: true,
      processes: list.map((item) => ({
        id: item.pm_id,
        name: item.name,
        status: item.pm2_env?.status ?? 'unknown',
        pid: item.pid ?? null,
        restarts: item.pm2_env?.restart_time ?? 0,
        uptimeMs: item.pm2_env?.pm_uptime ? Date.now() - item.pm2_env.pm_uptime : null,
        cpuPercent: item.monit?.cpu ?? null,
        memoryBytes: item.monit?.memory ?? null,
        script: item.pm2_env?.pm_exec_path ?? null,
        cwd: item.pm2_env?.pm_cwd ?? null,
      })),
    };
  } catch {
    return { available: false, processes: [] };
  }
}

export async function dockerSnapshot() {
  const result = await exec('docker', ['ps', '-a', '--format', '{{json .}}'], 10_000);
  if (!result.ok) return { available: false, containers: [] };
  const containers = result.stdout
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      try {
        const item = JSON.parse(line);
        return {
          id: String(item.ID ?? '').slice(0, 12),
          name: item.Names,
          image: item.Image,
          status: item.Status,
          state: item.State,
          ports: item.Ports,
        };
      } catch {
        return null;
      }
    })
    .filter(Boolean);
  return { available: true, containers };
}

export async function systemdSnapshot(names) {
  if (!names?.length) return [];
  const services = await Promise.all(
    names.map(async (name) => {
      const result = await exec('systemctl', ['is-active', name], 4000);
      return { name, kind: 'systemd', status: result.stdout.trim() || 'unknown' };
    }),
  );
  return services;
}

export async function listeningPorts() {
  const result = await exec('ss', ['-ltnp']);
  if (!result.ok) return [];
  return result.stdout
    .split('\n')
    .slice(1)
    .map((line) => {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 5) return null;
      const local = parts[3];
      const process = parts.slice(5).join(' ');
      const port = Number(local.split(':').pop());
      const pidMatch = process.match(/pid=(\d+)/);
      const nameMatch = process.match(/\(\("([^"]+)"/);
      return {
        port: Number.isFinite(port) ? port : null,
        address: local,
        pid: pidMatch ? Number(pidMatch[1]) : null,
        process: nameMatch ? nameMatch[1] : null,
      };
    })
    .filter(Boolean);
}

export async function fullSnapshot() {
  // Ensure there is a sampler even when called outside the server bootstrap
  // (scripts, tests). The cached sample is what every consumer reports.
  if (!cpuSampler) startCpuSampler();
  const [disk, processes, pm2, docker, ports] = await Promise.all([
    diskSnapshot(),
    processesSnapshot(),
    pm2Snapshot(),
    dockerSnapshot(),
    listeningPorts(),
  ]);
  return {
    capturedAt: Date.now(),
    system: systemSnapshot(),
    disk,
    network: networkSnapshot(),
    processes,
    pm2,
    docker,
    ports,
  };
}
