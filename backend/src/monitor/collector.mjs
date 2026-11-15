// Periodic sampler: persists metrics, syncs services and raises alerts.
import crypto from 'node:crypto';
import { config } from '../config.mjs';
import { query } from '../db.mjs';
import { logger } from '../logger.mjs';
import { createAlert, emitEvent, resolveAlertsByKind } from '../events.mjs';
import { startCpuSampler, stopCpuSampler, fullSnapshot } from './system.mjs';

const waiters = new Map();
let timer = null;
let lastSnapshot = null;
let lastStoredAt = null;
let lastError = null;
let collecting = false;
// kind -> { since, peak }: a breach must hold before it becomes an alert.
const breaches = new Map();

export function ensureNode() {
  const existing = query.get('SELECT * FROM server_nodes WHERE id = ?', config.nodeId);
  if (existing) return existing;
  query.run(
    'INSERT INTO server_nodes (id, name, kind, host, status, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    config.nodeId,
    config.nodeName,
    'primary',
    '127.0.0.1',
    'online',
    Date.now(),
    Date.now(),
  );
  return query.get('SELECT * FROM server_nodes WHERE id = ?', config.nodeId);
}

export function latestMetrics() {
  return lastSnapshot;
}

export function monitorHealth() {
  const cpu = lastSnapshot?.system?.cpu ?? null;
  return {
    collecting,
    lastCollectedAt: lastSnapshot?.capturedAt ?? null,
    lastError: lastError ? String(lastError).slice(0, 300) : null,
    intervalMs: config.monitorIntervalMs,
    cpu: cpu
      ? {
          usagePercent: cpu.usagePercent ?? null,
          capturedAt: cpu.capturedAt ?? null,
          windowMs: cpu.windowMs ?? null,
          sampleAgeMs: cpu.sampleAgeMs ?? null,
          stale: cpu.stale ?? false,
          reason: cpu.reason ?? null,
          sampleIntervalMs: config.cpuSampleIntervalMs,
        }
      : null,
    thresholds: { cpu: config.thresholdCpu, memory: config.thresholdMemory, disk: config.thresholdDisk, sustainMs: config.alertSustainMs },
  };
}

function syncServices(snapshot) {
  const now = Date.now();
  const rows = [];
  for (const item of snapshot.pm2.processes ?? []) {
    rows.push({
      id: `pm2:${item.name}`,
      name: item.name,
      kind: 'pm2',
      status: item.status,
      detail: JSON.stringify({
        pid: item.pid,
        restarts: item.restarts,
        cpu: item.cpuPercent,
        memory: item.memoryBytes,
        script: item.script,
      }),
    });
  }
  for (const item of snapshot.docker.containers ?? []) {
    rows.push({
      id: `docker:${item.name}`,
      name: item.name,
      kind: 'docker',
      status: String(item.state ?? item.status ?? 'unknown').toLowerCase(),
      detail: JSON.stringify({ image: item.image, status: item.status, ports: item.ports }),
    });
  }
  for (const item of snapshot.services ?? []) {
    rows.push({ id: `systemd:${item.name}`, name: item.name, kind: 'systemd', status: item.status, detail: null });
  }
  for (const row of rows) {
    query.run(
      `INSERT INTO services (id, node_id, name, kind, status, detail, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET status = excluded.status, detail = excluded.detail, updated_at = excluded.updated_at`,
      row.id,
      config.nodeId,
      row.name,
      row.kind,
      row.status,
      row.detail,
      now,
    );
  }
  return rows;
}

/**
 * Evaluate one metric against its threshold with three rules:
 *   - a breach must hold for config.alertSustainMs before an alert is created;
 *   - an open alert is updated in place (never re-created) while it holds;
 *   - it is resolved once the value drops below threshold - resolveMargin.
 * Unavailable values are skipped entirely: they neither raise nor resolve.
 */
export function evaluateMetric({
  kind,
  title,
  source,
  value,
  threshold,
  criticalAt,
  detail,
  nodeId = config.nodeId,
  now = Date.now(),
  sustainMs = config.alertSustainMs,
}) {
  if (value === null || value === undefined || !Number.isFinite(value)) return null;
  const state = breaches.get(kind);

  if (value >= threshold) {
    if (!state) breaches.set(kind, { since: now, peak: value });
    else state.peak = Math.max(state.peak, value);
    const current = breaches.get(kind);
    const heldMs = now - current.since;
    if (heldMs < sustainMs) return null;
    return createAlert({
      kind,
      title,
      source,
      nodeId,
      severity: current.peak >= criticalAt ? 'critical' : 'warning',
      value: Math.round(value * 10) / 10,
      threshold,
      peakValue: Math.round(current.peak * 10) / 10,
      detail: `${detail} Nilai ${value}% (ambang ${threshold}%, puncak ${current.peak}%) sudah bertahan ${Math.round(heldMs / 1000)}s.`,
    });
  }

  if (state) {
    // Still above the plain threshold: inside the hysteresis band, keep as is.
    if (value > threshold - config.alertResolveMargin) return null;
    breaches.delete(kind);
  }
  return resolveAlertsByKind({
    kind,
    source,
    nodeId,
    value: Math.round(value * 10) / 10,
    message: `Kembali normal di ${value}% (ambang ${threshold}%).`,
  });
}

function checkThresholds(snapshot) {
  const cpu = snapshot.system.cpu ?? {};
  const load = (cpu.loadAverage ?? snapshot.system.loadAverage ?? []).map((n) => Number(n).toFixed(2)).join(', ');
  evaluateMetric({
    kind: 'cpu',
    title: 'CPU tinggi',
    source: 'monitor',
    value: cpu.usagePercent ?? null,
    threshold: config.thresholdCpu,
    criticalAt: 95,
    detail: `CPU ${cpu.usagePercent ?? '--'}% pada ${cpu.cores ?? '?'} core (load ${load}).`,
  });

  evaluateMetric({
    kind: 'memory',
    title: 'RAM hampir penuh',
    source: 'monitor',
    value: snapshot.system.memory.usedPercent,
    threshold: config.thresholdMemory,
    criticalAt: 97,
    detail: `Terpakai ${Math.round(snapshot.system.memory.used / 1024 / 1024)} MB dari ${Math.round(
      snapshot.system.memory.total / 1024 / 1024,
    )} MB. Swap terpakai ${Math.round((snapshot.system.memory.swap?.used ?? 0) / 1024 / 1024)} MB.`,
  });

  evaluateMetric({
    kind: 'disk',
    title: 'Disk hampir penuh',
    source: 'monitor',
    value: snapshot.disk.usagePercent,
    threshold: config.thresholdDisk,
    criticalAt: 97,
    detail: snapshot.disk.root
      ? `Mount ${snapshot.disk.root.mount} terpakai ${Math.round(snapshot.disk.root.used / 1024 / 1024 / 1024)} GB dari ${Math.round(
          snapshot.disk.root.size / 1024 / 1024 / 1024,
        )} GB.`
      : 'Mount root tidak terbaca.',
  });

  for (const item of snapshot.pm2.processes ?? []) {
    const kind = `service:${item.name}`;
    if (item.status === 'errored' || item.status === 'stopped') {
      createAlert({
        kind,
        title: `Service berhenti: ${item.name}`,
        severity: 'critical',
        detail: `PM2 status "${item.status}"${item.restarts ? ` setelah ${item.restarts} restart` : ''}.`,
        source: 'pm2',
        nodeId: config.nodeId,
        value: null,
      });
      continue;
    }
    resolveAlertsByKind({ kind, source: 'pm2', nodeId: config.nodeId, by: 'monitor', message: `Service ${item.name} kembali ${item.status}.` });
  }
}

function pruneMetrics() {
  const cutoff = Date.now() - config.metricsRetentionDays * 24 * 60 * 60 * 1000;
  query.run('DELETE FROM server_metrics WHERE captured_at < ?', cutoff);
}

export async function collectOnce({ reason = 'interval' } = {}) {
  if (collecting) return lastSnapshot;
  collecting = true;
  try {
    ensureNode();
    const snapshot = await fullSnapshot();
    snapshot.services = [];
    snapshot.collectionReason = reason;
    syncServices(snapshot);
    // Never store the same capture twice (retry/re-entry), so the history has
    // one point per real sample instead of duplicate rows.
    if (lastStoredAt !== snapshot.capturedAt) {
      query.run(
        'INSERT INTO server_metrics (node_id, captured_at, metrics) VALUES (?, ?, ?)',
        config.nodeId,
        snapshot.capturedAt,
        JSON.stringify(snapshot),
      );
      lastStoredAt = snapshot.capturedAt;
    }
    query.run("UPDATE server_nodes SET status = 'online', last_seen_at = ? WHERE id = ?", snapshot.capturedAt, config.nodeId);
    lastSnapshot = snapshot;
    lastError = null;
    emitEvent('server.metrics', summarize(snapshot));
    checkThresholds(snapshot);
    if (Math.random() < 0.02) pruneMetrics();
    return snapshot;
  } catch (error) {
    lastError = error;
    logger.warn('metrics collection failed', String(error?.message ?? error));
    query.run("UPDATE server_nodes SET status = 'degraded' WHERE id = ?", config.nodeId);
    emitEvent('server.status', { nodeId: config.nodeId, status: 'degraded', error: String(error?.message ?? error) });
    return lastSnapshot;
  } finally {
    collecting = false;
    waiters.forEach((resolve) => resolve());
    waiters.clear();
  }
}

export function summarize(snapshot) {
  if (!snapshot) return null;
  return {
    nodeId: config.nodeId,
    capturedAt: snapshot.capturedAt,
    cpu: {
      usagePercent: snapshot.system.cpu.usagePercent ?? null,
      cores: snapshot.system.cpu.cores,
      loadAverage: snapshot.system.loadAverage,
      // Timing is part of the value: consumers and the chart can tell which
      // window a percentage belongs to, and spot an unavailable sample.
      capturedAt: snapshot.system.cpu.capturedAt ?? null,
      sampleAgeMs: snapshot.system.cpu.sampleAgeMs ?? null,
      windowMs: snapshot.system.cpu.windowMs ?? null,
      stale: snapshot.system.cpu.stale ?? false,
      reason: snapshot.system.cpu.reason ?? null,
    },
    memory: {
      usedPercent: snapshot.system.memory.usedPercent,
      used: snapshot.system.memory.used,
      total: snapshot.system.memory.total,
      swapUsed: snapshot.system.memory.swap?.used ?? null,
    },
    disk: {
      usagePercent: snapshot.disk.usagePercent,
      root: snapshot.disk.root,
      partitions: snapshot.disk.partitions?.slice(0, 6) ?? [],
    },
    network: {
      rxPerSec: snapshot.network.rxPerSec,
      txPerSec: snapshot.network.txPerSec,
      interfaces: snapshot.network.interfaces,
    },
    uptimeSeconds: snapshot.system.uptime.seconds,
    hostname: snapshot.system.hostname,
    platform: `${snapshot.system.platform} ${snapshot.system.release}`,
    processes: snapshot.processes?.slice(0, 10) ?? [],
    pm2: snapshot.pm2,
    docker: snapshot.docker,
  };
}

/** Wait until the next successful collection (used by tests and setup). */
export function nextCollection(timeoutMs = 20_000) {
  if (lastSnapshot && Date.now() - lastSnapshot.capturedAt < 1000) return Promise.resolve(lastSnapshot);
  return new Promise((resolve) => {
    const timerId = setTimeout(() => {
      waiters.delete(timerId);
      resolve(lastSnapshot);
    }, timeoutMs);
    waiters.set(timerId, () => {
      clearTimeout(timerId);
      resolve(lastSnapshot);
    });
  });
}

export function startMonitor() {
  if (timer) return;
  startCpuSampler();
  collectOnce({ reason: 'startup' }).catch(() => {});
  // The first CPU delta right after boot has no previous sample, so that first
  // snapshot legitimately reports "unavailable". Re-collect once the sampler has
  // its first valid window so the dashboard is not stuck at "--" for a full
  // monitor interval.
  const warmup = setTimeout(() => {
    if (lastSnapshot?.system?.cpu?.usagePercent == null) collectOnce({ reason: 'cpu-warmup' }).catch(() => {});
  }, 1500);
  warmup.unref?.();
  timer = setInterval(() => {
    collectOnce().catch(() => {});
  }, config.monitorIntervalMs);
  timer.unref?.();
  logger.info(`monitor started (every ${Math.round(config.monitorIntervalMs / 1000)}s)`);
}

export function stopMonitor() {
  if (timer) clearInterval(timer);
  timer = null;
  stopCpuSampler();
  breaches.clear();
}
