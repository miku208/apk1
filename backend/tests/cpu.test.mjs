import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Isolated database so the alert tests never touch the live one.
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lifeform-cpu-test-'));
process.env.DATA_DIR = dataDir;
process.env.NODE_ENV = 'test';
process.env.CPU_SAMPLE_INTERVAL_MS = '5000';
process.env.CPU_SAMPLE_STALE_MS = '30000';
process.env.ALERT_SUSTAIN_MS = '0'; // the collector path is covered below

const { computeCpuUsage, parseCpuCounters, isCpuSampleReset } = await import('../src/monitor/system.mjs');
const { openDatabase, closeDatabase, query } = await import('../src/db.mjs');
const { createAlert, resolveAlertsByKind } = await import('../src/events.mjs');
const { evaluateMetric } = await import('../src/monitor/collector.mjs');

openDatabase();
// alerts.node_id has a foreign key to server_nodes, same as in production.
query.run(
  'INSERT INTO server_nodes (id, name, kind, host, status, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  'primary',
  'Primary Node',
  'primary',
  '127.0.0.1',
  'online',
  Date.now(),
  Date.now(),
);

const aggregateLine = (user, nice, system, idle, iowait = 0, irq = 0, softirq = 0, steal = 0) =>
  `cpu  ${user} ${nice} ${system} ${idle} ${iowait} ${irq} ${softirq} ${steal} 0 0`;

test('aggregate /proc/stat counters are parsed and iowait counts as idle', () => {
  const counters = parseCpuCounters(aggregateLine(100, 0, 50, 200, 30));
  assert.deepEqual(counters, { total: 380, idle: 230 });
});

test('the first sample of a pair cannot produce a percentage', () => {
  const current = { ...parseCpuCounters(aggregateLine(100, 0, 50, 200)), at: 1000 };
  assert.equal(computeCpuUsage(null, current), null);
});

test('usage is the idle-corrected delta of one measured window', () => {
  const previous = { ...parseCpuCounters(aggregateLine(100, 0, 50, 200)), at: 1000 };
  // 400 total jiffies elapsed, 300 of them idle → 25% busy
  const current = { ...parseCpuCounters(aggregateLine(200, 0, 50, 500)), at: 2000 };
  assert.equal(computeCpuUsage(previous, current), 25);
});

test('multi-core aggregate is not summed again (2 cores, 1s window)', () => {
  const previous = { total: 10_000, idle: 6_000, at: 0 };
  // 200 jiffies in 1s = 2 cores; 100 idle → 50% of the whole machine
  const current = { total: 10_200, idle: 6_100, at: 1000 };
  assert.equal(computeCpuUsage(previous, current), 50);
});

test('zero or negative deltas are rejected instead of clamped', () => {
  const previous = { total: 1_000, idle: 500, at: 1_000 };
  assert.equal(computeCpuUsage(previous, { total: 1_000, idle: 500, at: 2_000 }), null);
  assert.equal(computeCpuUsage(previous, { total: 900, idle: 400, at: 2_000 }), null);
});

test('impossible idle deltas and too-short windows are rejected', () => {
  const previous = { total: 1_000, idle: 500, at: 1_000 };
  assert.equal(computeCpuUsage(previous, { total: 1_100, idle: 1_400, at: 2_000 }), null);
  // 5 ms window (the bug that produced 100%/50%/33% readings)
  assert.equal(computeCpuUsage(previous, { total: 1_001, idle: 500, at: 1_005 }, { minWindowMs: 250 }), null);
});

test('a reboot or counter reset is detected instead of trusted', () => {
  assert.equal(isCpuSampleReset({ total: 900, idle: 400, uptime: 100 }, { total: 1_000, idle: 500, uptime: 101 }), false);
  assert.equal(isCpuSampleReset({ total: 1_000, idle: 500, uptime: 100 }, { total: 900, idle: 450, uptime: 99 }), true);
  // Counters reset but uptime kept growing (e.g. restored snapshot): still reset.
  assert.equal(isCpuSampleReset({ total: 1_000, idle: 500, uptime: 100 }, { total: 10, idle: 5, uptime: 101 }), true);
});

test('results are clamped into 0..100', () => {
  assert.equal(computeCpuUsage({ total: 0, idle: 0, at: 0 }, { total: 100, idle: 100, at: 1000 }), 0);
  assert.equal(computeCpuUsage({ total: 0, idle: 0, at: 0 }, { total: 100, idle: 0, at: 1000 }), 100);
});

test('one open alert per (source, kind, node) — repeated polling does not duplicate', () => {
  for (const value of [88.1, 89.4, 93.2, 99.9]) {
    createAlert({
      kind: 'cpu',
      title: 'CPU tinggi',
      source: 'monitor',
      nodeId: 'primary',
      severity: value >= 95 ? 'critical' : 'warning',
      value,
      threshold: 85,
      detail: `CPU ${value}% pada 2 core.`,
    });
  }
  const open = query.all("SELECT * FROM alerts WHERE status = 'open' AND kind = 'cpu'");
  assert.equal(open.length, 1);
  // The stored severity escalates and the peak is remembered.
  assert.equal(open[0].severity, 'critical');
  assert.equal(open[0].peak_value, 99.9);
  assert.equal(open[0].metric_value, 99.9);
});

test('status changes are recorded as history', () => {
  const alert = query.get("SELECT id FROM alerts WHERE status = 'open' AND kind = 'cpu'");
  const before = query.all('SELECT status FROM alert_events WHERE alert_id = ?', alert.id).map((row) => row.status);
  assert.ok(before.includes('open'));
  assert.ok(before.includes('escalated'));

  resolveAlertsByKind({ kind: 'cpu', source: 'monitor', nodeId: 'primary', value: 40 });
  const row = query.get('SELECT status, resolved_at FROM alerts WHERE id = ?', alert.id);
  assert.equal(row.status, 'resolved');
  assert.ok(row.resolved_at > 0);
  const after = query.all('SELECT status FROM alert_events WHERE alert_id = ?', alert.id).map((r) => r.status);
  assert.equal(after.at(-1), 'resolved');
});

test('a breach must hold before it opens an alert, and resolves on recovery', () => {
  const base = {
    kind: 'disk',
    title: 'Disk hampir penuh',
    source: 'monitor',
    threshold: 90,
    criticalAt: 97,
    detail: 'mount /',
    nodeId: 'primary',
    sustainMs: 60_000,
  };
  const t0 = Date.now();
  assert.equal(evaluateMetric({ ...base, value: 95, now: t0 }), null);
  assert.equal(evaluateMetric({ ...base, value: 95, now: t0 + 30_000 }), null);
  assert.equal(query.all("SELECT id FROM alerts WHERE kind = 'disk'").length, 0);

  const created = evaluateMetric({ ...base, value: 95, now: t0 + 61_000 });
  assert.ok(created?.id);
  assert.equal(query.all("SELECT id FROM alerts WHERE kind = 'disk' AND status = 'open'").length, 1);

  // Inside the hysteresis band (90 - 5): still open, not flapping.
  assert.equal(evaluateMetric({ ...base, value: 88, now: t0 + 120_000 }), null);
  assert.equal(query.all("SELECT id FROM alerts WHERE kind = 'disk' AND status = 'open'").length, 1);

  // Clearly recovered: resolved, and a new breach starts a fresh timer.
  evaluateMetric({ ...base, value: 60, now: t0 + 180_000 });
  assert.equal(query.all("SELECT id FROM alerts WHERE kind = 'disk' AND status = 'open'").length, 0);
  assert.equal(evaluateMetric({ ...base, value: 95, now: t0 + 240_000 }), null);
});

test('unavailable values neither create nor resolve alerts', () => {
  assert.equal(
    evaluateMetric({
      kind: 'memory',
      title: 'RAM hampir penuh',
      source: 'monitor',
      value: null,
      threshold: 90,
      criticalAt: 97,
      detail: 'x',
      nodeId: 'primary',
      sustainMs: 0,
    }),
    null,
  );
  assert.equal(query.all("SELECT id FROM alerts WHERE kind = 'memory'").length, 0);
});

test('a resolved alert can be raised again later', () => {
  createAlert({ kind: 'cpu', title: 'CPU tinggi', source: 'monitor', nodeId: 'primary', value: 91, threshold: 85 });
  const open = query.all("SELECT id FROM alerts WHERE status = 'open' AND kind = 'cpu'");
  assert.equal(open.length, 1);
  assert.equal(query.all("SELECT id FROM alerts WHERE status = 'resolved' AND kind = 'cpu'").length, 1);
});

test.after(() => {
  closeDatabase();
  fs.rmSync(dataDir, { recursive: true, force: true });
});
