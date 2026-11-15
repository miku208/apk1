// Server, metrics, processes, services, network and storage routes.
import { HttpError, numberParam } from '../http.mjs';
import { parseJson, query } from '../db.mjs';
import { config } from '../config.mjs';
import { collectOnce, monitorHealth, summarize } from '../monitor/collector.mjs';
import { ensureNode } from '../monitor/collector.mjs';
import { latestMetrics } from '../monitor/collector.mjs';
import {
  dockerSnapshot,
  listeningPorts,
  pm2Snapshot,
  processesSnapshot,
  systemdSnapshot,
} from '../monitor/system.mjs';

function nodeRow() {
  ensureNode();
  return query.get('SELECT * FROM server_nodes WHERE id = ?', config.nodeId);
}

function mapNode(row) {
  return {
    id: row.id,
    name: row.name,
    kind: row.kind,
    host: row.host,
    status: row.status,
    lastSeenAt: row.last_seen_at,
    createdAt: row.created_at,
  };
}

/** Aggregate the newest stored snapshot per node, never a fabricated value. */
export function fleetSummary() {
  const nodes = query.all('SELECT * FROM server_nodes ORDER BY created_at').map(mapNode);
  const latest = latestMetrics();
  if (!latest || !nodes.length) {
    return { nodes, aggregate: null };
  }
  const summary = summarize(latest);
  return {
    nodes,
    aggregate: {
      cpuAvg: summary.cpu?.usagePercent ?? null,
      memoryAvg: summary.memory?.usedPercent ?? null,
      diskAvg: summary.disk?.usagePercent ?? null,
      serverCount: nodes.length,
      onlineCount: nodes.filter((node) => node.status === 'online').length,
      capturedAt: summary.capturedAt,
      // CPU timing travels with the number so the app, the chart and the alert
      // list can be proven to describe the same sampling window.
      cpuCapturedAt: summary.cpu?.capturedAt ?? null,
      cpuWindowMs: summary.cpu?.windowMs ?? null,
      cpuStale: summary.cpu?.stale ?? false,
      metricsAgeMs: summary.capturedAt ? Date.now() - summary.capturedAt : null,
      thresholds: { cpu: config.thresholdCpu, memory: config.thresholdMemory, disk: config.thresholdDisk },
      busiestNode: nodes[0] ? { id: nodes[0].id, name: nodes[0].name, cpu: summary.cpu?.usagePercent ?? null } : null,
    },
  };
}

export function monitorRoutes() {
  return [
    {
      method: 'GET',
      pattern: '/api/v1/servers',
      handler: () => {
        const { nodes, aggregate } = fleetSummary();
        return { body: { servers: nodes, aggregate, monitor: monitorHealth() } };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/servers/:id',
      handler: ({ params }) => {
        const row = query.get('SELECT * FROM server_nodes WHERE id = ?', params.id);
        if (!row) throw new HttpError(404, 'Server not found.', 'SERVER_NOT_FOUND');
        const snapshot = latestMetrics();
        return {
          body: {
            server: mapNode(row),
            metrics: snapshot && params.id === config.nodeId ? summarize(snapshot) : null,
          },
        };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/servers/:id/metrics',
      handler: ({ params, url }) => {
        if (params.id !== config.nodeId) {
          const exists = query.get('SELECT id FROM server_nodes WHERE id = ?', params.id);
          if (!exists) throw new HttpError(404, 'Server not found.', 'SERVER_NOT_FOUND');
        }
        const minutes = numberParam(url.searchParams.get('minutes'), 60, { min: 5, max: 10080 });
        const since = Date.now() - minutes * 60 * 1000;
        const rows = query.all(
          'SELECT captured_at, metrics FROM server_metrics WHERE node_id = ? AND captured_at >= ? ORDER BY captured_at ASC',
          params.id,
          since,
        );
        const points = rows.map((row) => {
          const metrics = parseJson(row.metrics, {});
          return {
            t: row.captured_at,
            cpu: metrics.system?.cpu?.usagePercent ?? null,
            memory: metrics.system?.memory?.usedPercent ?? null,
            disk: metrics.disk?.usagePercent ?? null,
            rx: metrics.network?.rxPerSec ?? null,
            tx: metrics.network?.txPerSec ?? null,
            load: metrics.system?.loadAverage?.[0] ?? null,
          };
        });
        return { body: { nodeId: params.id, minutes, points, count: points.length } };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/servers/:id/processes',
      handler: async ({ url }) => {
        const limit = numberParam(url.searchParams.get('limit'), 25, { min: 1, max: 100 });
        const processes = await processesSnapshot(limit);
        return { body: { processes } };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/servers/:id/services',
      handler: async () => {
        const [pm2, docker, systemd] = await Promise.all([
          pm2Snapshot(),
          dockerSnapshot(),
          systemdSnapshot(['nginx']),
        ]);
        const stored = query.all('SELECT * FROM services WHERE node_id = ? ORDER BY kind, name', config.nodeId);
        return {
          body: {
            pm2,
            docker,
            systemd,
            stored: stored.map((row) => ({
              id: row.id,
              name: row.name,
              kind: row.kind,
              status: row.status,
              detail: parseJson(row.detail, null),
              updatedAt: row.updated_at,
            })),
          },
        };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/servers/:id/network',
      handler: async () => {
        const snapshot = latestMetrics();
        const ports = await listeningPorts();
        return {
          body: {
            rates: snapshot
              ? { rxPerSec: snapshot.network?.rxPerSec ?? null, txPerSec: snapshot.network?.txPerSec ?? null }
              : null,
            interfaces: snapshot?.network?.interfaces ?? [],
            ports,
          },
        };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/servers/:id/storage',
      handler: () => {
        const snapshot = latestMetrics();
        return {
          body: {
            partitions: snapshot?.disk?.partitions ?? [],
            usagePercent: snapshot?.disk?.usagePercent ?? null,
            root: snapshot?.disk?.root ?? null,
          },
        };
      },
    },
    {
      method: 'POST',
      pattern: '/api/v1/monitor/collect',
      handler: async () => {
        const snapshot = await collectOnce({ reason: 'manual' });
        return { body: { capturedAt: snapshot?.capturedAt ?? null, summary: summarize(snapshot) } };
      },
    },
  ];
}

export { nodeRow };
