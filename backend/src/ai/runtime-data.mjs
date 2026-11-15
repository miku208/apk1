// Shared access to the live snapshot (used by the AI tools and lifeform core).
import { config } from '../config.mjs';
import { latestMetrics, summarize } from '../monitor/collector.mjs';
import * as systemModule from '../monitor/system.mjs';
import {
  dockerSnapshot,
  listeningPorts,
  pm2Snapshot,
  processesSnapshot,
} from '../monitor/system.mjs';


export { dockerSnapshot, listeningPorts, pm2Snapshot, processesSnapshot };

export async function summarizeForTools() {
  const snapshot = latestMetrics();
  if (snapshot) {
    const summary = summarize(snapshot);
    summary.processes = snapshot.processes?.slice(0, 12) ?? [];
    return summary;
  }
  // First call before the sampler ran: read the host directly instead of
  // returning placeholder numbers.
  const summary = summarize({
    capturedAt: Date.now(),
    system: systemModule.systemSnapshot(),
    disk: await systemModule.diskSnapshot(),
    network: systemModule.networkSnapshot(),
    processes: await processesSnapshot(10),
    pm2: await pm2Snapshot(),
    docker: await dockerSnapshot(),
  });
  summary.nodeId = config.nodeId;
  return summary;
}
