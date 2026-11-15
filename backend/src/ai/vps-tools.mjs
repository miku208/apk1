// VPS tools exposed to the AI. Every result comes from a real executor.
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { config } from '../config.mjs';
import { query } from '../db.mjs';
import { requestPermission } from '../security/policy.mjs';
import { defaultServerId, listServers } from '../remote/servers.mjs';
import { getAdapter } from '../remote/connection.mjs';
import { listDirectory, readForAi, searchFiles, writeFile } from '../remote/files.mjs';
import { isSensitivePath } from '../remote/paths.mjs';
import { audit } from '../auth.mjs';
import { recordActivity } from '../events.mjs';
import {
  dockerSnapshot,
  listeningPorts,
  pm2Snapshot,
  processesSnapshot,
  summarizeForTools,
} from './runtime-data.mjs';

function run(command, args, { timeout = config.commandTimeoutMs } = {}) {
  return new Promise((resolve) => {
    execFile(command, args, { timeout, maxBuffer: 2 * 1024 * 1024 }, (error, stdout, stderr) => {
      resolve({
        ok: !error,
        exitCode: error?.code ?? 0,
        stdout: String(stdout ?? '').slice(0, 20_000),
        stderr: String(stderr ?? '').slice(0, 4_000),
      });
    });
  });
}

async function guarded({ action, command, target, routine = false, reason = null }) {
  const verdict = await requestPermission({ action, command, target, routine, reason });
  if (!verdict.approved) {
    return {
      output: JSON.stringify({
        executed: false,
        reason: verdict.reason ?? `Tindakan tidak disetujui (${verdict.status ?? 'blocked'}).`,
        approvalId: verdict.approvalId ?? null,
      }),
    };
  }
  return null;
}

/**
 * Report the executor's real identity. Level 3 is an authorization level, not
 * a privilege grant: if the backend runs unprivileged, say so instead of
 * pretending to be root.
 */
export async function executorPrivilege() {
  const [who, idOut, uid, gid, host, kernel] = await Promise.all([
    run('whoami', []),
    run('id', []),
    run('id', ['-u']),
    run('id', ['-g']),
    run('hostname', []),
    run('uname', ['-a']),
  ]);
  const effectiveUid = Number(String(uid.stdout).trim());
  const effectiveGid = Number(String(gid.stdout).trim());
  const pm2 = await run('pm2', ['ping']);
  return {
    user: who.stdout.trim() || null,
    id: idOut.stdout.trim() || null,
    effectiveUid: Number.isFinite(effectiveUid) ? effectiveUid : null,
    effectiveGid: Number.isFinite(effectiveGid) ? effectiveGid : null,
    isRoot: effectiveUid === 0,
    hostname: host.stdout.trim() || os.hostname(),
    kernel: kernel.stdout.trim() || null,
    pm2Access: pm2.ok,
    runtime: 'local',
    capturedAt: new Date().toISOString(),
  };
}

export function vpsTools() {
  return [
    {
      name: 'system_info',
      description: 'Identify the Primary Node and the executor: hostname, kernel, OS, arch, CPU cores, effective user/uid/gid and whether it is really root. Read-only.',
      permission: 'read',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      async run() {
        const privilege = await executorPrivilege();
        const info = {
          ...privilege,
          platform: os.platform(),
          release: os.release(),
          arch: os.arch(),
          cpuCores: os.cpus().length,
          totalMemoryBytes: os.totalmem(),
          uptimeSeconds: Math.round(os.uptime()),
        };
        return { output: JSON.stringify(info, null, 2), meta: { isRoot: privilege.isRoot } };
      },
    },
    {
      name: 'terminal_execute',
      description: 'Run a non-interactive shell command on the Primary Node through the local runtime (or a remote node when serverId is given). Returns stdout, stderr and the real exit code. Audited; on Level 3 no per-action prompt.',
      permission: 'execute',
      parameters: {
        type: 'object',
        properties: {
          command: { type: 'string', description: 'Shell command.' },
          serverId: { type: 'string', description: 'Optional node id; defaults to the Primary Node.' },
          reason: { type: 'string' },
        },
        required: ['command'],
        additionalProperties: false,
      },
      async run(args) {
        const command = String(args?.command ?? '').trim();
        if (!command) return { output: JSON.stringify({ executed: false, error: 'Command kosong.' }) };
        if (command.length > 4000) return { output: JSON.stringify({ executed: false, error: 'Command terlalu panjang.' }) };
        const serverId = String(args?.serverId ?? defaultServerId() ?? '');
        const blocked = await guarded({
          action: `terminal: ${command.slice(0, 120)}`,
          command,
          target: serverId || 'primary',
          reason: args?.reason ?? null,
        });
        if (blocked) return { ...blocked, meta: { permission: 'denied' } };

        let result;
        if (serverId) {
          const adapter = await getAdapter(serverId);
          result = await adapter.exec(command, { timeoutMs: config.commandTimeoutMs });
        } else {
          result = await run('bash', ['-c', command]);
        }
        const privilege = await executorPrivilege();
        audit('ai', 'terminal.execute', serverId || 'primary', {
          exitCode: result.exitCode,
          command: command.slice(0, 200),
          uid: privilege.effectiveUid,
        });
        recordActivity({
          type: 'ai-action',
          title: 'Menjalankan perintah terminal',
          detail: `${command.slice(0, 160)} (exit ${result.exitCode ?? '?'})`,
          source: 'ai',
          risk: 'medium',
          result: result.exitCode === 0 ? 'ok' : 'failed',
        });
        return {
          output: JSON.stringify({
            executed: true,
            exitCode: result.exitCode,
            stdout: String(result.stdout ?? '').slice(0, 12000),
            stderr: String(result.stderr ?? '').slice(0, 4000),
            effectiveUid: privilege.effectiveUid,
            isRoot: privilege.isRoot,
          }, null, 2),
          meta: { exitCode: result.exitCode, isRoot: privilege.isRoot },
        };
      },
    },
    {
      name: 'system_metrics',
      description: 'Read live CPU, memory, disk, network rates and uptime from the host. Read-only.',
      permission: 'read',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      async run() {
        const data = await summarizeForTools();
        return { output: JSON.stringify(data, null, 2), meta: { capturedAt: data.capturedAt } };
      },
    },
    {
      name: 'list_processes',
      description: 'List the busiest host processes with CPU, memory, user and runtime.',
      permission: 'read',
      parameters: {
        type: 'object',
        properties: { limit: { type: 'number', description: 'How many processes (1-50).' } },
        additionalProperties: false,
      },
      async run(args) {
        const limit = Math.min(50, Math.max(1, Number(args?.limit) || 15));
        const processes = await processesSnapshot(limit);
        return { output: JSON.stringify(processes, null, 2) };
      },
    },
    {
      name: 'list_services',
      description: 'List PM2 processes, Docker containers and their status.',
      permission: 'read',
      parameters: {
        type: 'object',
        properties: { kind: { type: 'string', enum: ['all', 'pm2', 'docker'], description: 'Which service list.' } },
        additionalProperties: false,
      },
      async run(args) {
        const kind = args?.kind ?? 'all';
        const [pm2, docker] = await Promise.all([pm2Snapshot(), dockerSnapshot()]);
        const payload = {
          pm2: kind === 'docker' ? undefined : pm2,
          docker: kind === 'pm2' ? undefined : docker,
        };
        return { output: JSON.stringify(payload, null, 2) };
      },
    },
    {
      name: 'pm2_action',
      description: 'Start, restart, stop, reload or delete a PM2 process. Mutating: audited, and on Level 3 executed without a per-action prompt. The result is verified against a fresh PM2 list.',
      permission: 'execute',
      parameters: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'PM2 process name.' },
          action: { type: 'string', enum: ['restart', 'start', 'stop', 'reload', 'delete'] },
          reason: { type: 'string', description: 'Why this action is needed.' },
        },
        required: ['name', 'action'],
        additionalProperties: false,
      },
      async run(args) {
        const name = String(args?.name ?? '').trim();
        const action = String(args?.action ?? '').trim();
        if (!/^[A-Za-z0-9._@-]{1,60}$/.test(name)) return { output: JSON.stringify({ executed: false, error: 'Invalid PM2 process name.' }) };
        if (!['restart', 'start', 'stop', 'reload', 'delete'].includes(action)) return { output: JSON.stringify({ executed: false, error: 'Invalid action.' }) };

        // Verify the target really exists before mutating, so we never report a
        // success for a name that PM2 does not know.
        const before = await pm2Snapshot();
        if (!before.available) {
          return { output: JSON.stringify({ executed: false, error: 'PM2 tidak tersedia untuk pengguna runtime ini.' }) };
        }
        const target = before.processes.find((item) => item.name === name);
        if (!target) {
          return { output: JSON.stringify({ executed: false, error: `Proses PM2 "${name}" tidak ditemukan.`, processes: before.processes.map((p) => p.name) }, null, 2) };
        }

        const blocked = await guarded({
          action: `pm2 ${action} ${name}`,
          command: `pm2 ${action} ${name}`,
          target: name,
          routine: action !== 'stop' && action !== 'delete',
          reason: args?.reason ?? null,
        });
        if (blocked) return { ...blocked, meta: { permission: 'denied' } };
        const result = await run('pm2', [action, name]);
        audit('ai', `pm2.${action}`, name, { exitCode: result.exitCode, pmId: target.id });

        const after = await pm2Snapshot();
        const still = after.processes.find((item) => item.name === name) ?? null;
        const verified = action === 'delete' ? still === null : Boolean(still);
        recordActivity({
          type: 'ai-action',
          title: `PM2 ${action}: ${name}`,
          detail: result.stdout || result.stderr,
          source: 'ai',
          risk: action === 'stop' || action === 'delete' ? 'high' : 'medium',
          result: result.ok && verified ? 'ok' : 'failed',
        });
        return {
          output: JSON.stringify({
            executed: true,
            action,
            name,
            ok: result.ok && verified,
            verified,
            exitCode: result.exitCode,
            stdout: result.stdout.slice(0, 4000),
            stderr: result.stderr.slice(0, 2000),
            process: still,
            processes: after.processes.map((p) => ({ name: p.name, status: p.status, restarts: p.restarts })),
          }, null, 2),
        };
      },
    },
    {
      name: 'pm2_describe',
      description: 'Describe one PM2 process: status, pid, restarts, uptime, cpu, memory, script and cwd. Read-only.',
      permission: 'read',
      parameters: {
        type: 'object',
        properties: { name: { type: 'string', description: 'PM2 process name.' } },
        required: ['name'],
        additionalProperties: false,
      },
      async run(args) {
        const name = String(args?.name ?? '').trim();
        if (!name) return { output: JSON.stringify({ error: 'name wajib.' }) };
        const snapshot = await pm2Snapshot();
        const item = snapshot.processes.find((entry) => entry.name === name);
        if (!item) return { output: JSON.stringify({ error: `Proses PM2 "${name}" tidak ditemukan.`, processes: snapshot.processes.map((p) => p.name) }) };
        return { output: JSON.stringify(item, null, 2) };
      },
    },
    {
      name: 'pm2_logs',
      description: 'Read the tail of a PM2 process log (out or error). Read-only.',
      permission: 'read',
      parameters: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          kind: { type: 'string', enum: ['out', 'error'] },
          lines: { type: 'number', description: 'How many lines (1-400).' },
        },
        required: ['name'],
        additionalProperties: false,
      },
      async run(args) {
        const name = String(args?.name ?? '').trim();
        if (!/^[A-Za-z0-9._@-]{1,60}$/.test(name)) return { output: JSON.stringify({ error: 'Invalid PM2 process name.' }) };
        const kind = String(args?.kind ?? 'out').toLowerCase() === 'error' ? 'error' : 'out';
        const lines = Math.min(400, Math.max(1, Number(args?.lines) || 100));
        const file = path.join(os.homedir(), '.pm2', 'logs', `${name}-${kind}.log`);
        if (!fs.existsSync(file)) return { output: JSON.stringify({ error: 'Log PM2 tidak ditemukan.', path: file }) };
        const content = fs.readFileSync(file, 'utf8');
        return { output: content.split('\n').slice(-lines).join('\n'), meta: { path: file } };
      },
    },
    {
      name: 'pm2_save',
      description: 'Persist the current PM2 process list (pm2 save). Mutating: audited.',
      permission: 'execute',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      async run() {
        const blocked = await guarded({ action: 'pm2 save', command: 'pm2 save', target: 'pm2', routine: true });
        if (blocked) return { ...blocked, meta: { permission: 'denied' } };
        const result = await run('pm2', ['save']);
        audit('ai', 'pm2.save', 'pm2', { exitCode: result.exitCode });
        return { output: JSON.stringify({ executed: true, ok: result.ok, stdout: result.stdout, stderr: result.stderr }, null, 2) };
      },
    },
    {
      name: 'docker_action',
      description: 'Start, stop or restart a Docker container. Mutating: requires permission.',
      permission: 'execute',
      parameters: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          action: { type: 'string', enum: ['start', 'stop', 'restart'] },
          reason: { type: 'string' },
        },
        required: ['name', 'action'],
        additionalProperties: false,
      },
      async run(args) {
        const name = String(args?.name ?? '').trim();
        const action = String(args?.action ?? '').trim();
        if (!/^[A-Za-z0-9._-]{1,80}$/.test(name)) return { output: JSON.stringify({ executed: false, error: 'Invalid container name.' }) };
        if (!['start', 'stop', 'restart'].includes(action)) return { output: JSON.stringify({ executed: false, error: 'Invalid action.' }) };
        const blocked = await guarded({
          action: `docker ${action} ${name}`,
          command: `docker ${action} ${name}`,
          target: name,
          routine: action !== 'stop',
          reason: args?.reason ?? null,
        });
        if (blocked) return { ...blocked, meta: { permission: 'denied' } };
        const result = await run('docker', [action, name]);
        audit('ai', `docker.${action}`, name, { exitCode: result.exitCode });
        recordActivity({
          type: 'ai-action',
          title: `Docker ${action}: ${name}`,
          detail: result.stdout || result.stderr,
          source: 'ai',
          risk: 'medium',
          result: result.ok ? 'ok' : 'failed',
        });
        return { output: JSON.stringify({ executed: true, ...result }, null, 2) };
      },
    },
    {
      name: 'check_network',
      description: 'List listening TCP ports with their owning process. Read-only.',
      permission: 'read',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      async run() {
        const ports = await listeningPorts();
        return { output: JSON.stringify({ ports, interfaces: os.networkInterfaces() }, null, 2) };
      },
    },
    {
      name: 'read_logs',
      description: 'Read the tail of a log file inside the allowed roots (data dir, /root/.pm2/logs, /var/log). Read-only.',
      permission: 'read',
      parameters: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'Absolute log path.' },
          lines: { type: 'number', description: 'How many lines (1-400).' },
        },
        required: ['path'],
        additionalProperties: false,
      },
      async run(args) {
        const target = String(args?.path ?? '');
        const allowedRoots = [config.dataDir, path.join(os.homedir(), '.pm2', 'logs'), '/var/log'];
        const resolved = path.resolve(target);
        if (!allowedRoots.some((root) => resolved === root || resolved.startsWith(`${root}/`))) {
          return { output: JSON.stringify({ error: `Path is outside the allowed log roots: ${allowedRoots.join(', ')}` }) };
        }
        if (!fs.existsSync(resolved)) return { output: JSON.stringify({ error: 'Log file not found.' }) };
        const stat = fs.statSync(resolved);
        if (!stat.isFile()) return { output: JSON.stringify({ error: 'Not a regular file.' }) };
        const lines = Math.min(400, Math.max(1, Number(args?.lines) || 80));
        const content = fs.readFileSync(resolved, 'utf8');
        const tail = content.split('\n').slice(-lines).join('\n');
        return { output: tail, meta: { path: resolved, bytes: stat.size } };
      },
    },
    {
      name: 'remote_servers',
      description: 'List saved remote servers reachable over SFTP/SSH (never returns secrets). Read-only.',
      permission: 'read',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      async run() {
        const servers = listServers().map((server) => ({
          id: server.id,
          name: server.name,
          protocol: server.protocol,
          host: server.host,
          username: server.username,
          root: server.remoteRoot,
          status: server.lastStatus,
          isDefault: server.isDefault,
          supportsTerminal: server.supportsTerminal,
        }));
        return { output: JSON.stringify({ servers, defaultServerId: defaultServerId() }, null, 2) };
      },
    },
    {
      name: 'remote_list_files',
      description: 'List a directory on a saved remote server over SFTP. Read-only.',
      permission: 'read',
      parameters: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'Absolute remote path inside the server root.' },
          serverId: { type: 'string', description: 'Saved server id (default server when omitted).' },
          limit: { type: 'number' },
        },
        required: ['path'],
        additionalProperties: false,
      },
      async run(args) {
        const serverId = String(args?.serverId ?? defaultServerId() ?? '');
        if (!serverId) return { output: JSON.stringify({ error: 'Belum ada server remote tersimpan.' }) };
        const result = await listDirectory({
          serverId,
          target: String(args?.path ?? '.'),
          limit: Math.min(200, Math.max(1, Number(args?.limit) || 100)),
        });
        return { output: JSON.stringify({ path: result.path, entries: result.entries, truncated: result.truncated }, null, 2) };
      },
    },
    {
      name: 'remote_read_file',
      description: 'Read a text file on a saved remote server. Sensitive files (.env, keys, credentials) are refused. Read-only.',
      permission: 'read',
      parameters: {
        type: 'object',
        properties: { path: { type: 'string' }, serverId: { type: 'string' } },
        required: ['path'],
        additionalProperties: false,
      },
      async run(args) {
        const serverId = String(args?.serverId ?? defaultServerId() ?? '');
        if (!serverId) return { output: JSON.stringify({ error: 'Belum ada server remote tersimpan.' }) };
        const target = String(args?.path ?? '');
        if (isSensitivePath(target)) {
          return { output: JSON.stringify({ error: 'File sensitif tidak dibaca AI tanpa persetujuan eksplisit.' }) };
        }
        try {
          const file = await readForAi({ serverId, target });
          return {
            output: JSON.stringify(
              { path: file.path, size: file.size, modifiedAt: file.modifiedAt, truncated: file.truncated, content: file.content },
              null,
              2,
            ),
            meta: { serverId, path: file.path },
          };
        } catch (error) {
          return { output: JSON.stringify({ error: String(error?.message ?? error) }) };
        }
      },
    },
    {
      name: 'remote_search_files',
      description: 'Search file names inside a remote directory tree (bounded depth). Read-only.',
      permission: 'read',
      parameters: {
        type: 'object',
        properties: { path: { type: 'string' }, query: { type: 'string' }, serverId: { type: 'string' } },
        required: ['path', 'query'],
        additionalProperties: false,
      },
      async run(args) {
        const serverId = String(args?.serverId ?? defaultServerId() ?? '');
        if (!serverId) return { output: JSON.stringify({ error: 'Belum ada server remote tersimpan.' }) };
        const result = await searchFiles({
          serverId,
          base: String(args?.path ?? '.'),
          query: String(args?.query ?? ''),
        });
        return { output: JSON.stringify({ count: result.count, truncated: result.truncated, results: result.results.slice(0, 60) }, null, 2) };
      },
    },
    {
      name: 'remote_write_file',
      description: 'Create or overwrite a text file on a remote server. Backup and diff are produced; sensitive paths are refused. Requires permission.',
      permission: 'execute',
      parameters: {
        type: 'object',
        properties: {
          path: { type: 'string' },
          content: { type: 'string' },
          serverId: { type: 'string' },
          reason: { type: 'string' },
        },
        required: ['path', 'content'],
        additionalProperties: false,
      },
      async run(args) {
        const serverId = String(args?.serverId ?? defaultServerId() ?? '');
        if (!serverId) return { output: JSON.stringify({ executed: false, error: 'Belum ada server remote tersimpan.' }) };
        const target = String(args?.path ?? '');
        if (isSensitivePath(target)) {
          return { output: JSON.stringify({ executed: false, error: 'AI tidak boleh menulis file sensitif; minta pemilik mengedit manual.' }) };
        }
        const blocked = await guarded({
          action: `remote write ${target}`,
          command: null,
          target,
          reason: args?.reason ?? 'AI mengubah file di server remote',
        });
        if (blocked) return { ...blocked, meta: { permission: 'denied' } };
        const result = await writeFile({ serverId, target, content: String(args?.content ?? ''), actor: 'ai' });
        audit('ai', 'remote.file.written', `${serverId}:${target}`, { bytes: result.size, backup: result.backupPath });
        return { output: JSON.stringify({ executed: true, ...result }, null, 2) };
      },
    },
    {
      name: 'remote_exec',
      description: 'Run a command on a saved remote server over SSH and return stdout/stderr/exit code. Requires permission; exit code is always reported.',
      permission: 'execute',
      parameters: {
        type: 'object',
        properties: {
          command: { type: 'string' },
          serverId: { type: 'string' },
          reason: { type: 'string' },
        },
        required: ['command'],
        additionalProperties: false,
      },
      async run(args) {
        const serverId = String(args?.serverId ?? defaultServerId() ?? '');
        if (!serverId) return { output: JSON.stringify({ executed: false, error: 'Belum ada server remote tersimpan.' }) };
        const command = String(args?.command ?? '').trim();
        if (!command) return { output: JSON.stringify({ executed: false, error: 'Command kosong.' }) };
        if (command.length > 2000) return { output: JSON.stringify({ executed: false, error: 'Command terlalu panjang.' }) };
        const blocked = await guarded({
          action: `remote exec: ${command.slice(0, 120)}`,
          command,
          target: serverId,
          reason: args?.reason ?? 'AI menjalankan perintah di server remote',
        });
        if (blocked) return { ...blocked, meta: { permission: 'denied' } };
        const adapter = await getAdapter(serverId);
        if (!adapter.supportsTerminal) return { output: JSON.stringify({ executed: false, error: 'Server ini tidak mendukung eksekusi (FTP).' }) };
        const result = await adapter.exec(command, { timeoutMs: config.commandTimeoutMs });
        audit('ai', 'remote.exec', serverId, { exitCode: result.exitCode, command: command.slice(0, 200) });
        recordActivity({
          type: 'ai-action',
          title: 'Menjalankan perintah di server remote',
          detail: `${command.slice(0, 160)} (exit ${result.exitCode ?? '?'})`,
          source: 'ai',
          risk: 'medium',
          result: result.exitCode === 0 ? 'ok' : 'failed',
        });
        return {
          output: JSON.stringify({ executed: true, exitCode: result.exitCode, stdout: result.stdout.slice(0, 8000), stderr: result.stderr.slice(0, 4000) }, null, 2),
          meta: { exitCode: result.exitCode },
        };
      },
    },
    {
      name: 'get_alert_history',
      description: 'Read recent alerts and activities recorded by the lifeform. Read-only.',
      permission: 'read',
      parameters: {
        type: 'object',
        properties: { limit: { type: 'number' } },
        additionalProperties: false,
      },
      async run(args) {
        const limit = Math.min(50, Math.max(1, Number(args?.limit) || 15));
        const alerts = query.all('SELECT severity, title, detail, status, created_at FROM alerts ORDER BY created_at DESC LIMIT ?', limit);
        const activities = query.all('SELECT type, title, source, created_at FROM activities ORDER BY created_at DESC LIMIT ?', limit);
        return { output: JSON.stringify({ alerts, activities }, null, 2) };
      },
    },
  ];
}
