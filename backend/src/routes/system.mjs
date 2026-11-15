// Terminal, files, settings, events, notifications, API keys and plugins.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config.mjs';
import { HttpError, numberParam, optionalString, requireString } from '../http.mjs';
import { parseJson, query } from '../db.mjs';
import { executeCommand, cancelTask, terminalTask } from '../security/terminal.mjs';
import { getLifeformState, mapAlert } from '../events.mjs';
import { autonomyLevel, AUTONOMY } from '../security/policy.mjs';
import { localNodeInfo } from '../remote/local-runtime.mjs';
import { recordActivity } from '../events.mjs';
import { monitorHealth } from '../monitor/collector.mjs';
import { connectionCount, EVENT_GROUPS } from '../ws.mjs';
import { audit } from '../auth.mjs';

const FILE_LIMIT = 512 * 1024;
const READ_ONLY_SCOPES = ['read'];

function resolveInside(rawPath) {
  const root = path.resolve(config.workspaceRoot);
  const target = path.resolve(root, String(rawPath ?? '.').replace(/^\/+/, ''));
  if (target !== root && !target.startsWith(`${root}${path.sep}`)) {
    throw new HttpError(403, 'Path berada di luar workspace.', 'PATH_ESCAPE');
  }
  return target;
}

function statEntry(target) {
  const stat = fs.statSync(target);
  return {
    name: path.basename(target),
    path: path.relative(config.workspaceRoot, target) || '.',
    type: stat.isDirectory() ? 'directory' : 'file',
    size: stat.size,
    modifiedAt: Math.round(stat.mtimeMs),
    mode: `0${(stat.mode & 0o777).toString(8)}`,
  };
}

function settingsMap() {
  const rows = query.all('SELECT key, value FROM settings');
  const out = {};
  for (const row of rows) {
    out[row.key] = parseJson(row.value, row.value);
  }
  return out;
}

const SETTING_KEYS = new Set([
  'ai_model',
  'ai_provider',
  'autonomy_level',
  'monitor_interval_ms',
  'notification_preferences',
  'lifeform_language',
]);

export function systemRoutes() {
  return [
    {
      method: 'GET',
      pattern: '/api/v1/terminal/tasks',
      handler: () => ({
        body: {
          tasks: query.all('SELECT id, command, status, exit_code, started_at, finished_at FROM terminal_tasks ORDER BY started_at DESC LIMIT 40'),
        },
      }),
    },
    {
      method: 'GET',
      pattern: '/api/v1/terminal/tasks/:id',
      handler: ({ params }) => {
        const task = terminalTask(params.id);
        if (!task) throw new HttpError(404, 'Task not found.', 'TASK_NOT_FOUND');
        return {
          body: {
            id: task.id,
            command: task.command,
            status: task.status,
            exitCode: task.exit_code,
            output: task.output,
            startedAt: task.started_at,
            finishedAt: task.finished_at,
          },
        };
      },
    },
    {
      method: 'POST',
      pattern: '/api/v1/terminal/tasks/:id/cancel',
      handler: ({ params }) => ({ body: { cancelled: cancelTask(params.id) } }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/terminal/execute',
      handler: async ({ body, auth }) => {
        const command = requireString(body, 'command', { min: 1, max: 4000 });
        const timeoutMs = numberParam(body.timeoutMs, config.commandTimeoutMs, { min: 1000, max: 600_000 });
        const result = await executeCommand({ command, timeoutMs, actor: auth.deviceName ?? auth.deviceId, deviceId: auth.deviceId });
        return { body: result };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/files',
      handler: ({ url }) => {
        const target = resolveInside(url.searchParams.get('path') ?? '.');
        if (!fs.existsSync(target)) throw new HttpError(404, 'Path not found.', 'ENOENT');
        const stat = fs.statSync(target);
        if (!stat.isDirectory()) throw new HttpError(400, 'Not a directory.', 'NOT_DIRECTORY');
        const entries = fs
          .readdirSync(target, { withFileTypes: true })
          .slice(0, 500)
          .map((entry) => {
            try {
              return statEntry(path.join(target, entry.name));
            } catch {
              return null;
            }
          })
          .filter(Boolean)
          .sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type === 'directory' ? -1 : 1));
        return { body: { path: path.relative(config.workspaceRoot, target) || '.', entries } };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/files/read',
      handler: ({ url }) => {
        const target = resolveInside(url.searchParams.get('path') ?? '');
        if (!fs.existsSync(target)) throw new HttpError(404, 'File not found.', 'ENOENT');
        const stat = fs.statSync(target);
        if (!stat.isFile()) throw new HttpError(400, 'Not a file.', 'NOT_FILE');
        if (stat.size > FILE_LIMIT) throw new HttpError(413, `File lebih besar dari ${FILE_LIMIT} bytes.`, 'FILE_TOO_LARGE');
        if (/\.(pem|key|p12|pfx)$/i.test(target) || /(^|\/)(\.env|credentials\.json|id_rsa)$/i.test(target)) {
          throw new HttpError(403, 'File sensitif tidak boleh dibaca lewat API.', 'SENSITIVE_FILE');
        }
        return {
          body: { path: path.relative(config.workspaceRoot, target), size: stat.size, modifiedAt: Math.round(stat.mtimeMs), content: fs.readFileSync(target, 'utf8') },
        };
      },
    },
    {
      method: 'POST',
      pattern: '/api/v1/files/write',
      handler: ({ body, auth }) => {
        const target = resolveInside(requireString(body, 'path', { min: 1, max: 500 }));
        const content = String(body.content ?? '');
        if (Buffer.byteLength(content) > FILE_LIMIT) throw new HttpError(413, 'Content too large.', 'FILE_TOO_LARGE');
        fs.mkdirSync(path.dirname(target), { recursive: true });
        const existed = fs.existsSync(target);
        fs.writeFileSync(target, content, { mode: 0o644 });
        audit(auth.deviceId, existed ? 'file.overwrite' : 'file.create', target, { bytes: content.length });
        recordActivity({ type: 'file', title: `${existed ? 'Mengubah' : 'Membuat'} file ${path.relative(config.workspaceRoot, target)}`, source: auth.deviceName ?? 'app', result: 'ok' });
        return { body: { path: path.relative(config.workspaceRoot, target), bytes: content.length, created: !existed } };
      },
    },
    {
      method: 'POST',
      pattern: '/api/v1/files/search',
      handler: ({ body }) => {
        const needle = requireString(body, 'query', { min: 1, max: 200 }).toLowerCase();
        const base = resolveInside(optionalString(body, 'path', { max: 500 }) ?? '.');
        const max = numberParam(body.limit, 60, { min: 1, max: 200 });
        const results = [];
        const walk = (dir, depth) => {
          if (depth > 6 || results.length >= max) return;
          let entries = [];
          try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
          } catch {
            return;
          }
          for (const entry of entries) {
            if (results.length >= max) return;
            if (entry.name === 'node_modules' || entry.name === '.git') continue;
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(full, depth + 1);
            else if (entry.name.toLowerCase().includes(needle)) {
              try {
                results.push(statEntry(full));
              } catch {
                /* skip */
              }
            }
          }
        };
        walk(base, 0);
        return { body: { query: needle, results } };
      },
    },
    {
      method: 'DELETE',
      pattern: '/api/v1/files',
      handler: ({ url, auth }) => {
        const target = resolveInside(url.searchParams.get('path') ?? '');
        if (target === path.resolve(config.workspaceRoot)) throw new HttpError(400, 'Tidak bisa menghapus workspace root.', 'ROOT_DELETE');
        if (!fs.existsSync(target)) throw new HttpError(404, 'Path not found.', 'ENOENT');
        const stat = fs.statSync(target);
        if (stat.isDirectory() && fs.readdirSync(target).length > 0) {
          throw new HttpError(409, 'Direktori tidak kosong; hapus isinya lebih dulu.', 'DIRECTORY_NOT_EMPTY');
        }
        fs.unlinkSync(target);
        audit(auth.deviceId, 'file.delete', target, {});
        recordActivity({ type: 'file', title: `Menghapus ${path.relative(config.workspaceRoot, target)}`, source: auth.deviceName ?? 'app', result: 'ok' });
        return { body: { deleted: true } };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/settings',
      handler: async () => ({
        body: {
          settings: settingsMap(),
          autonomy: { level: autonomyLevel(), ...AUTONOMY[autonomyLevel()], options: Object.values(AUTONOMY) },
          runtime: await localNodeInfo(),
          backend: {
            baseUrl: config.publicBaseUrl,
            basePath: config.basePath,
            host: config.host,
            port: config.port,
            nodeEnv: config.nodeEnv,
            version: config.version,
          },
          monitor: monitorHealth(),
          ws: { connections: connectionCount(), groups: Object.keys(EVENT_GROUPS) },
        },
      }),
    },
    {
      method: 'PUT',
      pattern: '/api/v1/settings',
      handler: ({ body, auth }) => {
        const updated = {};
        for (const [key, value] of Object.entries(body ?? {})) {
          if (!SETTING_KEYS.has(key)) throw new HttpError(400, `Setting "${key}" tidak dikenal.`, 'UNKNOWN_SETTING');
          query.run(
            `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
            key,
            JSON.stringify(value),
            Date.now(),
          );
          updated[key] = value;
        }
        audit(auth.deviceId, 'settings.updated', null, updated);
        return { body: { updated } };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/events',
      handler: ({ url }) => {
        const limit = numberParam(url.searchParams.get('limit'), 50, { min: 1, max: 200 });
        const activities = query
          .all('SELECT * FROM activities ORDER BY created_at DESC LIMIT ?', limit)
          .map((row) => ({
            id: row.id,
            type: 'activity',
            activityType: row.type,
            title: row.title,
            detail: row.detail,
            source: row.source,
            risk: row.risk,
            result: row.result,
            createdAt: row.created_at,
          }));
        const alerts = query.all('SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?', limit).map(mapAlert);
        const notifications = query
          .all('SELECT * FROM notifications ORDER BY created_at DESC LIMIT ?', limit)
          .map((row) => ({ id: row.id, title: row.title, body: row.body, level: row.level, status: row.status, createdAt: row.created_at }));
        const approvals = query
          .all("SELECT * FROM approvals WHERE status = 'pending' ORDER BY created_at DESC LIMIT ?", limit)
          .map((row) => ({ id: row.id, action: row.action, risk: row.risk, target: row.target, expiresAt: row.expires_at }));
        return { body: { activities, alerts, notifications, pendingApprovals: approvals } };
      },
    },
    {
      method: 'POST',
      pattern: '/api/v1/notifications/:id/read',
      handler: ({ params }) => {
        query.run("UPDATE notifications SET status = 'read', read_at = ? WHERE id = ?", Date.now(), params.id);
        return { body: { ok: true } };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/api-keys',
      handler: () => ({
        body: {
          keys: query.all('SELECT id, label, scopes, rate_limit, created_at, last_used_at, revoked_at FROM api_keys ORDER BY created_at DESC').map((row) => ({
            id: row.id,
            label: row.label,
            scopes: row.scopes.split(','),
            rateLimit: row.rate_limit,
            createdAt: row.created_at,
            lastUsedAt: row.last_used_at,
            revoked: Boolean(row.revoked_at),
          })),
        },
      }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/api-keys',
      handler: ({ body, auth }) => {
        const label = requireString(body, 'label', { min: 2, max: 80 });
        const scopes = Array.isArray(body.scopes) ? body.scopes.join(',') : READ_ONLY_SCOPES.join(',');
        const secret = `mlf_${crypto.randomBytes(24).toString('base64url')}`;
        const id = crypto.randomUUID();
        query.run(
          'INSERT INTO api_keys (id, label, key_hash, scopes, rate_limit, created_at) VALUES (?, ?, ?, ?, ?, ?)',
          id,
          label,
          crypto.createHash('sha256').update(secret).digest('hex'),
          scopes,
          Number(body.rateLimit ?? 60),
          Date.now(),
        );
        audit(auth.deviceId, 'apikey.created', id, { scopes });
        return { status: 201, body: { id, label, scopes: scopes.split(','), key: secret, note: 'Simpan key ini sekarang; hanya ditampilkan sekali.' } };
      },
    },
    {
      method: 'DELETE',
      pattern: '/api/v1/api-keys/:id',
      handler: ({ params, auth }) => {
        query.run('UPDATE api_keys SET revoked_at = ? WHERE id = ?', Date.now(), params.id);
        audit(auth.deviceId, 'apikey.revoked', params.id, {});
        return { body: { revoked: true } };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/plugins',
      handler: () => ({
        body: {
          plugins: query.all('SELECT * FROM plugin_registry ORDER BY created_at DESC').map((row) => ({
            id: row.id,
            name: row.name,
            version: row.version,
            description: row.description,
            category: row.category,
            enabled: Boolean(row.enabled),
            permissions: parseJson(row.permissions, []),
            createdAt: row.created_at,
          })),
          note: 'Plugin dijalankan in-process dengan permission yang divalidasi; belum ada plugin terpasang.',
        },
      }),
    },
    {
      method: 'PUT',
      pattern: '/api/v1/plugins/:id',
      handler: ({ params, body, auth }) => {
        const enabled = body.enabled ? 1 : 0;
        query.run('UPDATE plugin_registry SET enabled = ? WHERE id = ?', enabled, params.id);
        audit(auth.deviceId, 'plugin.toggled', params.id, { enabled });
        return { body: { id: params.id, enabled: Boolean(enabled) } };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/security/audit',
      handler: ({ url }) => {
        const limit = numberParam(url.searchParams.get('limit'), 100, { min: 1, max: 500 });
        return {
          body: {
            logs: query.all('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?', limit).map((row) => ({
              id: row.id,
              actor: row.actor,
              action: row.action,
              target: row.target,
              detail: parseJson(row.detail, null),
              result: row.result,
              createdAt: row.created_at,
            })),
          },
        };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/health',
      auth: false,
      handler: () => ({
        body: {
          status: 'ok',
          service: config.serviceName,
          version: config.version,
          uptime: Math.round(process.uptime()),
          state: getLifeformState().state,
          monitor: monitorHealth(),
          wsConnections: connectionCount(),
          time: new Date().toISOString(),
        },
      }),
    },
  ];
}
