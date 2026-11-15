// REST surface for VPS Remote Control. Every route is authenticated and is
// restricted to device tokens (API keys cannot reach other machines).
import fs from 'node:fs';
import { query } from '../db.mjs';
import { HttpError, numberParam } from '../http.mjs';
import { audit } from '../auth.mjs';
import { defaultServerId, listConnectionHistory, listServers, publicServer, requireDeviceAuth, deleteServer, createServer, updateServer, getServerRow } from './servers.mjs';
import { connectionOverview, withNodeInfo, testServer, closeServer, connectServer } from './connection.mjs';
import { localNodeInfo } from './local-runtime.mjs';
import {
  copyPath,
  deletePath,
  downloadToResponse,
  fileMetadata,
  listDirectory,
  makeDirectory,
  movePath,
  openPreview,
  previewWrite,
  readFile,
  renamePath,
  searchFiles,
  uploadFile,
  writeFile,
} from './files.mjs';
import { cancelTransfer, getTransfer, listTransfers } from './transfers.mjs';
import { createSession, getSession, listSessions, closeSession, activeSessionCount } from './terminal.mjs';
import { isSensitivePath } from './paths.mjs';

function requireServerId(url, body) {
  const fromBody = body?.serverId;
  // Body-only routes pass no URL; query routes pass one.
  const fromQuery = url?.searchParams ? url.searchParams.get('serverId') : null;
  const id = fromBody || fromQuery || defaultServerId();
  if (!id) throw new HttpError(400, 'Belum ada server remote. Tambahkan server terlebih dahulu.', 'NO_REMOTE_SERVER');
  return id;
}

function pathParam(url) {
  const value = url.searchParams.get('path');
  if (!value) throw new HttpError(400, 'Parameter path wajib.', 'VALIDATION');
  return value;
}

function boolParam(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function disposition(type, filename) {
  const safe = String(filename ?? 'file').replace(/[\r\n"]/g, '_');
  return `${type}; filename="${safe.replace(/[^\x20-\x7e]/g, '_')}"; filename*=UTF-8''${encodeURIComponent(safe)}`;
}

export function remoteRoutes() {
  const withAuth = (handler) => async (ctx) => {
    requireDeviceAuth(ctx.auth);
    return handler(ctx);
  };

  return [
    {
      method: 'GET',
      pattern: '/api/v1/remote/overview',
      handler: withAuth(async () => {
        const servers = await Promise.all(connectionOverview().map(withNodeInfo));
        return {
          body: {
            servers,
            primary: servers.find((item) => item.isLocal) ?? null,
            transfers: listTransfers({ limit: 20 }),
            sessions: listSessions(),
            activeSessions: activeSessionCount(),
            defaults: { serverId: defaultServerId() },
          },
        };
      }),
    },
    {
      method: 'GET',
      pattern: '/api/v1/remote/servers',
      handler: withAuth(async () => ({
        body: {
          servers: await Promise.all(connectionOverview().map(withNodeInfo)),
          defaultServerId: defaultServerId(),
        },
      })),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/servers',
      handler: withAuth(({ body, auth }) => ({ status: 201, body: { server: createServer(body, auth) } })),
    },
    {
      method: 'GET',
      pattern: '/api/v1/remote/servers/:id',
      handler: withAuth(async ({ params }) => {
        const row = getServerRow(params.id);
        const server = publicServer(row);
        const entry = connectionOverview().find((item) => item.id === row.id) ?? null;
        return {
          body: {
            server,
            node: server.isLocal ? await localNodeInfo() : null,
            live: entry?.connection ?? null,
            history: listConnectionHistory({ serverId: row.id, limit: 20 }),
          },
        };
      }),
    },
    {
      method: 'PUT',
      pattern: '/api/v1/remote/servers/:id',
      handler: withAuth(({ params, body, auth }) => {
        const server = updateServer(params.id, body, auth);
        if (body?.hostFingerprint !== undefined || body?.host !== undefined || body?.port !== undefined) {
          // Configuration changed: drop the live connection so the next call
          // re-validates the host key instead of reusing a stale session.
          closeServer(params.id, 'config-changed');
        }
        return { body: { server } };
      }),
    },
    {
      method: 'DELETE',
      pattern: '/api/v1/remote/servers/:id',
      handler: withAuth(({ params, auth }) => {
        closeServer(params.id, 'server-deleted');
        return { body: deleteServer(params.id, auth) };
      }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/servers/:id/test',
      handler: withAuth(async ({ params }) => ({ body: await testServer(params.id) })),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/servers/:id/trust',
      handler: withAuth(({ params, body, auth }) => {
        const existing = getServerRow(params.id);
        const local = String(existing?.runtime ?? '').toLowerCase() === 'local' || String(existing?.protocol ?? '').toLowerCase() === 'local';
        if (local) {
          audit(auth.deviceId, 'remote.server.trusted', params.id, { local: true });
          return { body: { server: publicServer(existing), trusted: true, local: true } };
        }
        const fingerprint = String(body?.fingerprint ?? '').trim();
        if (!fingerprint) throw new HttpError(400, 'Fingerprint wajib.', 'VALIDATION');
        const server = updateServer(params.id, { hostFingerprint: fingerprint }, auth);
        audit(auth.deviceId, 'remote.server.trusted', params.id, { fingerprint });
        return { body: { server, trusted: true } };
      }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/servers/:id/reconnect',
      handler: withAuth(async ({ params }) => {
        await connectServer(params.id, { force: true });
        return { body: { reconnected: true, serverId: params.id } };
      }),
    },

    // ---- File manager -------------------------------------------------------
    {
      method: 'GET',
      pattern: '/api/v1/remote/files/list',
      handler: withAuth(async ({ url }) => {
        const serverId = requireServerId(url);
        const body = await listDirectory({
          serverId,
          target: url.searchParams.get('path') ?? undefined,
          showHidden: boolParam(url.searchParams.get('hidden'), true),
          sortBy: url.searchParams.get('sort') ?? 'name',
          order: url.searchParams.get('order') ?? 'asc',
          search: url.searchParams.get('q'),
          offset: numberParam(url.searchParams.get('offset'), 0, { min: 0, max: 100000 }),
          limit: numberParam(url.searchParams.get('limit'), 200, { min: 1, max: 500 }),
        });
        return { body };
      }),
    },
    {
      method: 'GET',
      pattern: '/api/v1/remote/files/read',
      handler: withAuth(async ({ url }) => ({
        body: await readFile({
          serverId: requireServerId(url),
          target: pathParam(url),
          maxBytes: numberParam(url.searchParams.get('maxBytes'), 2 * 1024 * 1024, { min: 1024, max: 8 * 1024 * 1024 }),
        }),
      })),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/files/diff',
      handler: withAuth(async ({ body }) => ({
        body: await previewWrite({
          serverId: requireServerId(null, body),
          target: String(body?.path ?? ''),
          content: String(body?.content ?? ''),
        }),
      })),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/files/write',
      handler: withAuth(async ({ body, auth }) => {
        const result = await writeFile({
          serverId: requireServerId(null, body),
          target: String(body?.path ?? ''),
          content: String(body?.content ?? ''),
          confirmSensitive: Boolean(body?.confirmSensitive),
          expectedModifiedAt: body?.expectedModifiedAt ?? null,
          actor: auth.deviceName ?? auth.deviceId,
        });
        return { body: result };
      }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/files/upload',
      // Binary body: the server skips JSON parsing for this route and the
      // request stream is piped straight into SFTP.
      rawBody: true,
      handler: withAuth(async ({ req, url, auth }) => {
        const serverId = requireServerId(url);
        const target = pathParam(url);
        const total = Number(req.headers['content-length'] ?? '') || null;
        const result = await uploadFile({
          serverId,
          target,
          stream: req,
          size: total,
          overwrite: boolParam(url.searchParams.get('overwrite')),
          deviceId: auth.deviceId,
          actor: auth.deviceName ?? auth.deviceId,
        });
        return { body: result };
      }),
    },
    {
      method: 'GET',
      pattern: '/api/v1/remote/files/download',
      handler: withAuth(async ({ url, res, auth }) => {
        const serverId = requireServerId(url);
        const target = pathParam(url);
        audit(auth.deviceId, 'remote.file.download.requested', `${serverId}:${target}`);
        await downloadToResponse({
          serverId,
          target,
          res,
          deviceId: auth.deviceId,
          actor: auth.deviceName ?? auth.deviceId,
        });
        return { streamed: true };
      }),
    },
    {
      method: 'GET',
      pattern: '/api/v1/remote/files/preview',
      handler: withAuth(async ({ url, res }) => {
        const preview = await openPreview({
          serverId: requireServerId(url),
          target: pathParam(url),
        });
        res.writeHead(200, {
          'Content-Type': preview.mime,
          'Content-Length': preview.size,
          'Content-Disposition': disposition('inline', preview.name),
          'Cache-Control': 'no-store',
        });
        preview.stream.on('error', () => res.destroy());
        preview.stream.pipe(res);
        return { streamed: true };
      }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/files/rename',
      handler: withAuth(async ({ body, auth }) => ({
        body: await renamePath({
          serverId: requireServerId(null, body),
          target: String(body?.path ?? ''),
          name: String(body?.name ?? ''),
          overwrite: Boolean(body?.overwrite),
          actor: auth.deviceName ?? auth.deviceId,
        }),
      })),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/files/copy',
      handler: withAuth(async ({ body, auth }) => ({
        body: await copyPath({
          serverId: requireServerId(null, body),
          target: String(body?.path ?? ''),
          destination: String(body?.destination ?? ''),
          overwrite: Boolean(body?.overwrite),
          recursive: Boolean(body?.recursive),
          actor: auth.deviceName ?? auth.deviceId,
        }),
      })),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/files/move',
      handler: withAuth(async ({ body, auth }) => ({
        body: await movePath({
          serverId: requireServerId(null, body),
          target: String(body?.path ?? ''),
          destination: String(body?.destination ?? ''),
          overwrite: Boolean(body?.overwrite),
          actor: auth.deviceName ?? auth.deviceId,
        }),
      })),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/files/mkdir',
      handler: withAuth(async ({ body, auth }) => ({
        body: await makeDirectory({
          serverId: requireServerId(null, body),
          target: String(body?.path ?? ''),
          recursive: Boolean(body?.recursive),
          actor: auth.deviceName ?? auth.deviceId,
        }),
      })),
    },
    {
      method: 'DELETE',
      pattern: '/api/v1/remote/files/delete',
      handler: withAuth(async ({ url, auth }) => ({
        body: await deletePath({
          serverId: requireServerId(url),
          target: pathParam(url),
          recursive: boolParam(url.searchParams.get('recursive')),
          confirm: boolParam(url.searchParams.get('confirm')),
          actor: auth.deviceName ?? auth.deviceId,
        }),
      })),
    },
    {
      method: 'GET',
      pattern: '/api/v1/remote/files/metadata',
      handler: withAuth(async ({ url }) => ({
        body: await fileMetadata({ serverId: requireServerId(url), target: pathParam(url) }),
      })),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/files/search',
      handler: withAuth(async ({ body }) => ({
        body: await searchFiles({
          serverId: requireServerId(null, body),
          base: String(body?.path ?? '.'),
          query: String(body?.query ?? ''),
          limit: body?.limit ? Number(body.limit) : null,
        }),
      })),
    },

    // ---- Transfers ----------------------------------------------------------
    {
      method: 'GET',
      pattern: '/api/v1/remote/transfers',
      handler: withAuth(({ url }) => ({
        body: {
          transfers: listTransfers({
            limit: numberParam(url.searchParams.get('limit'), 50, { min: 1, max: 200 }),
            serverId: url.searchParams.get('serverId') ?? null,
          }),
        },
      })),
    },
    {
      method: 'GET',
      pattern: '/api/v1/remote/transfers/:id',
      handler: withAuth(({ params }) => ({ body: { transfer: getTransfer(params.id) } })),
    },
    {
      method: 'POST',
      pattern: '/api/v1/remote/transfers/:id/cancel',
      handler: withAuth(({ params, auth }) => {
        const result = cancelTransfer(params.id);
        audit(auth.deviceId, 'remote.transfer.cancelled', params.id);
        return { body: { transfer: result, cancelled: true } };
      }),
    },

    // ---- Terminal -----------------------------------------------------------
    {
      method: 'POST',
      pattern: '/api/v1/remote/terminal/sessions',
      handler: withAuth(async ({ body, auth }) => ({
        status: 201,
        body: {
          session: await createSession({
            serverId: requireServerId(null, body),
            deviceId: auth.deviceId,
            userId: auth.deviceId,
            cwd: body?.cwd ? String(body.cwd) : null,
            cols: Number(body?.cols ?? 80),
            rows: Number(body?.rows ?? 24),
          }),
        },
      })),
    },
    {
      method: 'GET',
      pattern: '/api/v1/remote/terminal/sessions',
      handler: withAuth(({ url }) => ({ body: { sessions: listSessions({ serverId: url.searchParams.get('serverId') }) } })),
    },
    {
      method: 'GET',
      pattern: '/api/v1/remote/terminal/sessions/:id',
      handler: withAuth(({ params, auth }) => ({ body: getSession(params.id, { deviceId: auth.deviceId }) })),
    },
    {
      method: 'DELETE',
      pattern: '/api/v1/remote/terminal/sessions/:id',
      handler: withAuth(({ params, auth }) => {
        const result = closeSession(params.id, 'closed-by-user');
        audit(auth.deviceId, 'remote.terminal.closed', params.id);
        return { body: result };
      }),
    },

    // ---- Audit --------------------------------------------------------------
    {
      method: 'GET',
      pattern: '/api/v1/remote/audit',
      handler: withAuth(({ url }) => {
        const limit = numberParam(url.searchParams.get('limit'), 60, { min: 1, max: 300 });
        const serverId = url.searchParams.get('serverId');
        const actions = query
          .all("SELECT * FROM audit_logs WHERE action LIKE 'remote.%' ORDER BY created_at DESC LIMIT ?", limit)
          .map((row) => ({
            id: row.id,
            actor: row.actor,
            action: row.action,
            target: row.target,
            result: row.result,
            createdAt: row.created_at,
          }));
        return {
          body: {
            connections: listConnectionHistory({ serverId, limit }),
            actions,
            transfers: listTransfers({ limit: 20, serverId }),
            sessions: listSessions({ serverId }),
          },
        };
      }),
    },
  ];
}
