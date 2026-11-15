// MikuHost Lifeform backend: one HTTP server + one WebSocket endpoint.
import http from 'node:http';
import crypto from 'node:crypto';
import { config, ensureDirs } from './config.mjs';
import { logger } from './logger.mjs';
import { closeDatabase, openDatabase, query } from './db.mjs';
import {
  applyCors,
  applySecurityHeaders,
  clientIp,
  createRateLimiter,
  createRouter,
  HttpError,
  readJson,
  sendError,
  sendJson,
} from './http.mjs';
import { ensureOwner, authenticateToken, createPairingSession, activePairingSessions, audit } from './auth.mjs';
import { attachWebSocketServer, closeWebSocketServer, connectionCount } from './ws.mjs';
import { expireApprovals } from './security/policy.mjs';
import { startMonitor, stopMonitor, monitorHealth } from './monitor/collector.mjs';
import { ensureNode } from './monitor/collector.mjs';
import { ensureIdentity } from './lifeform/identity.mjs';
import { startLifeform, stopLifeform } from './lifeform/core.mjs';
import { authRoutes } from './routes/auth.mjs';
import { aiRoutes } from './routes/ai.mjs';
import { lifeformRoutes } from './routes/lifeform.mjs';
import { monitorRoutes } from './routes/monitor.mjs';
import { systemRoutes } from './routes/system.mjs';
import { remoteRoutes } from './remote/routes.mjs';
import { closeAllConnections } from './remote/connection.mjs';
import { ensurePrimaryNode } from './remote/servers.mjs';
import { cancelAllTransfers } from './remote/transfers.mjs';
import { closeAllSessions, recoverSessionsOnStartup, startTerminalSweeper, stopTerminalSweeper } from './remote/terminal.mjs';
import { getEngine } from './ai/engine.mjs';

const limiter = createRateLimiter({ windowMs: 60_000, max: 300 });
const loginLimiter = createRateLimiter({ windowMs: 10 * 60_000, max: 20 });

function buildRouter() {
  const router = createRouter();
  for (const route of [...authRoutes(), ...aiRoutes(), ...lifeformRoutes(), ...monitorRoutes(), ...systemRoutes(), ...remoteRoutes()]) {
    const add = router[route.method.toLowerCase()];
    add(route.pattern, route.handler, { auth: route.auth !== false, rawBody: route.rawBody === true });
  }
  // Spec alias: GET /health
  router.get('/health', () => ({
    body: {
      status: 'ok',
      service: config.serviceName,
      version: config.version,
      uptime: Math.round(process.uptime()),
    },
  }), { auth: false });
  return router;
}

/** API keys are read-only by scope; device tokens carry owner scope. */
function authenticateApiKey(rawToken) {
  if (!rawToken.startsWith('mlf_')) return null;
  const hash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const row = query.get('SELECT * FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL', hash);
  if (!row) return null;
  query.run('UPDATE api_keys SET last_used_at = ? WHERE id = ?', Date.now(), row.id);
  return { deviceId: `apikey:${row.id}`, deviceName: row.label, scopes: row.scopes, apiKey: true };
}

const router = buildRouter();

const server = http.createServer(async (req, res) => {
  const requestId = crypto.randomUUID();
  const startedAt = Date.now();
  applySecurityHeaders(res);
  applyCors(req, res);

  let url;
  try {
    url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
  } catch {
    sendJson(res, 400, { error: { code: 'BAD_URL', message: 'Malformed request URL.', requestId } });
    return;
  }

  let pathname = url.pathname.replace(/\/+$/, '') || '/';
  if (config.basePath && (pathname === config.basePath || pathname.startsWith(`${config.basePath}/`))) {
    pathname = pathname.slice(config.basePath.length) || '/';
  }

  res.on('finish', () => {
    const entry = {
      method: req.method,
      path: pathname,
      status: res.statusCode,
      ms: Date.now() - startedAt,
      ip: clientIp(req),
    };
    if (res.statusCode >= 400) logger.warn('http', entry);
    else logger.debug('http', entry);
  });

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const matched = router.match(req.method, pathname);
  if (!matched) {
    sendJson(res, 404, { error: { code: 'NOT_FOUND', message: `No route for ${req.method} ${pathname}`, requestId } });
    return;
  }
  if (matched.methodNotAllowed) {
    sendJson(res, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: `${req.method} not allowed for ${pathname}`, requestId } });
    return;
  }

  const { route, params } = matched;
  const ip = clientIp(req);
  const isAuthPath = pathname.startsWith('/api/v1/auth');
  const limit = isAuthPath ? loginLimiter(ip) : limiter(`${ip}:${route.pattern}`);
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfter ?? 60));
    sendJson(res, 429, { error: { code: 'RATE_LIMITED', message: 'Terlalu banyak request. Coba lagi sebentar.', requestId } });
    return;
  }

  try {
    let auth = null;
    if (route.options.auth !== false) {
      const header = req.headers.authorization ?? '';
      const token = header.replace(/^Bearer\s+/i, '').trim();
      if (!token) throw new HttpError(401, 'Token akses diperlukan.', 'MISSING_TOKEN');
      auth = authenticateApiKey(token) ?? authenticateToken(token);
      if (!auth) throw new HttpError(401, 'Token tidak valid atau sudah kedaluwarsa.', 'INVALID_TOKEN');
      if (auth.apiKey && req.method !== 'GET') {
        throw new HttpError(403, 'API key hanya bisa membaca. Gunakan token device untuk tindakan.', 'APIKEY_READ_ONLY');
      }
    }

    // Uploads stream their body straight into SFTP: those routes opt out of JSON parsing.
    const body = ['POST', 'PUT', 'PATCH'].includes(req.method) && !route.options.rawBody
      ? await readJson(req)
      : {};
    const result = (await route.handler({ req, res, url, params, body, auth, ip, requestId })) ?? {};
    if (result.streamed) return;
    const status = result.status ?? 200;
    if (result.body === undefined) {
      res.writeHead(status);
      res.end();
      return;
    }
    sendJson(res, status, result.body);
  } catch (error) {
    sendError(res, error, requestId);
  }
});

server.keepAliveTimeout = 65_000;
server.headersTimeout = 70_000;

async function bootstrap() {
  ensureDirs();
  openDatabase();
  ensureOwner();
  ensureNode();
  ensureIdentity();
  // The host running this backend is the Primary Node: adopt it into the local
  // runtime once, so Remote Control never opens SSH/SFTP to itself.
  await ensurePrimaryNode();

  startMonitor();
  attachWebSocketServer(server);
  startLifeform();
  // PTY sessions cannot survive a restart: mark them disconnected honestly and
  // start the idle sweeper for the new process.
  recoverSessionsOnStartup();
  startTerminalSweeper();

  // Warm the AI adapter so a misconfigured engine fails loudly at startup.
  try {
    await getEngine();
  } catch (error) {
    logger.error('AI engine unavailable at startup', String(error?.message ?? error));
  }

  const sweeper = setInterval(() => {
    try {
      expireApprovals();
    } catch (error) {
      logger.warn('approval sweeper failed', String(error));
    }
  }, 30_000);
  sweeper.unref?.();

  server.listen(config.port, config.host, () => {
    logger.info(`${config.serviceName} listening on http://${config.host}:${config.port}${config.basePath}`);
    logger.info(`public base: ${config.publicBaseUrl}${config.basePath}`);
    if (!activePairingSessions().length) {
      const session = createPairingSession({ createdBy: 'startup' });
      logger.info(`PAIRING CODE: ${session.code} (berlaku ${Math.round(config.pairingTtlMs / 60000)} menit) — masukkan di aplikasi Android`);
    }
    if (!config.ownerPassword) {
      logger.info('password login nonaktif (set OWNER_PASSWORD untuk mengaktifkannya); pairing code tetap bisa dipakai');
    }
  });

  const shutdown = (signal) => {
    logger.info(`shutting down (${signal})`);
    stopMonitor();
    stopLifeform();
    stopTerminalSweeper();
    closeAllSessions('backend shutdown');
    cancelAllTransfers('backend shutdown');
    closeAllConnections();
    closeWebSocketServer();
    server.close(() => {
      closeDatabase();
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 10_000).unref?.();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', (reason) => logger.error('unhandled rejection', String(reason)));
  process.on('uncaughtException', (error) => logger.error('uncaught exception', String(error?.stack ?? error)));
}

bootstrap().catch((error) => {
  logger.error('bootstrap failed', String(error?.stack ?? error));
  process.exit(1);
});

export { server, router };
