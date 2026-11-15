// Single WebSocket endpoint: /ws?token=<access token>
// One connection per device; the client subscribes to the event groups it needs.
import { WebSocketServer } from 'ws';
import { config } from './config.mjs';
import { logger } from './logger.mjs';
import { subscribe } from './events.mjs';
import { authenticateToken } from './auth.mjs';
import { interruptSession, resizeSession, writeInput } from './remote/terminal.mjs';

const clients = new Set();
let wss = null;
let heartbeat = null;
let unsubscribeBus = null;

export const EVENT_GROUPS = {
  server: ['server.metrics', 'server.status'],
  lifeform: ['lifeform.state', 'lifeform.awareness', 'lifeform.reflection', 'lifeform.goal.updated', 'activity.created'],
  ai: ['ai.stream', 'ai.status', 'ai.completed', 'ai.error'],
  alerts: ['alert.created', 'alert.updated'],
  approvals: ['approval.created', 'approval.resolved'],
  notifications: ['notification.created'],
  terminal: ['terminal.output', 'terminal.completed'],
  memory: ['memory.created'],
  remote: [
    'remote.transfer.started',
    'remote.transfer.progress',
    'remote.transfer.completed',
    'remote.transfer.failed',
    'remote.transfer.cancelled',
    'remote.file.created',
    'remote.file.updated',
    'remote.file.deleted',
    'remote.file.moved',
    'remote.terminal.session.created',
    'remote.terminal.session.closed',
    'remote.terminal.output',
    'remote.terminal.input',
    'remote.terminal.resize',
    'remote.terminal.interrupt',
    'remote.terminal.error',
  ],
};

function matches(subscriptions, type) {
  if (!subscriptions || subscriptions.size === 0) return true;
  if (subscriptions.has('all')) return true;
  for (const group of subscriptions) {
    if (group === type) return true;
    if (EVENT_GROUPS[group]?.includes(type)) return true;
  }
  return false;
}

function send(ws, payload) {
  if (ws.readyState !== ws.OPEN) return;
  try {
    ws.send(JSON.stringify(payload));
  } catch (error) {
    logger.debug('ws send failed', String(error));
  }
}

export function broadcast(event) {
  for (const client of clients) {
    if (!matches(client.subscriptions, event.type)) continue;
    // Terminal/transfer events carry the owning device: another device must not
    // be able to observe someone else's session, even on the same account.
    const owner = event.payload?.deviceId;
    if (owner && client.deviceId !== owner) continue;
    send(client.ws, { type: event.type, id: event.id, ts: event.ts, payload: event.payload });
  }
}

export function connectionCount() {
  return clients.size;
}

/** Map a terminal WebSocket message onto the PTY session manager. */
function handleTerminalMessage({ type, message, deviceId }) {
  const sessionId = String(message?.sessionId ?? '');
  if (!sessionId) throw Object.assign(new Error('sessionId wajib.'), { code: 'VALIDATION' });
  if (type === 'remote.terminal.input') {
    writeInput(sessionId, message?.data ?? '', { deviceId });
    return { ack: { sessionId, type } };
  }
  if (type === 'remote.terminal.resize') {
    const size = resizeSession(sessionId, { cols: message?.cols, rows: message?.rows, deviceId });
    return { ack: { sessionId, type, ...size } };
  }
  if (type === 'remote.terminal.interrupt') {
    interruptSession(sessionId, { deviceId });
    return { ack: { sessionId, type } };
  }
  throw Object.assign(new Error(`Tipe terminal tidak dikenal: ${type}`), { code: 'UNKNOWN_MESSAGE' });
}

/** Push an event to one device only (used for terminal output of its request). */
export function sendToDevice(deviceId, type, payload) {
  for (const client of clients) {
    if (client.deviceId !== deviceId) continue;
    send(client.ws, { type, ts: Date.now(), payload });
  }
}

export function attachWebSocketServer(server) {
  wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });

  server.on('upgrade', (req, socket, head) => {
    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      socket.destroy();
      return;
    }
    let path = url.pathname.replace(/\/+$/, '');
    // nginx forwards /lifeform/ws unchanged, so strip the public prefix here.
    if (config.basePath && (path === config.basePath || path.startsWith(`${config.basePath}/`))) {
      path = path.slice(config.basePath.length) || '/';
    }
    if (path !== '/ws') {
      socket.destroy();
      return;
    }
    const token = url.searchParams.get('token') ?? (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
    const auth = authenticateToken(token);
    if (!auth) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req, auth);
    });
  });

  wss.on('connection', (ws, req, auth) => {
    const client = { ws, deviceId: auth.deviceId, subscriptions: new Set(), alive: true, connectedAt: Date.now() };
    clients.add(client);
    logger.info(`ws connected (device ${auth.deviceId.slice(0, 8)}…) · total ${clients.size}`);
    send(ws, {
      type: 'connection.ready',
      ts: Date.now(),
      payload: {
        deviceId: auth.deviceId,
        groups: Object.keys(EVENT_GROUPS),
        heartbeatIntervalMs: 30_000,
      },
    });

    ws.on('message', (raw) => {
      let message;
      try {
        message = JSON.parse(String(raw));
      } catch {
        send(ws, { type: 'error', ts: Date.now(), payload: { code: 'INVALID_MESSAGE', message: 'Message must be JSON.' } });
        return;
      }
      const type = String(message?.type ?? '');
      if (type === 'subscribe') {
        const requested = Array.isArray(message.events) ? message.events.map(String) : [];
        const valid = requested.filter((event) => event === 'all' || EVENT_GROUPS[event] || event.includes('.'));
        client.subscriptions = new Set(valid);
        send(ws, { type: 'subscribed', ts: Date.now(), payload: { events: Array.from(client.subscriptions) } });
        return;
      }
      if (type === 'unsubscribe') {
        client.subscriptions = new Set();
        send(ws, { type: 'subscribed', ts: Date.now(), payload: { events: [] } });
        return;
      }
      if (type === 'ping') {
        send(ws, { type: 'pong', ts: Date.now(), payload: { latencyMs: Date.now() - Number(message.ts ?? Date.now()) } });
        return;
      }
      // Interactive terminal traffic rides the same socket as everything else.
      if (type.startsWith('remote.terminal.')) {
        try {
          const result = handleTerminalMessage({ type, message, deviceId: auth.deviceId });
          if (result?.ack) send(ws, { type: 'remote.terminal.ack', ts: Date.now(), payload: result.ack });
        } catch (error) {
          send(ws, {
            type: 'remote.terminal.error',
            ts: Date.now(),
            payload: {
              sessionId: message?.sessionId ?? null,
              code: error?.code ?? 'TERMINAL_ERROR',
              message: error?.message ?? 'Terminal error',
              deviceId: auth.deviceId,
            },
          });
        }
        return;
      }
      send(ws, { type: 'error', ts: Date.now(), payload: { code: 'UNKNOWN_MESSAGE', message: `Unknown message type: ${type}` } });
    });

    ws.on('pong', () => {
      client.alive = true;
    });
    ws.on('close', () => {
      clients.delete(client);
      logger.info(`ws disconnected · total ${clients.size}`);
    });
    ws.on('error', (error) => {
      logger.debug('ws error', String(error?.message ?? error));
    });
  });

  unsubscribeBus = subscribe(broadcast);
  heartbeat = setInterval(() => {
    for (const client of clients) {
      if (!client.alive) {
        client.ws.terminate();
        clients.delete(client);
        continue;
      }
      client.alive = false;
      try {
        client.ws.ping();
      } catch {
        /* ignore */
      }
    }
  }, 30_000);
  heartbeat.unref?.();

  logger.info('websocket server attached at /ws');
  return wss;
}

export function closeWebSocketServer() {
  if (heartbeat) clearInterval(heartbeat);
  heartbeat = null;
  unsubscribeBus?.();
  unsubscribeBus = null;
  for (const client of clients) {
    try {
      client.ws.close(1001, 'Server shutting down');
    } catch {
      /* ignore */
    }
  }
  clients.clear();
  wss?.close();
  wss = null;
}
