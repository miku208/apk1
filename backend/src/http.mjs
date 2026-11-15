// Minimal HTTP toolkit: routing, body parsing, rate limiting, safe responses.
import { config, isLoopback } from './config.mjs';
import { logger } from './logger.mjs';

const MAX_BODY_BYTES = 1024 * 1024;

export class HttpError extends Error {
  constructor(status, message, code = null, detail = null) {
    super(message);
    this.status = status;
    this.code = code ?? httpCode(status);
    this.detail = detail;
  }
}

function httpCode(status) {
  return (
    {
      400: 'BAD_REQUEST',
      401: 'UNAUTHORIZED',
      403: 'FORBIDDEN',
      404: 'NOT_FOUND',
      409: 'CONFLICT',
      422: 'UNPROCESSABLE',
      429: 'RATE_LIMITED',
      500: 'INTERNAL_ERROR',
      503: 'UNAVAILABLE',
    }[status] ?? 'ERROR'
  );
}

export function createRouter() {
  const routes = [];
  const add = (method) => (pattern, handler, options = {}) => {
    routes.push({ method, pattern, segments: pattern.split('/').filter(Boolean), handler, options });
  };
  return {
    get: add('GET'),
    post: add('POST'),
    put: add('PUT'),
    patch: add('PATCH'),
    delete: add('DELETE'),
    match(method, pathname) {
      const parts = pathname.split('/').filter(Boolean);
      let pathMatched = false;
      for (const route of routes) {
        if (route.segments.length !== parts.length) continue;
        const params = {};
        let ok = true;
        for (let i = 0; i < route.segments.length; i += 1) {
          const segment = route.segments[i];
          if (segment.startsWith(':')) params[segment.slice(1)] = decodeURIComponent(parts[i]);
          else if (segment !== parts[i]) {
            ok = false;
            break;
          }
        }
        if (!ok) continue;
        pathMatched = true;
        if (route.method === method) return { route, params };
      }
      return pathMatched ? { methodNotAllowed: true } : null;
    },
    list() {
      return routes.map((route) => `${route.method} ${route.pattern}`);
    },
  };
}

export function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded && config.trustedProxies.length) {
    const first = String(forwarded).split(',')[0].trim();
    if (first) return first;
  }
  return req.socket?.remoteAddress ?? 'unknown';
}

export async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'Request body is too large.', 'BODY_TOO_LARGE');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text.trim()) return {};
  try {
    const parsed = JSON.parse(text);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('body must be a JSON object');
    }
    return parsed;
  } catch {
    throw new HttpError(400, 'Body must be a valid JSON object.', 'INVALID_JSON');
  }
}

export function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

export function sendError(res, error, requestId) {
  const status = Number(error?.status) || 500;
  const payload = {
    error: {
      code: error?.code ?? httpCode(status),
      message: status >= 500 ? 'Internal server error.' : error?.message ?? 'Request failed.',
      ...(error?.detail ? { detail: error.detail } : {}),
      requestId,
    },
  };
  if (status >= 500) logger.error('request failed', { message: String(error?.stack ?? error) });
  sendJson(res, status, payload);
}

/** Fixed-window limiter keyed by ip+route; small and good enough for one owner. */
export function createRateLimiter({ windowMs = 60_000, max = 240 } = {}) {
  const buckets = new Map();
  return function check(key) {
    const now = Date.now();
    const bucket = buckets.get(key);
    if (!bucket || now - bucket.start > windowMs) {
      buckets.set(key, { start: now, count: 1 });
      return { allowed: true, remaining: max - 1 };
    }
    bucket.count += 1;
    if (bucket.count > max) return { allowed: false, remaining: 0, retryAfter: Math.ceil((bucket.start + windowMs - now) / 1000) };
    return { allowed: true, remaining: max - bucket.count };
  };
}

export function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
}

export function applyCors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return;
  const allowed =
    config.corsOrigins.includes(origin) ||
    (config.nodeEnv !== 'production' && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) ||
    config.corsOrigins.includes('*');
  if (!allowed) return;
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization,Content-Type,X-Requested-With');
  res.setHeader('Access-Control-Max-Age', '600');
}

export function requireString(body, key, { min = 1, max = 4000, trim = true } = {}) {
  const raw = body?.[key];
  if (typeof raw !== 'string') throw new HttpError(400, `Field "${key}" is required and must be a string.`, 'VALIDATION');
  const value = trim ? raw.trim() : raw;
  if (value.length < min || value.length > max) {
    throw new HttpError(400, `Field "${key}" must be ${min}-${max} characters.`, 'VALIDATION');
  }
  return value;
}

export function optionalString(body, key, { max = 8000 } = {}) {
  const raw = body?.[key];
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== 'string') throw new HttpError(400, `Field "${key}" must be a string.`, 'VALIDATION');
  return raw.slice(0, max);
}

export function numberParam(value, fallback, { min = 0, max = 100000 } = {}) {
  // An absent query parameter is not the number 0: Number(null) === 0 would turn
  // "no limit given" into "limit = min" for every route.
  if (value === null || value === undefined || String(value).trim() === '') return fallback;
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, Math.round(num)));
}

export function isLocalRequest(req) {
  return isLoopback(req.socket?.remoteAddress);
}
