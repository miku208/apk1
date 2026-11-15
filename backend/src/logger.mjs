// Structured logging with secret redaction and daily file rotation.
import fs from 'node:fs';
import path from 'node:path';
import { config, ensureDirs } from './config.mjs';

const SECRET_PATTERNS = [
  /\b(nvapi-[A-Za-z0-9_-]{6,})/g,
  /\b(thk[_-][A-Za-z0-9_-]{6,})/g,
  /\b(sk-[A-Za-z0-9_-]{6,})/g,
  /("?(?:api_?key|token|authorization|password|secret)"?\s*[:=]\s*")([^"]{4,})(")/gi,
];

export function redact(value) {
  let text = typeof value === 'string' ? value : JSON.stringify(value);
  if (text == null) return '';
  for (const pattern of SECRET_PATTERNS) {
    text = text.replace(pattern, (match, ...groups) => {
      if (groups.length >= 3) return `${groups[0]}***${groups[2] ?? ''}`;
      const raw = String(groups[0] ?? '');
      return `${raw.slice(0, 4)}***${raw.slice(-2)}`;
    });
  }
  return text;
}

let stream = null;
let streamDay = null;

function logFileFor(day) {
  return path.join(config.logDir, `lifeform-${day}.log`);
}

function serializeMeta(meta) {
  if (meta === undefined || meta === null) return null;
  if (typeof meta === 'object') {
    try {
      return JSON.parse(redact(meta));
    } catch {
      return { value: redact(JSON.stringify(meta)) };
    }
  }
  return { value: redact(String(meta)) };
}

function writeLine(level, message, meta) {
  const serialized = serializeMeta(meta);
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    msg: redact(message),
    ...(serialized ? { meta: serialized } : {}),
  });
  const day = new Date().toISOString().slice(0, 10);
  try {
    ensureDirs();
    if (!stream || streamDay !== day) {
      stream?.end();
      stream = fs.createWriteStream(logFileFor(day), { flags: 'a', mode: 0o600 });
      // A missing/removed log directory must never surface as an uncaught error.
      stream.on('error', () => {
        stream = null;
        streamDay = null;
      });
      streamDay = day;
      pruneLogs();
    }
    stream.write(`${line}\n`);
  } catch {
    // Logging must never take the service down.
  }
  if (config.nodeEnv !== 'test') {
    const out = level === 'error' ? process.stderr : process.stdout;
    out.write(`${line}\n`);
  }
}

function pruneLogs() {
  try {
    const cutoff = Date.now() - 14 * 24 * 60 * 60 * 1000;
    for (const name of fs.readdirSync(config.logDir)) {
      if (!name.startsWith('lifeform-')) continue;
      const file = path.join(config.logDir, name);
      if (fs.statSync(file).mtimeMs < cutoff) fs.unlinkSync(file);
    }
  } catch {
    /* ignore */
  }
}

export const logger = {
  info: (message, meta) => writeLine('info', message, meta),
  warn: (message, meta) => writeLine('warn', message, meta),
  error: (message, meta) => writeLine('error', message, meta),
  debug: (message, meta) => {
    if (config.nodeEnv !== 'production') writeLine('debug', message, meta);
  },
};
