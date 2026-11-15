// MikuHost Lifeform — runtime configuration. All values come from the environment.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');

function loadDotEnv(file) {
  if (!fs.existsSync(file)) return {};
  const out = {};
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) out[key] = value;
  }
  return out;
}

const fileEnv = loadDotEnv(path.join(ROOT, '.env'));

function env(name, fallback = null) {
  const value = process.env[name] ?? fileEnv[name];
  if (value === undefined || value === null || String(value).trim() === '') return fallback;
  return String(value).trim();
}

function int(name, fallback) {
  const raw = env(name, null);
  if (raw === null) return fallback;
  const num = Number(raw);
  return Number.isFinite(num) ? num : fallback;
}

function bool(name, fallback = false) {
  const value = env(name, '');
  if (!value) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

const dataDir = path.resolve(env('DATA_DIR', path.join(ROOT, 'data')));

export const config = Object.freeze({
  root: ROOT,
  dataDir,
  dbFile: path.join(dataDir, 'lifeform.db'),
  logDir: path.join(dataDir, 'logs'),

  nodeEnv: env('NODE_ENV', 'production'),
  host: env('HOST', '127.0.0.1'),
  port: int('PORT', 8888),
  publicBaseUrl: env('PUBLIC_BASE_URL', 'https://ashimusic.biz.id'),
  // Path prefix nginx already serves for the other apps on this domain.
  basePath: env('BASE_PATH', '/lifeform').replace(/\/+$/, '') || '',
  trustedProxies: env('TRUSTED_PROXIES', '127.0.0.1,::1')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean),
  corsOrigins: env('CORS_ORIGINS', '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean),

  version: '1.0.0',
  serviceName: 'MikuHost Lifeform',

  // Auth
  ownerPassword: env('OWNER_PASSWORD', null),
  pairingTtlMs: int('PAIRING_TTL_MS', 10 * 60 * 1000),
  accessTokenTtlMs: int('ACCESS_TOKEN_TTL_MS', 60 * 60 * 1000),
  refreshTokenTtlMs: int('REFRESH_TOKEN_TTL_MS', 30 * 24 * 60 * 60 * 1000),
  maxDevices: int('MAX_DEVICES', 10),

  // AI engine (reused, never duplicated)
  agentHome: path.resolve(env('MIKUHOST_AGENT_HOME', path.join(os.homedir(), 'mikuhost-agent'))),
  agentConfigFile: env('MIKUHOST_AGENT_CONFIG', null),
  workspaceRoot: path.resolve(env('LIFEFORM_WORKSPACE', os.homedir())),
  aiTimeoutMs: int('AI_TIMEOUT_MS', 180_000),
  // Per-model deadline: a provider that never answers falls through to the next.
  aiAttemptTimeoutMs: int('AI_ATTEMPT_TIMEOUT_MS', 60_000),
  aiMaxIterations: int('AI_MAX_ITERATIONS', 12),
  aiTemperature: Number(env('AI_TEMPERATURE', '0.6')),
  aiStreaming: bool('AI_STREAMING', true),

  // Monitoring
  monitorIntervalMs: int('MONITOR_INTERVAL_MS', 15_000),
  metricsRetentionDays: int('METRICS_RETENTION_DAYS', 7),
  // CPU is sampled by a single owner and served from cache; consumers never
  // read /proc/stat themselves, so no caller can steal another's delta window.
  cpuSampleIntervalMs: int('CPU_SAMPLE_INTERVAL_MS', 5000),
  cpuSampleStaleMs: int('CPU_SAMPLE_STALE_MS', 30_000),
  thresholdCpu: Number(env('THRESHOLD_CPU', '85')),
  thresholdMemory: Number(env('THRESHOLD_MEMORY', '90')),
  thresholdDisk: Number(env('THRESHOLD_DISK', '90')),
  // A breach must hold this long before an alert is created, and must drop
  // below (threshold - margin) before it is resolved (hysteresis, no flapping).
  alertSustainMs: int('ALERT_SUSTAIN_MS', 60_000),
  alertResolveMargin: Number(env('ALERT_RESOLVE_MARGIN', '5')),
  processLimit: int('PROCESS_LIMIT', 20),

  // VPS Remote Control (SSH/SFTP file manager + interactive terminal)
  remoteIdleTimeoutMs: int('REMOTE_IDLE_TIMEOUT_MS', 5 * 60 * 1000),
  remoteMaxEditBytes: int('REMOTE_MAX_EDIT_BYTES', 2 * 1024 * 1024),
  remoteMaxUploadBytes: int('REMOTE_MAX_UPLOAD_BYTES', 512 * 1024 * 1024),
  remoteMaxPreviewBytes: int('REMOTE_MAX_PREVIEW_BYTES', 20 * 1024 * 1024),
  remoteTerminalBufferBytes: int('REMOTE_TERMINAL_BUFFER_BYTES', 256 * 1024),
  remoteTerminalIdleMs: int('REMOTE_TERMINAL_IDLE_MS', 30 * 60 * 1000),
  remoteTerminalMaxSessions: int('REMOTE_TERMINAL_MAX_SESSIONS', 8),
  remoteSearchLimit: int('REMOTE_SEARCH_LIMIT', 200),
  // Optional CA bundle for private FTPS servers. TLS verification stays on.
  remoteFtpsCaFile: env('REMOTE_FTPS_CA_FILE', null),

  // Lifeform
  autonomyLevel: int('AUTONOMY_LEVEL', 1),
  reflectionIntervalMs: int('REFLECTION_INTERVAL_MS', 15 * 60 * 1000),
  awarenessIntervalMs: int('AWARENESS_INTERVAL_MS', 60 * 1000),
  approvalTtlMs: int('APPROVAL_TTL_MS', 15 * 60 * 1000),
  commandTimeoutMs: int('COMMAND_TIMEOUT_MS', 30_000),

  // Node identity
  nodeId: env('NODE_ID', 'primary'),
  nodeName: env('NODE_NAME', 'Primary Node'),
});

export function ensureDirs() {
  for (const dir of [config.dataDir, config.logDir]) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

/** Stable machine secret used to seal tokens written to disk. */
export function machineSecret() {
  const file = path.join(config.dataDir, '.machine-secret');
  if (!fs.existsSync(file)) {
    ensureDirs();
    fs.writeFileSync(file, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  }
  return fs.readFileSync(file, 'utf8').trim();
}

export function isLoopback(address) {
  if (!address) return false;
  const clean = String(address).replace(/^::ffff:/, '');
  return clean === '127.0.0.1' || clean === '::1' || clean === 'localhost';
}
