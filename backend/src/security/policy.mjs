// Autonomy levels, risk classification and the approval queue.
import crypto from 'node:crypto';
import { config } from '../config.mjs';
import { query } from '../db.mjs';
import { logger } from '../logger.mjs';
import { emitEvent, notify, recordActivity } from '../events.mjs';
import { audit } from '../auth.mjs';

export const AUTONOMY = Object.freeze({
  1: { level: 1, name: 'observe', label: 'Observe', description: 'Read-only: metrics, logs, services, analysis. No mutations.' },
  2: { level: 2, name: 'operate', label: 'Operate', description: 'Routine approved actions: restart known services, health checks, diagnostics.' },
  3: { level: 3, name: 'autonomous', label: 'Full Root Autonomy', description: 'Owner-authorized full autonomy for operations within executor capability; no per-action approval prompt.' },
});

export function autonomyLevel() {
  const row = query.get("SELECT value FROM settings WHERE key = 'autonomy_level'");
  const level = Number(row?.value ?? config.autonomyLevel);
  return AUTONOMY[level] ? level : 1;
}

export function setAutonomyLevel(level) {
  const numeric = Number(level);
  if (!AUTONOMY[numeric]) {
    const error = new Error('Autonomy level must be 1, 2 or 3.');
    error.status = 400;
    error.code = 'INVALID_AUTONOMY';
    throw error;
  }
  query.run(
    `INSERT INTO settings (key, value, updated_at) VALUES ('autonomy_level', ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    String(numeric),
    Date.now(),
  );
  audit('owner', 'autonomy.changed', String(numeric), {});
  return AUTONOMY[numeric];
}

const DESTRUCTIVE_PATTERNS = [
  { re: /\brm\s+(-[a-z]*[rf][a-z]*\s+)+(\/|\/\*|~|\$HOME)(?=$|[\s;&|])/i, risk: 'critical', reason: 'Menghapus direktori sistem/home' },
  { re: /\bmkfs(\.\w+)?\b/i, risk: 'critical', reason: 'Memformat filesystem' },
  { re: /\bdd\b.*\bof=\/dev\//i, risk: 'critical', reason: 'Menulis langsung ke device' },
  { re: /\b(shutdown|reboot|halt|poweroff)\b/i, risk: 'critical', reason: 'Mematikan server' },
  { re: /\b(iptables|nft|ufw)\b/i, risk: 'high', reason: 'Mengubah firewall' },
  { re: /\bsshd?_config|ssh_config|authorized_keys\b/i, risk: 'critical', reason: 'Mengubah konfigurasi SSH' },
  { re: /\b(DROP|TRUNCATE)\s+(TABLE|DATABASE)\b/i, risk: 'critical', reason: 'Menghapus data database' },
  { re: /\b(passwd|chpasswd|usermod|visudo|sudoers)\b/i, risk: 'critical', reason: 'Mengubah kredensial/akses' },
  { re: /\bpm2\s+(delete|kill)\b/i, risk: 'high', reason: 'Menghapus proses PM2' },
  { re: /\b(docker\s+(rm|rmi|system\s+prune)|kubectl\s+delete)\b/i, risk: 'high', reason: 'Menghapus container/image' },
  { re: /\bchmod\s+-R\s+777\b/i, risk: 'high', reason: 'Membuka permission secara global' },
  { re: /\bnginx\b.*\b(stop|reload|restart)\b/i, risk: 'high', reason: 'Menyentuh reverse proxy production' },
  { re: /\bmysql|psql\b.*\b(-e|--execute)\b/i, risk: 'medium', reason: 'Menjalankan query database' },
];

const ROUTINE_SERVICE = /^(mikuhost-|miku$|botpanel$|ryuzen$|zahra$)/i;

export function classifyCommand(command) {
  const text = String(command ?? '').trim();
  if (!text) return { risk: 'low', reason: 'Perintah kosong', requiresApproval: false };
  for (const rule of DESTRUCTIVE_PATTERNS) {
    if (rule.re.test(text)) {
      return { risk: rule.risk, reason: rule.reason, requiresApproval: true };
    }
  }
  if (/^[a-z0-9_./-]+(\s|$)/i.test(text) && /^(cat|ls|df|du|free|uptime|ps|ss|top|tail|head|grep|systemctl\s+status|pm2\s+(list|jlist|describe|logs)|docker\s+ps|journalctl)/i.test(text)) {
    return { risk: 'low', reason: 'Perintah baca-saja', requiresApproval: false };
  }
  return { risk: 'medium', reason: 'Perintah mengubah state atau belum dikenali', requiresApproval: true };
}

/**
 * Decide whether an action may run now.
 * - Level 1: read-only, no mutations.
 * - Level 2: routine service actions allowed; other mutating actions require explicit approval.
 * - Level 3: owner-authorized full autonomy for operations within executor capability
 *   (no per-action approval prompt). Authentication, authorization, audit logging,
 *   and emergency controls remain enforced outside this decision.
 */
export function authorize({ action, command = null, target = null, risk = null, routine = false }) {
  const level = autonomyLevel();
  const classified = risk ? { risk, requiresApproval: risk !== 'low', reason: 'Diklasifikasikan oleh tool' } : classifyCommand(command ?? action);

  // Read-only / low-risk observations are always allowed.
  if (classified.risk === 'low' && !classified.requiresApproval) {
    return { allowed: true, approvalRequired: false, classification: classified };
  }

  if (level === 1) {
    return { allowed: false, approvalRequired: false, classification: classified, reason: 'Autonomy Level 1 (Observe) tidak mengizinkan tindakan yang mengubah sistem.' };
  }

  if (level >= 3) {
    // Full root autonomy: execute authorized operations without per-action approval.
    return { allowed: true, approvalRequired: false, classification: { ...classified, autonomy: 'full' } };
  }

  // Level 2
  if (routine && ROUTINE_SERVICE.test(String(target ?? ''))) {
    return { allowed: true, approvalRequired: false, classification: classified };
  }
  return { allowed: false, approvalRequired: true, classification: classified };
}

const pending = new Map();

export function createApproval({ action, reason, risk, command = null, target = null, ttlMs = config.approvalTtlMs }) {
  const id = crypto.randomUUID();
  const now = Date.now();
  query.run(
    'INSERT INTO approvals (id, action, reason, risk, command, target, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    id,
    action,
    reason,
    risk,
    command,
    target,
    'pending',
    now,
    now + ttlMs,
  );
  const approval = { id, action, reason, risk, command, target, status: 'pending', createdAt: now, expiresAt: now + ttlMs };
  emitEvent('approval.created', approval);
  notify({ title: 'Approval diperlukan', body: `${action}${target ? ` · ${target}` : ''} (${risk})`, level: 'warning' });
  recordActivity({ type: 'approval', title: `Approval diminta: ${action}`, detail: command ?? reason, source: 'ai', risk, result: 'pending' });
  return approval;
}

export function waitForApproval(approvalId) {
  return new Promise((resolve) => {
    const row = query.get('SELECT * FROM approvals WHERE id = ?', approvalId);
    if (!row) return resolve({ approved: false, status: 'missing' });
    if (row.status !== 'pending') return resolve({ approved: row.status === 'approved', status: row.status });
    const timeout = setTimeout(() => {
      pending.delete(approvalId);
      query.run("UPDATE approvals SET status = 'expired', resolved_at = ? WHERE id = ? AND status = 'pending'", Date.now(), approvalId);
      emitEvent('approval.resolved', { id: approvalId, status: 'expired' });
      resolve({ approved: false, status: 'expired' });
    }, Math.max(1000, Number(row.expires_at) - Date.now()));
    timeout.unref?.();
    pending.set(approvalId, (decision) => {
      clearTimeout(timeout);
      resolve(decision);
    });
  });
}

export function decideApproval(id, decision, { by = 'owner' } = {}) {
  const row = query.get('SELECT * FROM approvals WHERE id = ?', id);
  if (!row) {
    const error = new Error('Approval not found.');
    error.status = 404;
    throw error;
  }
  if (row.status !== 'pending') {
    const error = new Error(`Approval already ${row.status}.`);
    error.status = 409;
    error.code = 'APPROVAL_NOT_PENDING';
    throw error;
  }
  const status = decision === 'approve' ? 'approved' : 'rejected';
  const resolvedAt = Date.now();
  query.run('UPDATE approvals SET status = ?, resolved_at = ?, resolved_by = ? WHERE id = ?', status, resolvedAt, by, id);
  emitEvent('approval.resolved', { id, status, resolvedAt });
  recordActivity({
    type: 'approval',
    title: `Approval ${status === 'approved' ? 'disetujui' : 'ditolak'}: ${row.action}`,
    detail: row.command ?? row.reason,
    source: by,
    risk: row.risk,
    result: status,
  });
  audit(by, `approval.${status}`, id, { action: row.action, risk: row.risk });
  const resolver = pending.get(id);
  if (resolver) {
    pending.delete(id);
    resolver({ approved: status === 'approved', status });
  }
  return { ...row, status, resolvedAt };
}

export function listApprovals({ status = null, limit = 50 } = {}) {
  const rows = status
    ? query.all('SELECT * FROM approvals WHERE status = ? ORDER BY created_at DESC LIMIT ?', status, limit)
    : query.all('SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?', limit);
  return rows.map(mapApproval);
}

export function mapApproval(row) {
  return {
    id: row.id,
    action: row.action,
    reason: row.reason,
    risk: row.risk,
    command: row.command,
    target: row.target,
    status: row.status,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    resolvedAt: row.resolved_at,
    resolvedBy: row.resolved_by,
  };
}

/**
 * Gate used by AI tools: returns true when the action may proceed. Risky
 * actions suspend the turn until the owner answers in the app.
 */
export async function requestPermission({ action, reason = null, command = null, target = null, routine = false }) {
  const verdict = authorize({ action, command, target, routine });
  if (verdict.allowed) return { approved: true, mode: 'auto' };
  if (!verdict.approvalRequired) {
    recordActivity({ type: 'security', title: `Tindakan diblokir: ${action}`, detail: verdict.reason, source: 'policy', risk: verdict.classification.risk, result: 'blocked' });
    return { approved: false, mode: 'blocked', reason: verdict.reason };
  }
  const approval = createApproval({
    action,
    reason: reason ?? verdict.classification.reason,
    risk: verdict.classification.risk,
    command,
    target,
  });
  const decision = await waitForApproval(approval.id);
  return { approved: decision.approved, mode: 'approval', approvalId: approval.id, status: decision.status };
}

export function expireApprovals() {
  const now = Date.now();
  const expired = query.all("SELECT id FROM approvals WHERE status = 'pending' AND expires_at < ?", now);
  for (const row of expired) {
    query.run("UPDATE approvals SET status = 'expired', resolved_at = ? WHERE id = ?", now, row.id);
    emitEvent('approval.resolved', { id: row.id, status: 'expired' });
    logger.info(`approval expired: ${row.id}`);
  }
  return expired.length;
}
