// Shell executor with approval, timeout, output capture and an audit trail.
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { config } from '../config.mjs';
import { query } from '../db.mjs';
import { emitEvent, recordActivity } from '../events.mjs';
import { audit } from '../auth.mjs';
import { classifyCommand, requestPermission } from './policy.mjs';

const running = new Map();

export function runningCommands() {
  return Array.from(running.values()).map(({ id, command, startedAt }) => ({ id, command, startedAt }));
}

function killTree(pid) {
  try {
    process.kill(-pid, 'SIGTERM');
  } catch {
    try {
      process.kill(pid, 'SIGTERM');
    } catch {
      /* already gone */
    }
  }
}

/**
 * Execute a command. Non read-only commands pass through the approval queue
 * first, so Level 1 never executes and risky commands block until answered.
 */
export async function executeCommand({ command, timeoutMs = config.commandTimeoutMs, actor = 'owner', deviceId = null }) {
  const text = String(command ?? '').trim();
  if (!text) {
    const error = new Error('Command kosong.');
    error.status = 400;
    throw error;
  }
  if (text.length > 4000) {
    const error = new Error('Command terlalu panjang (maks 4000 karakter).');
    error.status = 400;
    throw error;
  }
  const classified = classifyCommand(text);
  const permission = await requestPermission({
    action: `terminal: ${text.slice(0, 120)}`,
    command: text,
    target: 'shell',
  });

  const id = crypto.randomUUID();
  const startedAt = Date.now();
  query.run(
    'INSERT INTO terminal_tasks (id, command, status, started_at, created_by) VALUES (?, ?, ?, ?, ?)',
    id,
    text.slice(0, 4000),
    permission.approved ? 'running' : 'blocked',
    startedAt,
    actor,
  );

  if (!permission.approved) {
    const reason = permission.reason ?? `Tindakan tidak diizinkan (${permission.mode}${permission.status ? ` · ${permission.status}` : ''}).`;
    query.run('UPDATE terminal_tasks SET status = ?, finished_at = ?, output = ? WHERE id = ?', 'blocked', Date.now(), reason, id);
    recordActivity({ type: 'security', title: 'Perintah diblokir', detail: reason, source: actor, risk: classified.risk, result: 'blocked' });
    audit(actor, 'terminal.blocked', id, { command: text.slice(0, 200), risk: classified.risk }, 'denied');
    return { id, status: 'blocked', exitCode: null, output: '', error: reason, risk: classified.risk };
  }

  // `-c` (not `-lc`): a login shell would source profile scripts and pollute
  // the captured output with banners and escape sequences.
  const child = spawn('bash', ['-c', text], {
    cwd: config.workspaceRoot,
    env: sanitizedEnv(),
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  running.set(id, { id, command: text, startedAt, child });

  let output = '';
  const limit = 200_000;
  const push = (chunk, stream) => {
    const textChunk = chunk.toString('utf8');
    if (output.length < limit) output += textChunk.slice(0, limit - output.length);
    emitEvent('terminal.output', { taskId: id, stream, chunk: textChunk.slice(0, 8000) });
  };
  child.stdout?.on('data', (chunk) => push(chunk, 'stdout'));
  child.stderr?.on('data', (chunk) => push(chunk, 'stderr'));

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    if (child.pid) killTree(child.pid);
  }, Math.min(Math.max(1000, timeoutMs), 600_000));

  const exitCode = await new Promise((resolve) => {
    child.on('close', (code) => resolve(code ?? 0));
    child.on('error', (error) => {
      push(String(error.message), 'stderr');
      resolve(127);
    });
  });
  clearTimeout(timer);
  running.delete(id);

  const status = timedOut ? 'timeout' : exitCode === 0 ? 'completed' : 'failed';
  const finishedAt = Date.now();
  query.run(
    'UPDATE terminal_tasks SET status = ?, exit_code = ?, output = ?, finished_at = ? WHERE id = ?',
    status,
    exitCode,
    output.slice(0, limit),
    finishedAt,
    id,
  );
  emitEvent('terminal.completed', { taskId: id, status, exitCode, durationMs: finishedAt - startedAt });
  recordActivity({
    type: 'terminal',
    title: `Perintah ${status}: ${text.slice(0, 80)}`,
    detail: timedOut ? `Timeout setelah ${timeoutMs} ms` : `Exit code ${exitCode}`,
    source: actor,
    risk: classified.risk,
    result: status,
  });
  audit(actor, 'terminal.execute', id, { command: text.slice(0, 400), exitCode, status, deviceId });

  return {
    id,
    status,
    exitCode,
    output: output.slice(0, limit),
    durationMs: finishedAt - startedAt,
    risk: classified.risk,
    permission: permission.mode,
  };
}

function sanitizedEnv() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^MIKUHOST_.*(KEY|SECRET|TOKEN)$/i.test(key)) delete env[key];
    if (/^(NVIDIA|TOKENHARBOR|OPENAI)_API_KEY$/i.test(key)) delete env[key];
    if (key === 'MIKUHOST_ENCRYPTION_KEY') delete env[key];
  }
  return env;
}

export function terminalTask(id) {
  return query.get('SELECT * FROM terminal_tasks WHERE id = ?', id) ?? null;
}

export function cancelTask(id) {
  const entry = running.get(id);
  if (!entry) return false;
  if (entry.child?.pid) killTree(entry.child.pid);
  return true;
}
