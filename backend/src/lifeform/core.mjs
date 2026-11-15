// Awareness, goal planning, reflection and the lifecycle scheduler.
// The LLM is only called on reflection/planning, never on every metrics tick.
import crypto from 'node:crypto';
import { config } from '../config.mjs';
import { query } from '../db.mjs';
import { logger } from '../logger.mjs';
import { emitEvent, getLifeformState, recordActivity, setLifeformState } from '../events.mjs';
import { latestMetrics } from '../monitor/collector.mjs';
import { summarize } from '../monitor/collector.mjs';
import { addMemory, defaultPlanSteps, getGoal, getIdentity, listGoals, relevantMemories, updateGoal } from './identity.mjs';
import * as ai from '../ai/engine.mjs';

let awarenessTimer = null;
let reflectionTimer = null;
let lastSummary = null;
let lastReflectionAt = 0;
let runningReflection = false;

const OBSERVATION_WINDOW = 40;

function snapshotSummary() {
  const snapshot = latestMetrics();
  if (!snapshot) return null;
  return summarize(snapshot);
}

/** Compare the new tick with the previous one and record only real changes. */
export function runAwareness() {
  const summary = snapshotSummary();
  if (!summary) return null;
  const previous = lastSummary;
  lastSummary = summary;

  const observations = [];
  if (previous) {
    // Only compare real numbers. Treating an unavailable sample as 0 produced
    // phantom "CPU naik 75%" observations after every restart.
    const cpuNow = summary.cpu?.usagePercent ?? null;
    const cpuBefore = previous.cpu?.usagePercent ?? null;
    if (cpuNow !== null && cpuBefore !== null) {
      const cpuDelta = cpuNow - cpuBefore;
      if (Math.abs(cpuDelta) >= 25) {
        observations.push(`CPU bergerak ${cpuDelta > 0 ? 'naik' : 'turun'} ${Math.abs(Math.round(cpuDelta))}% menjadi ${cpuNow}%`);
      }
    }
    const memDelta = (summary.memory.usedPercent ?? 0) - (previous.memory?.usedPercent ?? 0);
    if (memDelta >= 10) {
      observations.push(`RAM naik ${Math.round(memDelta)}% menjadi ${summary.memory.usedPercent}%`);
    }
    const diskDelta = (summary.disk.usagePercent ?? 0) - (previous.disk?.usagePercent ?? 0);
    if (diskDelta >= 3) {
      observations.push(`Disk bertambah ${Math.round(diskDelta)}% menjadi ${summary.disk.usagePercent}%`);
    }
    for (const service of summary.pm2?.processes ?? []) {
      const before = previous.pm2?.processes?.find((item) => item.name === service.name);
      if (before && before.status !== service.status) {
        observations.push(`Service ${service.name}: ${before.status} → ${service.status}`);
      }
    }
  }

  if (observations.length) {
    recordActivity({
      type: 'observation',
      title: observations[0],
      detail: observations.slice(1).join(' · ') || null,
      source: 'awareness',
      result: 'observed',
    });
    const state = getLifeformState();
    if (state.state === 'idle') {
      setLifeformState({ state: 'observing', currentTask: 'Memantau infrastruktur', lastActivity: observations[0] });
    }
  }
  emitEvent('lifeform.awareness', {
    capturedAt: summary.capturedAt,
    observations,
    cpu: summary.cpu.usagePercent,
    memory: summary.memory.usedPercent,
    disk: summary.disk.usagePercent,
  });
  return observations;
}

export function recentContext(limit = OBSERVATION_WINDOW) {
  return query
    .all('SELECT type, title, detail, source, result, created_at FROM activities ORDER BY created_at DESC LIMIT ?', limit)
    .map((row) => `- [${new Date(row.created_at).toISOString()}] ${row.type}/${row.source}: ${row.title}${row.detail ? ` — ${row.detail}` : ''}`)
    .join('\n');
}

/**
 * Reflection turns recent concrete events into a short lesson + memory. Skipped
 * when nothing happened since the last reflection, so idle servers cost nothing.
 */
export async function runReflection({ force = false } = {}) {
  if (runningReflection) return { skipped: true, reason: 'busy' };
  if (!force && Date.now() - lastReflectionAt < config.reflectionIntervalMs) {
    return { skipped: true, reason: 'interval' };
  }
  const latestActivity = query.get('SELECT created_at FROM activities ORDER BY created_at DESC LIMIT 1');
  if (!force && (!latestActivity || Number(latestActivity.created_at) < lastReflectionAt)) {
    return { skipped: true, reason: 'no-new-events' };
  }
  runningReflection = true;
  setLifeformState({ state: 'reflecting', currentTask: 'Mengevaluasi aktivitas terakhir' });
  try {
    const summary = snapshotSummary();
    const identity = getIdentity();
    const prompt = [
      'Lakukan refleksi singkat atas aktivitas server berikut.',
      'Balas HANYA JSON valid dengan bentuk:',
      '{"summary":"<= 2 kalimat","lesson":"<= 1 kalimat pelajaran konkret","memory":{"relevant":true|false,"category":"operational|lesson|server","content":"<= 240 karakter","importance":1-5}}',
      'Gunakan relevant=false jika tidak ada yang layak diingat jangka panjang.',
      '',
      'AKTIVITAS TERAKHIR:',
      recentContext(30) || '(tidak ada)',
      '',
      'KONDISI SEKARANG:',
      summary
        ? `CPU ${summary.cpu.usagePercent}% · RAM ${summary.memory.usedPercent}% · Disk ${summary.disk.usagePercent}% · PM2 ${(summary.pm2?.processes ?? [])
            .map((p) => `${p.name}=${p.status}`)
            .join(', ')}`
        : '(snapshot tidak tersedia)',
    ].join('\n');

    const result = await ai.chat({
      conversationId: 'internal:reflection',
      messages: [{ role: 'user', content: prompt }],
      identity,
      state: getLifeformState(),
      memories: relevantMemories(8),
      goals: listGoals({ status: 'active', limit: 5 }),
    });
    lastReflectionAt = Date.now();
    const parsed = extractJson(result.text);
    const summaryText = String(parsed?.summary ?? result.text ?? '').slice(0, 600).trim();
    if (summaryText) {
      setLifeformState({ lastReflection: summaryText, state: 'idle', currentTask: null });
      recordActivity({ type: 'reflection', title: 'Refleksi selesai', detail: summaryText, source: 'lifeform', result: 'ok' });
      emitEvent('lifeform.reflection', { summary: summaryText, lesson: parsed?.lesson ?? null });
    }
    if (parsed?.memory?.relevant && parsed.memory.content) {
      addMemory({
        category: parsed.memory.category ?? 'lesson',
        content: String(parsed.memory.content).slice(0, 240),
        source: 'reflection',
        importance: Number(parsed.memory.importance) || 3,
        confidence: 0.6,
      });
    }
    return { skipped: false, summary: summaryText, lesson: parsed?.lesson ?? null };
  } catch (error) {
    logger.warn('reflection failed', String(error?.message ?? error));
    setLifeformState({ state: 'idle', currentTask: null });
    return { skipped: true, reason: 'error', error: String(error?.message ?? error) };
  } finally {
    runningReflection = false;
  }
}

export function extractJson(text) {
  const raw = String(text ?? '').trim();
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = fenced ? fenced[1] : raw;
  const start = candidate.indexOf('{');
  const end = candidate.lastIndexOf('}');
  if (start === -1 || end <= start) return null;
  try {
    return JSON.parse(candidate.slice(start, end + 1));
  } catch {
    return null;
  }
}

/** Ask the model for concrete steps; fall back to a deterministic plan. */
export async function planGoal(goalId) {
  const goal = getGoal(goalId);
  if (!goal) {
    const error = new Error('Goal not found.');
    error.status = 404;
    throw error;
  }
  const identity = getIdentity();
  const prompt = [
    `Buat rencana langkah untuk tujuan: "${goal.title}".`,
    goal.description ? `Deskripsi: ${goal.description}` : '',
    'Balas HANYA JSON valid: {"steps":["langkah 1","langkah 2", ...]} maksimal 8 langkah, tiap langkah konkret dan bisa diverifikasi.',
    'Jangan sertakan langkah yang butuh akses destruktif tanpa menyebut perlunya persetujuan.',
  ]
    .filter(Boolean)
    .join('\n');
  let steps = defaultPlanSteps(goal.title);
  try {
    const result = await ai.chat({
      conversationId: 'internal:planner',
      messages: [{ role: 'user', content: prompt }],
      identity,
      state: getLifeformState(),
      memories: relevantMemories(6),
      goals: [goal],
    });
    const parsed = extractJson(result.text);
    if (Array.isArray(parsed?.steps) && parsed.steps.length) {
      steps = parsed.steps.slice(0, 8).map((step) => String(step).slice(0, 500));
    }
  } catch (error) {
    logger.warn('planner fallback', String(error?.message ?? error));
  }

  const now = Date.now();
  const existingTask = query.get('SELECT * FROM tasks WHERE goal_id = ? ORDER BY created_at LIMIT 1', goalId);
  const taskId = existingTask?.id ?? crypto.randomUUID();
  if (!existingTask) {
    query.run(
      'INSERT INTO tasks (id, goal_id, title, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
      taskId,
      goalId,
      goal.title.slice(0, 300),
      'pending',
      now,
      now,
    );
  }
  query.run('DELETE FROM task_steps WHERE task_id = ?', taskId);
  steps.forEach((step, index) => {
    query.run(
      'INSERT INTO task_steps (id, task_id, position, description, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      crypto.randomUUID(),
      taskId,
      index + 1,
      step,
      'pending',
      now,
      now,
    );
  });
  updateGoal(goalId, {});
  recordActivity({ type: 'planning', title: `Rencana dibuat untuk: ${goal.title}`, detail: `${steps.length} langkah`, source: 'ai', result: 'ok' });
  emitEvent('lifeform.goal.updated', getGoal(goalId));
  return getGoal(goalId);
}

export function startLifeform() {
  if (awarenessTimer) return;
  setLifeformState({ state: 'observing', currentTask: 'Memantau infrastruktur' });
  awarenessTimer = setInterval(() => {
    try {
      runAwareness();
    } catch (error) {
      logger.warn('awareness tick failed', String(error?.message ?? error));
    }
  }, config.awarenessIntervalMs);
  awarenessTimer.unref?.();

  reflectionTimer = setInterval(() => {
    runReflection().catch(() => {});
  }, Math.max(60_000, Math.floor(config.reflectionIntervalMs / 3)));
  reflectionTimer.unref?.();
  logger.info('lifeform core started');
}

export function stopLifeform() {
  if (awarenessTimer) clearInterval(awarenessTimer);
  if (reflectionTimer) clearInterval(reflectionTimer);
  awarenessTimer = null;
  reflectionTimer = null;
}

export function reflectionStatus() {
  return { lastReflectionAt, running: runningReflection, intervalMs: config.reflectionIntervalMs };
}
