// Lifeform identity, state, goals, memory and reflection.
import crypto from 'node:crypto';
import { query, parseJson, transaction } from '../db.mjs';
import { emitEvent, getLifeformState, recordActivity, setLifeformState } from '../events.mjs';
import { audit } from '../auth.mjs';

export const DEFAULT_IDENTITY = Object.freeze({
  name: 'Miku',
  personality:
    'Tenang, teliti, dan jujur. Menyampaikan temuan apa adanya, tidak melebih-lebihkan kemampuan, dan memprioritaskan stabilitas server di atas kecepatan.',
  language: 'id',
  style: 'Ringkas dan terstruktur. Angka dulu, lalu analisis singkat, lalu rekomendasi tindakan.',
  purpose:
    'Menjaga VPS tetap sehat, mengenali masalah lebih awal, dan membantu pemilik menjalankan pekerjaan operasional dengan aman.',
  constraints:
    'Tidak menjalankan tindakan destruktif tanpa persetujuan. Tidak menampilkan kredensial. Tidak mengarang data. Tidak melewati permission system.',
  preferences: 'Laporkan hanya hal penting. Hindari notifikasi berulang untuk masalah yang sama.',
});

export function ensureIdentity() {
  const row = query.get('SELECT * FROM lifeform_identity WHERE id = 1');
  if (row) return mapIdentity(row);
  const now = Date.now();
  query.run(
    `INSERT INTO lifeform_identity (id, name, personality, language, style, purpose, constraints, preferences, updated_at)
     VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)`,
    DEFAULT_IDENTITY.name,
    DEFAULT_IDENTITY.personality,
    DEFAULT_IDENTITY.language,
    DEFAULT_IDENTITY.style,
    DEFAULT_IDENTITY.purpose,
    DEFAULT_IDENTITY.constraints,
    DEFAULT_IDENTITY.preferences,
    now,
  );
  return mapIdentity(query.get('SELECT * FROM lifeform_identity WHERE id = 1'));
}

export function mapIdentity(row) {
  return {
    name: row.name,
    personality: row.personality,
    language: row.language,
    style: row.style,
    purpose: row.purpose,
    constraints: row.constraints,
    preferences: row.preferences,
    updatedAt: row.updated_at,
  };
}

export function getIdentity() {
  return ensureIdentity();
}

export function updateIdentity(patch) {
  const current = ensureIdentity();
  const fields = ['name', 'personality', 'language', 'style', 'purpose', 'constraints', 'preferences'];
  const next = { ...current };
  for (const field of fields) {
    if (patch[field] === undefined) continue;
    if (typeof patch[field] !== 'string' || !patch[field].trim()) {
      const error = new Error(`Field "${field}" harus berupa teks yang tidak kosong.`);
      error.status = 400;
      throw error;
    }
    next[field] = patch[field].slice(0, 4000);
  }
  query.run(
    `UPDATE lifeform_identity SET name = ?, personality = ?, language = ?, style = ?, purpose = ?, constraints = ?, preferences = ?, updated_at = ? WHERE id = 1`,
    next.name,
    next.personality,
    next.language,
    next.style,
    next.purpose,
    next.constraints,
    next.preferences,
    Date.now(),
  );
  audit('owner', 'lifeform.identity.updated', null, { fields: Object.keys(patch) });
  recordActivity({ type: 'lifeform', title: 'Identitas lifeform diperbarui', source: 'owner', result: 'ok' });
  return getIdentity();
}

// ---------------------------------------------------------------- memories

const MEMORY_CATEGORIES = [
  'short-term',
  'long-term',
  'user-preference',
  'project',
  'server',
  'operational',
  'goal',
  'lesson',
];

export function addMemory({ category = 'long-term', content, source = 'ai', importance = 3, tags = [], confidence = 0.7, expiresAt = null }) {
  const cleanCategory = MEMORY_CATEGORIES.includes(category) ? category : 'long-term';
  const text = String(content ?? '').trim();
  if (!text) {
    const error = new Error('Memory content tidak boleh kosong.');
    error.status = 400;
    throw error;
  }
  const id = crypto.randomUUID();
  const now = Date.now();
  query.run(
    `INSERT INTO memories (id, category, content, source, importance, tags, confidence, expires_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    id,
    cleanCategory,
    text.slice(0, 8000),
    source,
    Math.min(5, Math.max(1, Number(importance) || 3)),
    JSON.stringify(Array.isArray(tags) ? tags.slice(0, 12).map(String) : []),
    Math.min(1, Math.max(0, Number(confidence) || 0.7)),
    expiresAt,
    now,
    now,
  );
  const memory = getMemory(id);
  emitEvent('memory.created', memory);
  return memory;
}

export function mapMemory(row) {
  return {
    id: row.id,
    category: row.category,
    content: row.content,
    source: row.source,
    importance: row.importance,
    tags: parseJson(row.tags, []),
    confidence: row.confidence,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function getMemory(id) {
  const row = query.get('SELECT * FROM memories WHERE id = ?', id);
  return row ? mapMemory(row) : null;
}

export function listMemories({ category = null, search = null, limit = 50 } = {}) {
  const clauses = [];
  const params = [];
  if (category) {
    clauses.push('category = ?');
    params.push(category);
  }
  if (search) {
    clauses.push('(content LIKE ? OR tags LIKE ?)');
    params.push(`%${search}%`, `%${search}%`);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = query.all(
    `SELECT * FROM memories ${where} ORDER BY importance DESC, created_at DESC LIMIT ?`,
    ...params,
    limit,
  );
  return rows.map(mapMemory);
}

/** Top memories for the system prompt, newest and most important first. */
export function relevantMemories(limit = 12) {
  const rows = query.all(
    `SELECT * FROM memories WHERE (expires_at IS NULL OR expires_at > ?) ORDER BY importance DESC, updated_at DESC LIMIT ?`,
    Date.now(),
    limit,
  );
  return rows.map(mapMemory);
}

export function updateMemory(id, patch) {
  const current = getMemory(id);
  if (!current) {
    const error = new Error('Memory not found.');
    error.status = 404;
    throw error;
  }
  const content = patch.content !== undefined ? String(patch.content).trim() : current.content;
  if (!content) {
    const error = new Error('Memory content tidak boleh kosong.');
    error.status = 400;
    throw error;
  }
  const category = MEMORY_CATEGORIES.includes(patch.category) ? patch.category : current.category;
  const importance = patch.importance !== undefined ? Math.min(5, Math.max(1, Number(patch.importance) || 3)) : current.importance;
  const tags = Array.isArray(patch.tags) ? JSON.stringify(patch.tags.slice(0, 12).map(String)) : JSON.stringify(current.tags);
  query.run(
    'UPDATE memories SET category = ?, content = ?, importance = ?, tags = ?, updated_at = ? WHERE id = ?',
    category,
    content.slice(0, 8000),
    importance,
    tags,
    Date.now(),
    id,
  );
  return getMemory(id);
}

export function deleteMemory(id) {
  const result = query.run('DELETE FROM memories WHERE id = ?', id);
  return Number(result.changes ?? 0) > 0;
}

// ------------------------------------------------------------------- goals

export function mapGoal(row) {
  const steps = query.all('SELECT * FROM task_steps WHERE task_id IN (SELECT id FROM tasks WHERE goal_id = ?) ORDER BY position', row.id);
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    status: row.status,
    progress: row.progress,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    completedAt: row.completed_at,
    tasks: query
      .all('SELECT * FROM tasks WHERE goal_id = ? ORDER BY created_at', row.id)
      .map((task) => ({
        id: task.id,
        title: task.title,
        status: task.status,
        createdAt: task.created_at,
        updatedAt: task.updated_at,
        steps: steps
          .filter((step) => step.task_id === task.id)
          .map((step) => ({
            id: step.id,
            position: step.position,
            description: step.description,
            status: step.status,
            result: step.result,
          })),
      })),
  };
}

export function listGoals({ status = null, limit = 50 } = {}) {
  const rows = status
    ? query.all('SELECT * FROM goals WHERE status = ? ORDER BY created_at DESC LIMIT ?', status, limit)
    : query.all('SELECT * FROM goals ORDER BY created_at DESC LIMIT ?', limit);
  return rows.map(mapGoal);
}

export function getGoal(id) {
  const row = query.get('SELECT * FROM goals WHERE id = ?', id);
  return row ? mapGoal(row) : null;
}

export function createGoal({ title, description = null, steps = [] }) {
  const clean = String(title ?? '').trim();
  if (!clean) {
    const error = new Error('Judul goal wajib diisi.');
    error.status = 400;
    throw error;
  }
  const id = crypto.randomUUID();
  const now = Date.now();
  transaction(() => {
    query.run(
      'INSERT INTO goals (id, title, description, status, progress, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      id,
      clean.slice(0, 300),
      description ? String(description).slice(0, 4000) : null,
      'active',
      0,
      now,
      now,
    );
    if (Array.isArray(steps) && steps.length) {
      const taskId = crypto.randomUUID();
      query.run(
        'INSERT INTO tasks (id, goal_id, title, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
        taskId,
        id,
        clean.slice(0, 300),
        'pending',
        now,
        now,
      );
      steps.slice(0, 40).forEach((step, index) => {
        query.run(
          'INSERT INTO task_steps (id, task_id, position, description, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
          crypto.randomUUID(),
          taskId,
          index + 1,
          String(step).slice(0, 1000),
          'pending',
          now,
          now,
        );
      });
    }
  });
  const goal = getGoal(id);
  emitEvent('lifeform.goal.updated', goal);
  recordActivity({ type: 'goal', title: `Tujuan dibuat: ${clean}`, source: 'owner', result: 'ok' });
  audit('owner', 'goal.created', id, { title: clean });
  return goal;
}

export function updateGoal(id, patch) {
  const goal = getGoal(id);
  if (!goal) {
    const error = new Error('Goal not found.');
    error.status = 404;
    throw error;
  }
  const status = ['active', 'paused', 'completed', 'cancelled'].includes(patch.status) ? patch.status : goal.status;
  const progress = patch.progress !== undefined ? Math.min(100, Math.max(0, Number(patch.progress) || 0)) : goal.progress;
  const now = Date.now();
  query.run(
    'UPDATE goals SET title = ?, description = ?, status = ?, progress = ?, updated_at = ?, completed_at = ? WHERE id = ?',
    patch.title ? String(patch.title).slice(0, 300) : goal.title,
    patch.description !== undefined ? (patch.description ? String(patch.description).slice(0, 4000) : null) : goal.description,
    status,
    progress,
    now,
    status === 'completed' ? goal.completedAt ?? now : goal.completedAt,
    id,
  );
  const updated = getGoal(id);
  emitEvent('lifeform.goal.updated', updated);
  return updated;
}

export function deleteGoal(id) {
  const result = query.run('DELETE FROM goals WHERE id = ?', id);
  return Number(result.changes ?? 0) > 0;
}

export function updateStep(stepId, { status, result = null }) {
  const valid = ['pending', 'running', 'done', 'failed', 'skipped'];
  if (!valid.includes(status)) {
    const error = new Error('Status step tidak valid.');
    error.status = 400;
    throw error;
  }
  query.run('UPDATE task_steps SET status = ?, result = ?, updated_at = ? WHERE id = ?', status, result, Date.now(), stepId);
  const step = query.get('SELECT * FROM task_steps WHERE id = ?', stepId);
  if (step) {
    const task = query.get('SELECT * FROM tasks WHERE id = ?', step.task_id);
    if (task) {
      const all = query.all('SELECT status FROM task_steps WHERE task_id = ?', task.id);
      const done = all.filter((row) => row.status === 'done').length;
      const progress = all.length ? Math.round((done / all.length) * 100) : 0;
      if (task.goal_id) query.run('UPDATE goals SET progress = ?, updated_at = ? WHERE id = ?', progress, Date.now(), task.goal_id);
    }
  }
  return step;
}

/** Deterministic step plan, used when the AI planner is unavailable. */
export function defaultPlanSteps(title) {
  return [
    `Kumpulkan data terkait "${title}"`,
    'Analisis penyebab dan dampak',
    'Tentukan tindakan yang diizinkan',
    'Jalankan tindakan (atau minta approval)',
    'Verifikasi hasil',
    'Simpan ringkasan dan pelajaran',
  ];
}

export function lifeformOverview() {
  const identity = getIdentity();
  const state = getLifeformState();
  const goals = listGoals({ status: 'active', limit: 10 });
  const recent = query.all('SELECT * FROM activities ORDER BY created_at DESC LIMIT 10').map((row) => ({
    id: row.id,
    type: row.type,
    title: row.title,
    source: row.source,
    result: row.result,
    risk: row.risk,
    createdAt: row.created_at,
  }));
  return { identity, state, goals, recentActivity: recent };
}

export { setLifeformState };
