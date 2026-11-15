// In-process event bus + persisted activity/alert/notification records.
import crypto from 'node:crypto';
import { query } from './db.mjs';
import { logger } from './logger.mjs';

const listeners = new Set();

export function subscribe(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function emitEvent(type, payload = {}) {
  const event = { id: crypto.randomUUID(), type, ts: Date.now(), payload };
  for (const listener of listeners) {
    try {
      listener(event);
    } catch (error) {
      logger.debug('event listener failed', String(error));
    }
  }
  return event;
}

export function recordActivity({ type, title, detail = null, source = 'system', risk = null, result = null }) {
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  query.run(
    'INSERT INTO activities (id, type, title, detail, source, risk, result, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    id,
    type,
    title,
    detail,
    source,
    risk,
    result,
    createdAt,
  );
  const activity = { id, type, title, detail, source, risk, result, createdAt };
  emitEvent('activity.created', activity);
  return activity;
}

function recordAlertEvent({ alert, status, fromStatus = null, value = null, threshold = null, message = null }) {
  query.run(
    `INSERT INTO alert_events (id, alert_id, node_id, kind, status, from_status, severity, value, threshold, message, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    crypto.randomUUID(),
    alert.id,
    alert.nodeId ?? null,
    alert.kind ?? null,
    status,
    fromStatus,
    alert.severity ?? null,
    value,
    threshold,
    message,
    Date.now(),
  );
}

/**
 * Create or update an alert. Deduplication is by (source, kind, node) — never
 * by the message text — so a metric that stays high keeps exactly one open
 * alert instead of one per measured value. Every status change is recorded in
 * alert_events.
 */
export function createAlert({
  severity = 'warning',
  title,
  detail = null,
  source = 'monitor',
  nodeId = null,
  kind = null,
  metric = null,
  value = null,
  threshold = null,
  peakValue = null,
}) {
  const dedupeKey = kind ?? title;
  const existing = nodeId
    ? query.get(
        "SELECT * FROM alerts WHERE status = 'open' AND source = ? AND node_id = ? AND COALESCE(kind, title) = ? ORDER BY created_at DESC LIMIT 1",
        source,
        nodeId,
        dedupeKey,
      )
    : query.get(
        "SELECT * FROM alerts WHERE status = 'open' AND source = ? AND node_id IS NULL AND COALESCE(kind, title) = ? ORDER BY created_at DESC LIMIT 1",
        source,
        dedupeKey,
      );

  const now = Date.now();
  if (existing) {
    const peak = Math.max(existing.peak_value ?? existing.metric_value ?? 0, value ?? 0, peakValue ?? 0);
    const escalated = severity === 'critical' && existing.severity !== 'critical';
    query.run(
      'UPDATE alerts SET detail = ?, severity = ?, metric_value = ?, threshold = ?, peak_value = ?, updated_at = ? WHERE id = ?',
      detail,
      escalated ? 'critical' : existing.severity,
      value ?? existing.metric_value ?? null,
      threshold ?? existing.threshold ?? null,
      peak || null,
      now,
      existing.id,
    );
    const mapped = mapAlert(query.get('SELECT * FROM alerts WHERE id = ?', existing.id));
    // Only record an update when it carries new information: severity change
    // or the metric moved at least 5 points. Otherwise the history floods.
    const previousValue = existing.metric_value ?? null;
    const moved = value !== null && (previousValue === null || Math.abs(value - previousValue) >= 5);
    if (escalated || moved) {
      recordAlertEvent({
        alert: mapped,
        status: escalated ? 'escalated' : 'updated',
        fromStatus: existing.status,
        value: value ?? null,
        threshold: threshold ?? null,
        message: detail,
      });
      emitEvent('alert.updated', mapped);
    }
    return mapped;
  }

  const id = crypto.randomUUID();
  query.run(
    `INSERT INTO alerts (id, node_id, severity, title, detail, source, status, kind, metric_value, threshold, peak_value, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    id,
    nodeId,
    severity,
    title,
    detail,
    source,
    'open',
    kind,
    value,
    threshold,
    peakValue ?? value,
    now,
    now,
  );
  const alert = {
    id,
    nodeId,
    severity,
    title,
    detail,
    source,
    status: 'open',
    kind,
    metric,
    value,
    threshold,
    createdAt: now,
    updatedAt: now,
    resolvedAt: null,
  };
  emitEvent('alert.created', alert);
  recordActivity({ type: 'alert', title, detail, source, risk: severity, result: 'open' });
  recordAlertEvent({ alert, status: 'open', value, threshold, message: detail });
  notify({ title, body: detail ?? title, level: severity });
  return alert;
}

export function resolveAlert(id, { by = 'owner', value = null, message = null } = {}) {
  const alert = query.get('SELECT * FROM alerts WHERE id = ?', id);
  if (!alert) return null;
  if (alert.status === 'resolved') return mapAlert(alert);
  const resolvedAt = Date.now();
  query.run(
    "UPDATE alerts SET status = 'resolved', resolved_at = ?, updated_at = ?, metric_value = COALESCE(?, metric_value) WHERE id = ?",
    resolvedAt,
    resolvedAt,
    value,
    id,
  );
  const mapped = { ...mapAlert(query.get('SELECT * FROM alerts WHERE id = ?', id)), status: 'resolved', resolvedAt };
  emitEvent('alert.updated', mapped);
  recordActivity({ type: 'alert', title: `Alert resolved: ${alert.title}`, detail: message, source: by, result: 'resolved' });
  recordAlertEvent({ alert: mapped, status: 'resolved', fromStatus: alert.status, value, message });
  return mapped;
}

/** Resolve every open alert of one kind (used when the metric is healthy again). */
export function resolveAlertsByKind({ kind, source = 'monitor', nodeId = null, value = null, by = 'monitor', message = null }) {
  const rows = query.all(
    `SELECT id FROM alerts WHERE status = 'open' AND source = ? AND COALESCE(kind, '') = ? AND (? IS NULL OR node_id = ?)`,
    source,
    kind,
    nodeId,
    nodeId,
  );
  return rows.map((row) => resolveAlert(row.id, { by, value, message })).filter(Boolean);
}

export function mapAlert(row) {
  return {
    id: row.id,
    nodeId: row.node_id,
    severity: row.severity,
    title: row.title,
    detail: row.detail,
    source: row.source,
    status: row.status,
    kind: row.kind ?? null,
    value: row.metric_value ?? null,
    threshold: row.threshold ?? null,
    peakValue: row.peak_value ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at ?? null,
    resolvedAt: row.resolved_at,
  };
}

export function notify({ title, body = null, level = 'info' }) {
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  query.run(
    'INSERT INTO notifications (id, title, body, level, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    id,
    title,
    body,
    level,
    'unread',
    createdAt,
  );
  const notification = { id, title, body, level, status: 'unread', createdAt };
  emitEvent('notification.created', notification);
  return notification;
}

export function setLifeformState(patch) {
  const current = query.get('SELECT * FROM lifeform_state WHERE id = 1');
  const now = Date.now();
  const next = {
    state: patch.state ?? current?.state ?? 'idle',
    currentTask: patch.currentTask ?? current?.current_task ?? null,
    activeGoal: patch.activeGoal ?? current?.active_goal ?? null,
    lastActivity: patch.lastActivity ?? current?.last_activity ?? null,
    lastReflection: patch.lastReflection ?? current?.last_reflection ?? null,
    since: patch.state && patch.state !== current?.state ? now : current?.since ?? now,
  };
  query.run(
    `INSERT INTO lifeform_state (id, state, current_task, active_goal, last_activity, last_reflection, since, updated_at)
     VALUES (1, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET state = excluded.state, current_task = excluded.current_task,
       active_goal = excluded.active_goal, last_activity = excluded.last_activity,
       last_reflection = excluded.last_reflection, since = excluded.since, updated_at = excluded.updated_at`,
    next.state,
    next.currentTask,
    next.activeGoal,
    next.lastActivity,
    next.lastReflection,
    next.since,
    now,
  );
  const state = { ...next, updatedAt: now };
  emitEvent('lifeform.state', state);
  return state;
}

export function getLifeformState() {
  const row = query.get('SELECT * FROM lifeform_state WHERE id = 1');
  if (!row) {
    return {
      state: 'idle',
      currentTask: null,
      activeGoal: null,
      lastActivity: null,
      lastReflection: null,
      since: Date.now(),
      updatedAt: Date.now(),
    };
  }
  return {
    state: row.state,
    currentTask: row.current_task,
    activeGoal: row.active_goal,
    lastActivity: row.last_activity,
    lastReflection: row.last_reflection,
    since: row.since,
    updatedAt: row.updated_at,
  };
}
