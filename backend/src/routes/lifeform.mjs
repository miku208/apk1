// Lifeform status, identity, activity, goals, memory and approvals.
import { HttpError, numberParam, optionalString, requireString } from '../http.mjs';
import { query } from '../db.mjs';
import { getLifeformState, mapAlert, resolveAlert } from '../events.mjs';
import {
  addMemory,
  createGoal,
  deleteGoal,
  deleteMemory,
  getGoal,
  getIdentity,
  lifeformOverview,
  listGoals,
  listMemories,
  updateGoal,
  updateIdentity,
  updateMemory,
  updateStep,
} from '../lifeform/identity.mjs';
import { planGoal, reflectionStatus, runReflection } from '../lifeform/core.mjs';
import { decideApproval, listApprovals, autonomyLevel, setAutonomyLevel, AUTONOMY } from '../security/policy.mjs';
import { localNodeInfo } from '../remote/local-runtime.mjs';
import * as ai from '../ai/engine.mjs';

export function lifeformRoutes() {
  return [
    {
      method: 'GET',
      pattern: '/api/v1/lifeform/status',
      handler: async () => {
        const state = getLifeformState();
        let model = null;
        try {
          const catalog = await ai.providerCatalog();
          model = catalog.active;
        } catch {
          model = null;
        }
        return {
          body: {
            ...lifeformOverview(),
            model,
            autonomy: { ...AUTONOMY[autonomyLevel()], runtime: await localNodeInfo() },
            reflection: reflectionStatus(),
          },
        };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/lifeform/identity',
      handler: () => ({ body: getIdentity() }),
    },
    {
      method: 'PUT',
      pattern: '/api/v1/lifeform/identity',
      handler: ({ body }) => ({ body: updateIdentity(body) }),
    },
    {
      method: 'GET',
      pattern: '/api/v1/lifeform/activity',
      handler: ({ url }) => {
        const limit = numberParam(url.searchParams.get('limit'), 50, { min: 1, max: 200 });
        const offset = numberParam(url.searchParams.get('offset'), 0, { min: 0, max: 100000 });
        const type = url.searchParams.get('type');
        const where = type ? 'WHERE type = ?' : '';
        const params = type ? [type, limit, offset] : [limit, offset];
        const rows = query.all(
          `SELECT * FROM activities ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
          ...params,
        );
        const total = query.get(`SELECT COUNT(*) AS n FROM activities ${where}`, ...(type ? [type] : [])).n;
        return {
          body: {
            total,
            activities: rows.map((row) => ({
              id: row.id,
              type: row.type,
              title: row.title,
              detail: row.detail,
              source: row.source,
              risk: row.risk,
              result: row.result,
              createdAt: row.created_at,
            })),
          },
        };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/lifeform/goals',
      handler: ({ url }) => {
        const status = url.searchParams.get('status');
        return { body: { goals: listGoals({ status, limit: 100 }) } };
      },
    },
    {
      method: 'POST',
      pattern: '/api/v1/lifeform/goals',
      handler: ({ body }) => {
        const title = requireString(body, 'title', { min: 3, max: 300 });
        const description = optionalString(body, 'description', { max: 4000 });
        const steps = Array.isArray(body.steps) ? body.steps.map(String) : [];
        return { status: 201, body: createGoal({ title, description, steps }) };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/lifeform/goals/:id',
      handler: ({ params }) => {
        const goal = getGoal(params.id);
        if (!goal) throw new HttpError(404, 'Goal not found.', 'GOAL_NOT_FOUND');
        return { body: goal };
      },
    },
    {
      method: 'PATCH',
      pattern: '/api/v1/lifeform/goals/:id',
      handler: ({ params, body }) => ({ body: updateGoal(params.id, body) }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/lifeform/goals/:id/pause',
      handler: ({ params }) => ({ body: updateGoal(params.id, { status: 'paused' }) }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/lifeform/goals/:id/resume',
      handler: ({ params }) => ({ body: updateGoal(params.id, { status: 'active' }) }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/lifeform/goals/:id/plan',
      handler: async ({ params }) => ({ body: await planGoal(params.id) }),
    },
    {
      method: 'DELETE',
      pattern: '/api/v1/lifeform/goals/:id',
      handler: ({ params }) => ({ body: { deleted: deleteGoal(params.id) } }),
    },
    {
      method: 'PATCH',
      pattern: '/api/v1/lifeform/steps/:id',
      handler: ({ params, body }) => ({
        body: updateStep(params.id, { status: requireString(body, 'status', { min: 2, max: 20 }), result: optionalString(body, 'result', { max: 4000 }) }),
      }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/lifeform/reflect',
      handler: async () => ({ body: await runReflection({ force: true }) }),
    },
    {
      method: 'GET',
      pattern: '/api/v1/memories',
      handler: ({ url }) => {
        const limit = numberParam(url.searchParams.get('limit'), 50, { min: 1, max: 200 });
        return {
          body: {
            memories: listMemories({
              category: url.searchParams.get('category'),
              search: url.searchParams.get('q'),
              limit,
            }),
          },
        };
      },
    },
    {
      method: 'POST',
      pattern: '/api/v1/memories',
      handler: ({ body }) => ({
        status: 201,
        body: addMemory({
          category: optionalString(body, 'category') ?? 'long-term',
          content: requireString(body, 'content', { min: 3, max: 8000 }),
          source: 'owner',
          importance: Number(body.importance ?? 3),
          tags: Array.isArray(body.tags) ? body.tags : [],
          confidence: body.confidence !== undefined ? Number(body.confidence) : 1,
        }),
      }),
    },
    {
      method: 'PATCH',
      pattern: '/api/v1/memories/:id',
      handler: ({ params, body }) => ({ body: updateMemory(params.id, body) }),
    },
    {
      method: 'DELETE',
      pattern: '/api/v1/memories/:id',
      handler: ({ params }) => ({ body: { deleted: deleteMemory(params.id) } }),
    },
    {
      method: 'GET',
      pattern: '/api/v1/approvals',
      handler: ({ url }) => ({
        body: { approvals: listApprovals({ status: url.searchParams.get('status'), limit: 100 }) },
      }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/approvals/:id/approve',
      handler: ({ params, auth }) => ({ body: decideApproval(params.id, 'approve', { by: auth.deviceId }) }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/approvals/:id/reject',
      handler: ({ params, auth }) => ({ body: decideApproval(params.id, 'reject', { by: auth.deviceId }) }),
    },
    {
      method: 'GET',
      pattern: '/api/v1/alerts',
      handler: ({ url }) => {
        const status = url.searchParams.get('status');
        const limit = numberParam(url.searchParams.get('limit'), 50, { min: 1, max: 200 });
        const rows = status
          ? query.all('SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC LIMIT ?', status, limit)
          : query.all('SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?', limit);
        return { body: { alerts: rows.map(mapAlert) } };
      },
    },
    {
      method: 'POST',
      pattern: '/api/v1/alerts/:id/resolve',
      handler: ({ params, auth }) => {
        const alert = resolveAlert(params.id, { by: auth.deviceId });
        if (!alert) throw new HttpError(404, 'Alert not found.', 'ALERT_NOT_FOUND');
        return { body: alert };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/autonomy',
      handler: async () => {
        const level = autonomyLevel();
        return { body: { level, ...AUTONOMY[level], options: Object.values(AUTONOMY), runtime: await localNodeInfo() } };
      },
    },
    {
      method: 'PUT',
      pattern: '/api/v1/autonomy',
      handler: ({ body }) => ({ body: setAutonomyLevel(body.level) }),
    },
  ];
}
