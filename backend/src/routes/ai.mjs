// AI chat, conversations, providers/models and usage.
import crypto from 'node:crypto';
import { HttpError, requireString, optionalString, numberParam } from '../http.mjs';
import { query } from '../db.mjs';
import * as ai from '../ai/engine.mjs';
import { getIdentity, listGoals, relevantMemories } from '../lifeform/identity.mjs';
import { getLifeformState, recordActivity } from '../events.mjs';
import { logger } from '../logger.mjs';

function titleFrom(message) {
  const clean = String(message ?? '').replace(/\s+/g, ' ').trim();
  return clean.length > 60 ? `${clean.slice(0, 57)}…` : clean || 'New conversation';
}

export function mapConversation(row) {
  return {
    id: row.id,
    title: row.title,
    provider: row.provider,
    model: row.model,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    messageCount: row.message_count ?? undefined,
  };
}

function getConversation(id) {
  const row = query.get('SELECT * FROM conversations WHERE id = ?', id);
  if (!row) throw new HttpError(404, 'Conversation not found.', 'CONVERSATION_NOT_FOUND');
  return row;
}

function createConversation({ title }) {
  const id = crypto.randomUUID();
  const now = Date.now();
  query.run(
    'INSERT INTO conversations (id, title, provider, model, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
    id,
    title,
    null,
    null,
    now,
    now,
  );
  return getConversation(id);
}

function historyFor(conversationId, limit = 40) {
  const rows = query.all(
    "SELECT role, content FROM messages WHERE conversation_id = ? AND role IN ('user','assistant') AND content <> '' ORDER BY created_at DESC LIMIT ?",
    conversationId,
    limit,
  );
  return rows.reverse().map((row) => ({ role: row.role, content: row.content }));
}

function appendMessage(conversationId, { role, content, toolName = null, meta = null }) {
  const id = crypto.randomUUID();
  const now = Date.now();
  query.run(
    'INSERT INTO messages (id, conversation_id, role, content, tool_name, meta, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    id,
    conversationId,
    role,
    content,
    toolName,
    meta ? JSON.stringify(meta) : null,
    now,
  );
  query.run('UPDATE conversations SET updated_at = ? WHERE id = ?', now, conversationId);
  return { id, role, content, toolName, meta, createdAt: now };
}

export function aiRoutes() {
  return [
    {
      method: 'POST',
      pattern: '/api/v1/ai/chat',
      handler: async ({ body, auth }) => {
        const message = requireString(body, 'message', { min: 1, max: 12000 });
        const requestedId = optionalString(body, 'conversationId', { max: 60 });
        let conversation = requestedId ? getConversation(requestedId) : createConversation({ title: titleFrom(message) });
        if (conversation.title === 'New conversation') {
          query.run('UPDATE conversations SET title = ? WHERE id = ?', titleFrom(message), conversation.id);
        }

        appendMessage(conversation.id, { role: 'user', content: message });
        recordActivity({ type: 'chat', title: `Pesan masuk: ${titleFrom(message)}`, source: auth.deviceName ?? 'app', result: 'received' });

        const result = await ai.chat({
          conversationId: conversation.id,
          messages: historyFor(conversation.id),
          identity: getIdentity(),
          state: getLifeformState(),
          memories: relevantMemories(10),
          goals: listGoals({ status: 'active', limit: 5 }),
        });

        const assistant = appendMessage(conversation.id, {
          role: 'assistant',
          content: result.text,
          meta: {
            model: result.model,
            provider: result.provider,
            durationMs: result.durationMs,
            toolCalls: result.toolEvents.length,
          },
        });
        for (const tool of result.toolEvents) {
          appendMessage(conversation.id, {
            role: 'tool',
            content: '',
            toolName: tool.name,
            meta: { ok: tool.ok, durationMs: tool.durationMs },
          });
        }
        query.run('UPDATE conversations SET model = ?, provider = ?, updated_at = ? WHERE id = ?', result.model, result.provider, Date.now(), conversation.id);
        return {
          body: {
            conversationId: conversation.id,
            message: assistant,
            model: result.model,
            modelName: result.model,
            provider: result.provider,
            providerName: result.providerName,
            durationMs: result.durationMs,
            toolCalls: result.toolEvents.map((tool) => tool.name),
            usage: await ai.usageSummary().then((usage) => usage.today),
          },
        };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/ai/providers',
      handler: async () => ({ body: await ai.providerCatalog() }),
    },
    {
      method: 'GET',
      pattern: '/api/v1/ai/models',
      handler: async () => {
        const catalog = await ai.providerCatalog();
        return { body: { models: catalog.models, active: catalog.active } };
      },
    },
    {
      method: 'PUT',
      pattern: '/api/v1/ai/model',
      handler: async ({ body }) => {
        const model = requireString(body, 'model', { min: 1, max: 200 });
        const provider = optionalString(body, 'provider', { max: 40 });
        return { body: await ai.setModel({ model, provider }) };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/ai/usage',
      handler: async () => ({ body: await ai.usageSummary() }),
    },
    {
      method: 'GET',
      pattern: '/api/v1/conversations',
      handler: ({ url }) => {
        const limit = numberParam(url.searchParams.get('limit'), 30, { min: 1, max: 100 });
        const rows = query.all(
          `SELECT c.*, (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) AS message_count
           FROM conversations c ORDER BY c.updated_at DESC LIMIT ?`,
          limit,
        );
        return { body: { conversations: rows.map(mapConversation) } };
      },
    },
    {
      method: 'POST',
      pattern: '/api/v1/conversations',
      handler: ({ body }) => {
        const title = optionalString(body, 'title', { max: 120 }) ?? 'New conversation';
        return { status: 201, body: mapConversation(createConversation({ title })) };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/conversations/:id',
      handler: ({ params }) => {
        const row = getConversation(params.id);
        const messages = query
          .all('SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC LIMIT 500', params.id)
          .map((message) => ({
            id: message.id,
            role: message.role,
            content: message.content,
            toolName: message.tool_name,
            meta: message.meta ? JSON.parse(message.meta) : null,
            createdAt: message.created_at,
          }));
        return { body: { conversation: mapConversation(row), messages } };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/conversations/:id/messages',
      handler: ({ params, url }) => {
        getConversation(params.id);
        const limit = numberParam(url.searchParams.get('limit'), 100, { min: 1, max: 500 });
        const rows = query.all(
          'SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT ?',
          params.id,
          limit,
        );
        return {
          body: {
            messages: rows.reverse().map((message) => ({
              id: message.id,
              role: message.role,
              content: message.content,
              toolName: message.tool_name,
              meta: message.meta ? JSON.parse(message.meta) : null,
              createdAt: message.created_at,
            })),
          },
        };
      },
    },
    {
      method: 'DELETE',
      pattern: '/api/v1/conversations/:id',
      handler: ({ params }) => {
        getConversation(params.id);
        query.run('DELETE FROM messages WHERE conversation_id = ?', params.id);
        query.run('DELETE FROM conversations WHERE id = ?', params.id);
        logger.info(`conversation deleted: ${params.id}`);
        return { body: { deleted: true } };
      },
    },
  ];
}
