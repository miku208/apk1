// SQLite layer built on the Node built-in driver (no native build step).
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { config, ensureDirs } from './config.mjs';
import { logger } from './logger.mjs';

let db = null;

/**
 * Schema migrations are append-only. `schema_migrations` records what has been
 * applied so a restart never re-runs a migration or loses data.
 */
const MIGRATIONS = [
  {
    id: 1,
    name: 'initial',
    sql: `
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        platform TEXT,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER,
        revoked_at INTEGER
      );

      CREATE TABLE IF NOT EXISTS tokens (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        scopes TEXT NOT NULL DEFAULT 'owner',
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        revoked_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash);

      CREATE TABLE IF NOT EXISTS pairing_sessions (
        id TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER,
        created_at INTEGER NOT NULL,
        created_by TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_pairing_hash ON pairing_sessions(code_hash);

      CREATE TABLE IF NOT EXISTS conversations (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL DEFAULT 'New conversation',
        provider TEXT,
        model TEXT,
        session_id TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        content TEXT NOT NULL DEFAULT '',
        tool_name TEXT,
        meta TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at);

      CREATE TABLE IF NOT EXISTS lifeform_identity (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        name TEXT NOT NULL,
        personality TEXT NOT NULL,
        language TEXT NOT NULL,
        style TEXT NOT NULL,
        purpose TEXT NOT NULL,
        constraints TEXT NOT NULL,
        preferences TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS lifeform_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        state TEXT NOT NULL,
        current_task TEXT,
        active_goal TEXT,
        last_activity TEXT,
        last_reflection TEXT,
        since INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS memories (
        id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        content TEXT NOT NULL,
        source TEXT NOT NULL,
        importance INTEGER NOT NULL DEFAULT 3,
        tags TEXT NOT NULL DEFAULT '[]',
        confidence REAL NOT NULL DEFAULT 0.7,
        expires_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_memories_category ON memories(category, created_at DESC);

      CREATE TABLE IF NOT EXISTS goals (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        progress INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        completed_at INTEGER
      );

      CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        goal_id TEXT REFERENCES goals(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS task_steps (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        position INTEGER NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        result TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_steps_task ON task_steps(task_id, position);

      CREATE TABLE IF NOT EXISTS server_nodes (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT 'primary',
        host TEXT,
        status TEXT NOT NULL DEFAULT 'unknown',
        last_seen_at INTEGER,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS server_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id TEXT NOT NULL REFERENCES server_nodes(id) ON DELETE CASCADE,
        captured_at INTEGER NOT NULL,
        metrics TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_metrics_node_time ON server_metrics(node_id, captured_at DESC);

      CREATE TABLE IF NOT EXISTS services (
        id TEXT PRIMARY KEY,
        node_id TEXT NOT NULL REFERENCES server_nodes(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        kind TEXT NOT NULL,
        status TEXT NOT NULL,
        detail TEXT,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        node_id TEXT REFERENCES server_nodes(id) ON DELETE SET NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        detail TEXT,
        source TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        created_at INTEGER NOT NULL,
        resolved_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at DESC);

      CREATE TABLE IF NOT EXISTS activities (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        detail TEXT,
        source TEXT NOT NULL,
        risk TEXT,
        result TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_activities_time ON activities(created_at DESC);

      CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        action TEXT NOT NULL,
        reason TEXT,
        risk TEXT NOT NULL,
        command TEXT,
        target TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        resolved_at INTEGER,
        resolved_by TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, created_at DESC);

      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT,
        detail TEXT,
        result TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at DESC);

      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE,
        scopes TEXT NOT NULL DEFAULT 'read',
        rate_limit INTEGER NOT NULL DEFAULT 60,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        revoked_at INTEGER
      );

      CREATE TABLE IF NOT EXISTS plugin_registry (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        description TEXT,
        category TEXT,
        enabled INTEGER NOT NULL DEFAULT 0,
        permissions TEXT NOT NULL DEFAULT '[]',
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        body TEXT,
        level TEXT NOT NULL DEFAULT 'info',
        status TEXT NOT NULL DEFAULT 'unread',
        created_at INTEGER NOT NULL,
        read_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications(status, created_at DESC);

      CREATE TABLE IF NOT EXISTS terminal_tasks (
        id TEXT PRIMARY KEY,
        command TEXT NOT NULL,
        status TEXT NOT NULL,
        exit_code INTEGER,
        output TEXT,
        started_at INTEGER NOT NULL,
        finished_at INTEGER,
        created_by TEXT
      );
    `,
  },
  {
    id: 2,
    name: 'alert-kind-and-history',
    sql: `
      -- Alerts used to be deduplicated by title, and the CPU title embedded the
      -- measured value, so every new percentage created a new alert. kind is
      -- the stable key (cpu, memory, disk, service:<name>) used for dedupe.
      ALTER TABLE alerts ADD COLUMN kind TEXT;
      ALTER TABLE alerts ADD COLUMN metric_value REAL;
      ALTER TABLE alerts ADD COLUMN threshold REAL;
      ALTER TABLE alerts ADD COLUMN peak_value REAL;
      ALTER TABLE alerts ADD COLUMN updated_at INTEGER;

      UPDATE alerts SET kind = CASE
        WHEN title LIKE 'CPU%' THEN 'cpu'
        WHEN title LIKE 'RAM%' THEN 'memory'
        WHEN title LIKE 'Disk%' THEN 'disk'
        WHEN title LIKE 'Service berhenti:%' THEN 'service:' || TRIM(SUBSTR(title, 19))
        ELSE NULL
      END
      WHERE kind IS NULL;

      CREATE TABLE IF NOT EXISTS alert_events (
        id TEXT PRIMARY KEY,
        alert_id TEXT NOT NULL,
        node_id TEXT,
        kind TEXT,
        status TEXT NOT NULL,
        from_status TEXT,
        severity TEXT,
        value REAL,
        threshold REAL,
        message TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_alert_events_alert ON alert_events(alert_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_alert_events_kind ON alert_events(kind, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_alerts_kind ON alerts(source, kind, status);
    `,
  },
  {
    id: 3,
    name: 'vps-remote-control',
    sql: `
      -- Saved remote machines reached over SSH/SFTP (primary) or FTP/FTPS.
      -- Secrets are encrypted with AES-256-GCM before they reach this table and
      -- are never returned to the API in plaintext.
      CREATE TABLE IF NOT EXISTS remote_servers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        protocol TEXT NOT NULL DEFAULT 'sftp',
        host TEXT NOT NULL,
        port INTEGER NOT NULL DEFAULT 22,
        username TEXT NOT NULL,
        auth_type TEXT NOT NULL DEFAULT 'password',
        password_encrypted TEXT,
        private_key_encrypted TEXT,
        passphrase_encrypted TEXT,
        host_fingerprint TEXT,
        remote_root TEXT NOT NULL DEFAULT '/',
        connect_timeout_ms INTEGER NOT NULL DEFAULT 15000,
        is_default INTEGER NOT NULL DEFAULT 0,
        last_status TEXT,
        last_error TEXT,
        last_connected_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_remote_servers_default ON remote_servers(is_default DESC, name);

      CREATE TABLE IF NOT EXISTS remote_connection_events (
        id TEXT PRIMARY KEY,
        server_id TEXT,
        protocol TEXT,
        event TEXT NOT NULL,
        status TEXT,
        detail TEXT,
        actor TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_remote_conn_events ON remote_connection_events(server_id, created_at DESC);

      CREATE TABLE IF NOT EXISTS remote_transfers (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL,
        device_id TEXT,
        direction TEXT NOT NULL,
        remote_path TEXT NOT NULL,
        local_name TEXT,
        total_bytes INTEGER,
        transferred_bytes INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL,
        error TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        finished_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_remote_transfers ON remote_transfers(created_at DESC);

      CREATE TABLE IF NOT EXISTS remote_terminal_sessions (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL,
        device_id TEXT,
        user_id TEXT,
        shell TEXT,
        cwd TEXT,
        cols INTEGER NOT NULL DEFAULT 80,
        rows INTEGER NOT NULL DEFAULT 24,
        pty_pid INTEGER,
        status TEXT NOT NULL,
        buffer_bytes INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        last_activity INTEGER NOT NULL,
        closed_at INTEGER,
        close_reason TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_remote_terminals ON remote_terminal_sessions(created_at DESC);
    `,
  },
  {
    id: 4,
    name: 'remote-local-runtime',
    sql: `
      -- Primary VPS is accessed through the local runtime, never SSH to itself.
      -- The migration only adds the columns; identifyPrimaryNode() (servers.mjs)
      -- decides which saved node is this host, so a loopback-looking SSH server
      -- is never silently converted into a local node.
      ALTER TABLE remote_servers ADD COLUMN runtime TEXT NOT NULL DEFAULT 'remote';
      ALTER TABLE remote_servers ADD COLUMN runtime_kind TEXT;
    `,
  },
];

export function openDatabase(file = config.dbFile) {
  if (db) return db;
  ensureDirs();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('PRAGMA busy_timeout = 5000');
  db.exec('CREATE TABLE IF NOT EXISTS schema_migrations (id INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)');
  const applied = new Set(db.prepare('SELECT id FROM schema_migrations').all().map((row) => Number(row.id)));
  for (const migration of MIGRATIONS) {
    if (applied.has(migration.id)) continue;
    db.exec('BEGIN');
    try {
      db.exec(migration.sql);
      db.prepare('INSERT INTO schema_migrations (id, name, applied_at) VALUES (?, ?, ?)').run(
        migration.id,
        migration.name,
        Date.now(),
      );
      db.exec('COMMIT');
      logger.info(`migration applied: ${migration.id}-${migration.name}`);
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }
  return db;
}

export function getDb() {
  return db ?? openDatabase();
}

export function closeDatabase() {
  if (!db) return;
  try {
    db.close();
  } catch {
    /* ignore */
  }
  db = null;
}

export const query = {
  all(sql, ...params) {
    return getDb().prepare(sql).all(...params);
  },
  get(sql, ...params) {
    return getDb().prepare(sql).get(...params) ?? null;
  },
  run(sql, ...params) {
    return getDb().prepare(sql).run(...params);
  },
};

/** Run `fn` inside a transaction; rolls back on throw. */
export function transaction(fn) {
  const database = getDb();
  database.exec('BEGIN');
  try {
    const result = fn();
    database.exec('COMMIT');
    return result;
  } catch (error) {
    try {
      database.exec('ROLLBACK');
    } catch {
      /* ignore */
    }
    throw error;
  }
}

export function parseJson(value, fallback) {
  if (value == null) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}
