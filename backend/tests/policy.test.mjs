import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Isolated database so the test never touches the live one.
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lifeform-test-'));
process.env.DATA_DIR = dataDir;
process.env.NODE_ENV = 'test';

const { openDatabase, closeDatabase, query } = await import('../src/db.mjs');
const policy = await import('../src/security/policy.mjs');

openDatabase();

test('read-only commands do not need approval', () => {
  const verdict = policy.classifyCommand('df -h && free -m');
  assert.equal(verdict.risk, 'low');
  assert.equal(verdict.requiresApproval, false);
});

test('destructive commands are classified as critical', () => {
  const verdict = policy.classifyCommand('rm -rf /');
  assert.equal(verdict.risk, 'critical');
  assert.equal(verdict.requiresApproval, true);
});

test('firewall and sshd changes require approval', () => {
  assert.equal(policy.classifyCommand('iptables -F').risk, 'high');
  assert.equal(policy.classifyCommand('sed -i "s/x/y/" /etc/ssh/sshd_config').risk, 'critical');
});

test('level 1 (observe) blocks mutating actions', () => {
  policy.setAutonomyLevel(1);
  const verdict = policy.authorize({ action: 'pm2 restart miku', command: 'pm2 restart miku', target: 'miku' });
  assert.equal(verdict.allowed, false);
});

test('level 1 still allows reading', () => {
  policy.setAutonomyLevel(1);
  const verdict = policy.authorize({ action: 'ps aux', command: 'ps aux' });
  assert.equal(verdict.allowed, true);
});

test('level 2 allows routine restarts of known services', () => {
  policy.setAutonomyLevel(2);
  const verdict = policy.authorize({ action: 'pm2 restart miku', command: 'pm2 restart miku', target: 'miku', routine: true });
  assert.equal(verdict.allowed, true);
});

test('level 3 still routes destructive commands to approval', () => {
  policy.setAutonomyLevel(3);
  const verdict = policy.authorize({ action: 'shutdown now', command: 'shutdown now' });
  assert.equal(verdict.approvalRequired, true);
});

test('approval decisions are persisted and single-shot', () => {
  const approval = policy.createApproval({ action: 'restart nginx', reason: 'test', risk: 'high', command: 'nginx -s reload' });
  const decided = policy.decideApproval(approval.id, 'approve', { by: 'test' });
  assert.equal(decided.status, 'approved');
  assert.throws(() => policy.decideApproval(approval.id, 'approve'), /already/);

  const row = query.get('SELECT status FROM approvals WHERE id = ?', approval.id);
  assert.equal(row.status, 'approved');
});

test('expired approvals are swept', () => {
  const approval = policy.createApproval({ action: 'old', reason: 'test', risk: 'medium', ttlMs: 1 });
  query.run('UPDATE approvals SET expires_at = ? WHERE id = ?', Date.now() - 1000, approval.id);
  const swept = policy.expireApprovals();
  assert.ok(swept >= 1);
  const row = query.get('SELECT status FROM approvals WHERE id = ?', approval.id);
  assert.equal(row.status, 'expired');
});

test.after(() => {
  closeDatabase();
  fs.rmSync(dataDir, { recursive: true, force: true });
});
