#!/usr/bin/env node
// Pre-flight check: engine modules, credentials, database, port and permissions.
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { config, ensureDirs } from '../src/config.mjs';
import { openDatabase, query } from '../src/db.mjs';
import { agentCredentialsFile } from '../src/ai/engine.mjs';

const checks = [];
function ok(name, detail) {
  checks.push({ name, status: 'ok', detail });
}
function warn(name, detail) {
  checks.push({ name, status: 'warn', detail });
}
function fail(name, detail) {
  checks.push({ name, status: 'fail', detail });
}

function checkNode() {
  const major = Number(process.versions.node.split('.')[0]);
  const minor = Number(process.versions.node.split('.')[1]);
  if (major > 22 || (major === 22 && minor >= 5)) ok('node', process.version);
  else fail('node', `Butuh Node >= 22.5 untuk node:sqlite (sekarang ${process.version})`);
}

function checkAgent() {
  const src = path.join(config.agentHome, 'src');
  if (!fs.existsSync(src)) return fail('mikuhost-agent', `Tidak ditemukan di ${src}`);
  const required = [
    'config/manager.mjs',
    'credentials/manager.mjs',
    'providers/catalog.mjs',
    'models/registry.mjs',
    'core/agent-loop.mjs',
    'tools/registry.mjs',
    'sessions/database.mjs',
  ];
  const missing = required.filter((file) => !fs.existsSync(path.join(src, file)));
  if (missing.length) fail('mikuhost-agent', `Modul hilang: ${missing.join(', ')}`);
  else ok('mikuhost-agent', src);
}

function checkCredentials() {
  const file = agentCredentialsFile();
  if (!fs.existsSync(file)) return fail('credentials', `Tidak ada file kredensial: ${file}`);
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    const keys = Array.isArray(parsed.keys) ? parsed.keys : [];
    if (!keys.length) return warn('credentials', 'File ada tetapi tidak berisi key');
    const providers = Array.from(new Set(keys.map((entry) => entry.provider)));
    ok('credentials', `${keys.length} key · provider: ${providers.join(', ')} (nilai tidak ditampilkan)`);
  } catch {
    fail('credentials', 'File kredensial tidak bisa dibaca sebagai JSON');
  }
}

function checkDb() {
  try {
    ensureDirs();
    openDatabase();
    const tables = query.all("SELECT name FROM sqlite_master WHERE type = 'table'").map((row) => row.name);
    ok('database', `${config.dbFile} · ${tables.length} tabel`);
  } catch (error) {
    fail('database', String(error?.message ?? error));
  }
}

function checkEnv() {
  const envFile = path.join(config.root, '.env');
  if (!fs.existsSync(envFile)) warn('.env', 'Belum ada .env (memakai default + .env.example)');
  else ok('.env', envFile);
  if (!config.ownerPassword) warn('OWNER_PASSWORD', 'Tidak diset — login hanya lewat pairing code');
}

function probePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', (error) => resolve({ free: false, error: error.code }));
    server.once('listening', () => server.close(() => resolve({ free: true })));
    server.listen(config.port, config.host);
  });
}

async function main() {
  checkNode();
  checkAgent();
  checkCredentials();
  checkDb();
  checkEnv();
  const port = await probePort();
  if (port.free) ok('port', `${config.host}:${config.port} bebas`);
  else warn('port', `${config.host}:${config.port} sedang dipakai (${port.error}) — mungkin service sudah jalan`);

  let failures = 0;
  for (const check of checks) {
    if (check.status === 'fail') failures += 1;
    const icon = check.status === 'ok' ? 'OK  ' : check.status === 'warn' ? 'WARN' : 'FAIL';
    console.log(`${icon}  ${check.name.padEnd(18)} ${check.detail}`);
  }
  console.log('');
  console.log(failures ? `${failures} masalah harus diperbaiki.` : 'Semua pemeriksaan kritis lolos.');
  process.exit(failures ? 1 : 0);
}

main();
