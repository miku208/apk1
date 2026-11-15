// Encrypted storage for remote server credentials.
// AES-256-GCM with a key that never leaves the host. The API can tell you that
// a secret exists, but never returns it.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { config, ensureDirs } from '../config.mjs';

const PREFIX = 'v1';
let cachedKey = null;

function keyFile() {
  return path.join(config.dataDir, 'remote.key');
}

function parseKey(raw) {
  const trimmed = String(raw ?? '').trim();
  if (!trimmed) return null;
  const buf = /^[0-9a-f]{64}$/i.test(trimmed) ? Buffer.from(trimmed, 'hex') : Buffer.from(trimmed, 'base64');
  return buf.length === 32 ? buf : null;
}

/** Load (or create once) the 32-byte key. File mode 0600, never logged. */
export function loadKey() {
  if (cachedKey) return cachedKey;
  const fromEnv = parseKey(process.env.REMOTE_SECRET_KEY);
  if (fromEnv) {
    cachedKey = fromEnv;
    return cachedKey;
  }
  ensureDirs();
  const file = keyFile();
  try {
    const existing = parseKey(fs.readFileSync(file, 'utf8'));
    if (existing) {
      cachedKey = existing;
      return cachedKey;
    }
    throw new Error('remote.key is not a valid 32-byte key');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const key = crypto.randomBytes(32);
    fs.writeFileSync(file, key.toString('base64'), { mode: 0o600 });
    try {
      fs.chmodSync(file, 0o600);
    } catch {
      /* best effort on exotic filesystems */
    }
    cachedKey = key;
    return cachedKey;
  }
}

export function encryptSecret(plaintext) {
  if (plaintext === null || plaintext === undefined || plaintext === '') return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', loadKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [PREFIX, iv.toString('base64url'), tag.toString('base64url'), ciphertext.toString('base64url')].join('.');
}

export function decryptSecret(payload) {
  if (!payload) return null;
  const parts = String(payload).split('.');
  if (parts.length !== 4 || parts[0] !== PREFIX) throw new Error('Unsupported secret format');
  const [, ivRaw, tagRaw, dataRaw] = parts;
  const decipher = crypto.createDecipheriv('aes-256-gcm', loadKey(), Buffer.from(ivRaw, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagRaw, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(dataRaw, 'base64url')), decipher.final()]).toString('utf8');
}

/** Non-reversible hint so the UI can confirm which credential is stored. */
export function secretHint(plaintext) {
  if (!plaintext) return null;
  const value = String(plaintext);
  if (value.length <= 4) return '••••';
  return `${value.slice(0, 2)}••••${value.slice(-2)} (${value.length} karakter)`;
}
