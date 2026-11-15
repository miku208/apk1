// Remote path handling: POSIX normalisation, a root boundary and traversal
// rejection. Nothing here touches the network; the caller still verifies the
// canonical path (and symlink targets) through the connection.
import path from 'node:path';

const posix = path.posix;

export class RemotePathError extends Error {
  constructor(message, code = 'PATH_INVALID') {
    super(message);
    this.code = code;
    this.status = 403;
  }
}

/** Normalise the configured root: absolute, no trailing slash, no "..". */
export function normalizeRoot(input) {
  const raw = String(input ?? '/').trim() || '/';
  if (raw.includes('\0')) throw new RemotePathError('Root path mengandung karakter tidak valid.');
  const absolute = posix.isAbsolute(raw) ? raw : `/${raw}`;
  const normalized = posix.normalize(absolute);
  return normalized === '/' ? '/' : normalized.replace(/\/+$/, '');
}

export function isInsideRoot(root, target) {
  const base = normalizeRoot(root);
  const candidate = posix.normalize(target);
  if (base === '/') return candidate.startsWith('/');
  return candidate === base || candidate.startsWith(`${base}/`);
}

/**
 * Resolve a user supplied path against the allowed root.
 * Absolute input stays absolute but must remain inside the root; relative input
 * is joined to the current directory (which itself must be inside the root).
 */
export function resolveRemotePath({ root = '/', cwd = null, target }) {
  const base = normalizeRoot(root);
  const raw = String(target ?? '').trim();
  if (raw.includes('\0')) throw new RemotePathError('Path mengandung karakter tidak valid.');
  if (raw.length > 4096) throw new RemotePathError('Path terlalu panjang.');
  const directory = cwd ? resolveRemotePath({ root: base, target: cwd }) : base;

  let joined;
  if (posix.isAbsolute(raw)) joined = posix.normalize(raw);
  else joined = posix.normalize(posix.join(directory, raw || '.'));

  if (joined.includes('\0')) throw new RemotePathError('Path mengandung karakter tidak valid.');
  if (!isInsideRoot(base, joined)) {
    throw new RemotePathError(`Path berada di luar direktori yang diizinkan (${base}).`, 'PATH_ESCAPE');
  }
  return joined;
}

/** Join a directory entry name safely (rejects separators and traversal). */
export function resolveEntry(directory, name) {
  const entry = String(name ?? '');
  if (!entry || entry === '.' || entry === '..' || entry.includes('/') || entry.includes('\0')) {
    throw new RemotePathError('Nama entry tidak valid.', 'ENTRY_INVALID');
  }
  return posix.join(directory, entry);
}

export function parentOf(target) {
  const value = posix.normalize(target);
  const parent = posix.dirname(value);
  if (!parent || parent === '.') return '/';
  return parent;
}

const SENSITIVE_PATTERNS = [
  /(^|\/)\.env(\.|$)/i,
  /(^|\/)\.env$/i,
  /(^|\/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i,
  /(^|\/)credentials(\.json)?$/i,
  /(^|\/)(\.npmrc|\.netrc|\.pgpass)$/i,
  /(^|\/)\.ssh\/(config|known_hosts)$/i,
  /\.(pem|key|p12|pfx|jks|keystore)$/i,
  /(^|\/)(secrets?|tokens?)(\.json|\.yaml|\.yml|\.env)?$/i,
  /(^|\/)remote\.key$/i,
];

export function isSensitivePath(target) {
  const value = String(target ?? '');
  return SENSITIVE_PATTERNS.some((pattern) => pattern.test(value));
}

export function isPrivateKeyPath(target) {
  return /\.(pem|key)$/i.test(String(target ?? '')) || /id_(rsa|ed25519|ecdsa|dsa)$/i.test(String(target ?? ''));
}

/** Heuristic: NUL byte or too many control characters means "do not render as text". */
export function looksBinary(buffer) {
  const sample = Buffer.isBuffer(buffer) ? buffer.subarray(0, Math.min(buffer.length, 8000)) : Buffer.from(buffer ?? '');
  if (!sample.length) return false;
  if (sample.includes(0)) return true;
  let control = 0;
  for (const byte of sample) {
    if (byte < 9 || (byte > 13 && byte < 32)) control += 1;
  }
  return control / sample.length > 0.1;
}

const MIME_BY_EXTENSION = {
  txt: 'text/plain',
  log: 'text/plain',
  md: 'text/markdown',
  js: 'text/javascript',
  mjs: 'text/javascript',
  cjs: 'text/javascript',
  ts: 'text/typescript',
  json: 'application/json',
  html: 'text/html',
  htm: 'text/html',
  css: 'text/css',
  yml: 'text/yaml',
  yaml: 'text/yaml',
  xml: 'text/xml',
  sh: 'text/x-shellscript',
  py: 'text/x-python',
  env: 'text/plain',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  svg: 'image/svg+xml',
  pdf: 'application/pdf',
  zip: 'application/zip',
  gz: 'application/gzip',
  apk: 'application/vnd.android.package-archive',
};

export function mimeTypeFor(target, fallback = 'application/octet-stream') {
  const ext = posix.extname(String(target ?? '')).slice(1).toLowerCase();
  return MIME_BY_EXTENSION[ext] ?? fallback;
}

export function isPreviewableText(target) {
  return mimeTypeFor(target).startsWith('text/') || mimeTypeFor(target) === 'application/json';
}

export function isImage(target) {
  return mimeTypeFor(target).startsWith('image/');
}

export function sortEntries(entries, { sortBy = 'name', order = 'asc' } = {}) {
  const direction = order === 'desc' ? -1 : 1;
  const keyed = [...entries];
  keyed.sort((a, b) => {
    // Directories first, always.
    if (a.type === 'directory' && b.type !== 'directory') return -1;
    if (a.type !== 'directory' && b.type === 'directory') return 1;
    let result = 0;
    if (sortBy === 'size') result = (a.size ?? 0) - (b.size ?? 0);
    else if (sortBy === 'modified') result = (a.modifiedAt ?? 0) - (b.modifiedAt ?? 0);
    else if (sortBy === 'type') {
      result = String(posix.extname(a.name)).localeCompare(String(posix.extname(b.name)));
      if (result === 0) result = a.name.localeCompare(b.name);
    } else result = a.name.localeCompare(b.name, 'en', { numeric: true });
    return result * direction;
  });
  return keyed;
}

export { posix };
