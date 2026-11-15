// SSH host key pinning. A server is only trusted when its host key matches the
// fingerprint the owner saved; unknown keys are reported, never auto-accepted.
import crypto from 'node:crypto';

/** SHA256 fingerprint of an SSH host key blob, OpenSSH style (no padding). */
export function fingerprintFromKeyBlob(keyBlob) {
  if (!keyBlob) return null;
  const digest = crypto.createHash('sha256').update(Buffer.from(keyBlob)).digest('base64').replace(/=+$/, '');
  return `SHA256:${digest}`;
}

/** Accepts "SHA256:abc", "abc", "SHA256:abc=" and normalises to "SHA256:abc". */
export function normalizeFingerprint(input) {
  if (!input) return null;
  let value = String(input).trim();
  if (!value) return null;
  value = value.replace(/^sha256:/i, '');
  value = value.split(/\s+/)[0];
  value = value.replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/]{43}$/.test(value)) return null;
  return `SHA256:${value}`;
}

export function fingerprintsMatch(a, b) {
  const left = normalizeFingerprint(a);
  const right = normalizeFingerprint(b);
  if (!left || !right) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
  } catch {
    return false;
  }
}

/**
 * `hostVerifier` for ssh2: returns true only for the pinned fingerprint.
 * With no pin the connection is refused — the caller must run a probe first,
 * show the fingerprint to the owner and save it.
 */
export function createHostVerifier(expectedFingerprint, onSeen) {
  const expected = normalizeFingerprint(expectedFingerprint);
  return (keyBlob) => {
    const seen = fingerprintFromKeyBlob(keyBlob);
    onSeen?.(seen);
    if (!expected) return false;
    return fingerprintsMatch(expected, seen);
  };
}

export class HostKeyMismatchError extends Error {
  constructor({ expected, actual }) {
    super('SSH host key tidak cocok dengan fingerprint yang tersimpan.');
    this.code = 'HOST_KEY_MISMATCH';
    this.status = 409;
    this.detail = { expected, actual };
  }
}
