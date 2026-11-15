// Authentication and device management routes.
import { HttpError, requireString, optionalString, isLocalRequest } from '../http.mjs';
import {
  activePairingSessions,
  createPairingSession,
  listDevices,
  loginWithPassword,
  logoutDevice,
  pairDevice,
  refreshTokens,
  revokeDevice,
} from '../auth.mjs';
import { config } from '../config.mjs';

export function authRoutes() {
  return [
    {
      method: 'GET',
      pattern: '/api/v1/auth/pairing',
      auth: false,
      handler: ({ req }) => {
        // Bootstrap stays on the box: the owner runs `npm run pair` or reads the
        // startup code from the log. Remote callers cannot mint pairing codes.
        if (!isLocalRequest(req)) throw new HttpError(403, 'Pairing codes can only be created locally.', 'LOCAL_ONLY');
        const session = createPairingSession({ createdBy: 'local' });
        return {
          status: 201,
          body: {
            pairingId: session.id,
            code: session.code,
            expiresAt: session.expiresAt,
            ttlSeconds: Math.floor(config.pairingTtlMs / 1000),
            hint: 'Masukkan kode ini di aplikasi Android → Settings → Pair device.',
          },
        };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/auth/pairing/sessions',
      handler: () => ({ body: { sessions: activePairingSessions() } }),
    },
    {
      method: 'POST',
      pattern: '/api/v1/auth/pair',
      auth: false,
      handler: ({ body }) => {
        const code = requireString(body, 'code', { min: 4, max: 12 });
        const name = optionalString(body, 'deviceName', { max: 80 }) ?? 'Android device';
        const platform = optionalString(body, 'platform', { max: 40 }) ?? 'android';
        return { status: 201, body: pairDevice({ code, name, platform }) };
      },
    },
    {
      method: 'POST',
      pattern: '/api/v1/auth/login',
      auth: false,
      handler: ({ body }) => {
        const password = requireString(body, 'password', { min: 1, max: 200 });
        const name = optionalString(body, 'deviceName', { max: 80 }) ?? 'Android device';
        return { body: loginWithPassword({ password, name }) };
      },
    },
    {
      method: 'POST',
      pattern: '/api/v1/auth/refresh',
      auth: false,
      handler: ({ body }) => {
        const refreshToken = requireString(body, 'refreshToken', { min: 10, max: 500 });
        const deviceId = requireString(body, 'deviceId', { min: 5, max: 100 });
        return { body: refreshTokens({ refreshToken, deviceId }) };
      },
    },
    {
      method: 'POST',
      pattern: '/api/v1/auth/logout',
      handler: ({ auth }) => {
        logoutDevice(auth.deviceId);
        return { body: { ok: true } };
      },
    },
    {
      method: 'GET',
      pattern: '/api/v1/auth/devices',
      handler: () => ({ body: { devices: listDevices() } }),
    },
    {
      method: 'DELETE',
      pattern: '/api/v1/auth/devices/:id',
      handler: ({ params, auth }) => {
        if (params.id === auth.deviceId) {
          throw new HttpError(400, 'Cannot revoke the device you are using right now.', 'SELF_REVOKE');
        }
        return { body: { revoked: revokeDevice(params.id) } };
      },
    },
  ];
}
