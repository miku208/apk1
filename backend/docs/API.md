# API

Base: `https://ashimusic.biz.id/lifeform/api/v1` (lokal: `http://127.0.0.1:8888/api/v1`)

Semua endpoint (kecuali auth publik dan `/health`) membutuhkan
`Authorization: Bearer <accessToken>`.

## Auth

| Method | Path | Keterangan |
|---|---|---|
| GET | `/auth/pairing` | buat kode pairing (hanya dari loopback) |
| POST | `/auth/pair` | `{code, deviceName, platform}` → token + deviceId |
| POST | `/auth/login` | `{password, deviceName}` (aktif bila `OWNER_PASSWORD` diset) |
| POST | `/auth/refresh` | `{refreshToken, deviceId}` → token baru (rotasi) |
| POST | `/auth/logout` | cabut token device ini |
| GET | `/auth/devices` | daftar device |
| DELETE | `/auth/devices/:id` | cabut device lain |

## AI

| Method | Path | Keterangan |
|---|---|---|
| POST | `/ai/chat` | `{message, conversationId?}` → jawaban lengkap |
| GET | `/ai/providers` | provider + model yang tersedia (key tersedia/tidak) |
| GET | `/ai/models` | daftar model |
| PUT | `/ai/model` | `{model, provider}` pilih model aktif |
| GET | `/ai/usage` | pemakaian token harian |

Streaming jawaban dikirim lewat WebSocket (`ai.stream`, `ai.status`,
`ai.completed`, `ai.error`).

## Conversations

`GET /conversations`, `POST /conversations`, `GET /conversations/:id`,
`GET /conversations/:id/messages`, `DELETE /conversations/:id`

## Lifeform

| Method | Path |
|---|---|
| GET | `/lifeform/status` |
| GET/PUT | `/lifeform/identity` |
| GET | `/lifeform/activity?limit&offset&type` |
| GET/POST | `/lifeform/goals` |
| GET/PATCH/DELETE | `/lifeform/goals/:id` |
| POST | `/lifeform/goals/:id/pause`, `/resume`, `/plan` |
| PATCH | `/lifeform/steps/:id` |
| POST | `/lifeform/reflect` |
| GET/POST | `/memories`, `PATCH/DELETE /memories/:id` |

## Monitoring

`GET /servers`, `GET /servers/:id`, `GET /servers/:id/metrics?minutes=`,
`GET /servers/:id/processes`, `GET /servers/:id/services`,
`GET /servers/:id/network`, `GET /servers/:id/storage`,
`POST /monitor/collect`

### CPU

CPU usage comes from a single sampler that reads the aggregate `cpu` line of
`/proc/stat` every `CPU_SAMPLE_INTERVAL_MS` (default 5000 ms) and diffs it against
the previous sample:

```
cpuUsage = (deltaTotal - deltaIdle) / deltaTotal * 100    // idle includes iowait
```

One owner means the same measured value and timestamp are served to the
dashboard, the Resources chart, the alert engine and the AI context — no screen
can inherit a different, shorter sampling window.

Fields returned with every CPU reading:

| Field | Meaning |
|---|---|
| `cpu.usagePercent` | 0–100, or `null` when the sample is not valid (first sample after start, counter reset, stale) |
| `cpu.capturedAt` | end of the measurement window (ms epoch) |
| `cpu.windowMs` | length of the window the percentage covers |
| `cpu.sampleAgeMs` | age of the sample at response time |
| `cpu.stale` | `true` when the sample is older than `CPU_SAMPLE_STALE_MS` |
| `cpu.reason` | `ok`, `warming-up`, `counter-reset`, `stale`, `stale-window`, `invalid-delta`, `proc-unavailable` |
| `cpu.cores` | logical CPU count (aggregate counters already cover all cores) |
| `cpu.loadAverage` | 1/5/15 min load, reported separately from CPU usage |

`GET /servers` → `aggregate` also carries `cpuAvg`, `cpuCapturedAt`, `cpuWindowMs`,
`cpuStale`, `metricsAgeMs` and the active `thresholds`.

Alerts are deduplicated by `(source, kind, node)` — `kind` is `cpu`, `memory`,
`disk` or `service:<name>` — and a breach must hold for `ALERT_SUSTAIN_MS` before
one is opened. Status changes are stored in `alert_events`; a resolved alert keeps
its history and can be opened again later.

## Alerts, approvals, notification

`GET /alerts`, `POST /alerts/:id/resolve`,
`GET /approvals`, `POST /approvals/:id/approve`, `POST /approvals/:id/reject`,
`POST /notifications/:id/read`

## Terminal & files

`POST /terminal/execute` `{command, timeoutMs}`,
`GET /terminal/tasks`, `GET /terminal/tasks/:id`, `POST /terminal/tasks/:id/cancel`

`GET /files?path=`, `GET /files/read?path=`, `POST /files/write`,
`POST /files/search`, `DELETE /files?path=`

## Settings & security

`GET/PUT /settings`, `GET/PUT /autonomy`,
`GET /api-keys`, `POST /api-keys`, `DELETE /api-keys/:id`,
`GET /plugins`, `PUT /plugins/:id`,
`GET /security/audit`,
`GET /events` (event yang terlewat saat perangkat offline),
`GET /health` (tanpa auth)

## Remote control (VPS)

Semua endpoint `/remote/*` **menolak API key** dan hanya menerima access token perangkat
yang sudah dipasangkan (`requireDeviceAuth`). Kredensial SSH/FTP dienkripsi AES-256-GCM
dengan kunci `data/remote.key` dan tidak pernah dikembalikan ke klien.

`GET /remote/servers`, `POST /remote/servers`, `PATCH /remote/servers/:id`,
`DELETE /remote/servers/:id`, `POST /remote/servers/:id/test`,
`POST /remote/servers/:id/trust` (pin host key secara eksplisit),
`GET /remote/servers/:id/fingerprint`

`GET /remote/files?serverId=&path=`, `GET /remote/files/read?serverId=&path=`,
`GET /remote/files/metadata?serverId=&path=`,
`POST /remote/files/upload` (streaming, `application/octet-stream`),
`GET /remote/files/download?serverId=&path=` (streaming),
`POST /remote/files/mkdir`, `POST /remote/files/rename`, `POST /remote/files/move`,
`POST /remote/files/copy`, `POST /remote/files/write`, `POST /remote/files/diff`,
`DELETE /remote/files?serverId=&path=&confirm=&recursive=`,
`GET /remote/files/search?serverId=&path=&q=`

`GET /remote/transfers`, `POST /remote/transfers/:id/cancel`

`GET /remote/terminal/sessions`, `POST /remote/terminal/sessions`,
`DELETE /remote/terminal/sessions/:id`

Path traversal dan symlink yang keluar dari root server ditolak; file sensitif
(`.env`, kunci privat, `credentials`, dsb.) ditandai `sensitive: true` dan
memerlukan konfirmasi eksplisit sebelum ditulis.

## WebSocket

`wss://ashimusic.biz.id/lifeform/ws?token=<accessToken>`

Klien mengirim:

```json
{"type":"subscribe","events":["server","lifeform","ai","alerts","approvals"]}
{"type":"ping","ts":1700000000000}
```

Grup: `server`, `lifeform`, `ai`, `alerts`, `approvals`, `notifications`,
`terminal`, `memory`, `remote`, atau `all`.

Grup `remote` mengirim `remote.terminal.output`, `remote.terminal.created`,
`remote.terminal.closed`, `remote.transfer.progress`, `remote.notice`; semuanya
difilter per `deviceId` sehingga perangkat lain tidak menerima isi terminal.

Klien remote dapat mengirim `{"type":"remote.terminal.input","sessionId":"…","data":"…"}`,
`{"type":"remote.terminal.resize","sessionId":"…","cols":80,"rows":24}`, dan
`{"type":"remote.terminal.interrupt","sessionId":"…"}`.

Event yang dikirim: `connection.ready`, `subscribed`, `pong`,
`server.metrics`, `server.status`, `lifeform.state`, `lifeform.awareness`,
`lifeform.reflection`, `lifeform.goal.updated`, `activity.created`,
`ai.stream`, `ai.status`, `ai.completed`, `ai.error`, `alert.created`,
`alert.updated`, `approval.created`, `approval.resolved`,
`notification.created`, `terminal.output`, `terminal.completed`,
`memory.created`.

## Error format

```json
{"error":{"code":"INVALID_TOKEN","message":"Token tidak valid atau sudah kedaluwarsa.","requestId":"..."}}
```

Rate limit: 300 request/menit per IP+rute (auth: 20 per 10 menit per IP).
