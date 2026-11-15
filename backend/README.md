# MikuHost Lifeform

AI operator yang hidup sebagai service di VPS, dikendalikan dari aplikasi Android.
Backend ini **memakai ulang engine `mikuhost-agent`** (provider, model registry,
credential store, agent loop, tools) — tidak ada AI engine kedua.

- Backend: Node 22 + `node:http` + `ws` + SQLite (`node:sqlite`), port **8888**
- Android: Kotlin + Jetpack Compose (Material 3), dark forest green
- Domain: `https://ashimusic.biz.id` dengan prefix `/lifeform` (lihat catatan konflik di bawah)

## Domain dan nginx

`ashimusic.biz.id` sudah dipakai aplikasi lain, jadi Lifeform ditambahkan secara
**aditif** dengan prefix `/lifeform` — tidak ada location existing yang diubah.

Trafik publik masuk ke nginx port 3838 → `127.0.0.1:13838` (mikuhost-api).
Blok `location /lifeform/` dipasang di `/etc/nginx/conf.d/mikuhost-api-ashimusic.conf`
dan diteruskan ke `127.0.0.1:8888`.

| URL | Status |
|---|---|
| `https://ashimusic.biz.id/lifeform/health` | 200 |
| `wss://ashimusic.biz.id/lifeform/ws` | terverifikasi (subscribe + `server.metrics`) |
| `https://ashimusic.biz.id/` | tetap 200 (tidak berubah) |

Backup konfigurasi sebelum perubahan: `mikuhost-api-ashimusic.conf.bak.<timestamp>`
di direktori yang sama.

## Mulai cepat

```bash
cd /root/mikuhost-lifeform
cp .env.example .env          # sesuaikan bila perlu
node scripts/doctor.mjs       # cek engine, key, DB, port
./scripts/lifeform.sh start   # jalankan via PM2 (nama: mikuhost-lifeform)
npm run pair                  # buat kode pairing untuk Android
```

Health check:

```bash
curl http://127.0.0.1:8888/health
```

## Struktur

```
src/
  server.mjs            HTTP + WebSocket bootstrap, routing, auth middleware
  config.mjs            semua konfigurasi dari environment
  db.mjs                SQLite + migrasi bertahap (26 tabel)
  auth.mjs              pairing code, access/refresh token, device, audit
  http.mjs              router, body parser, rate limit, error handler
  ws.mjs                satu endpoint /ws, subscription per grup event
  events.mjs            event bus + activity/alert/notification + lifeform state
  ai/
    engine.mjs          adapter ke mikuhost-agent (loop, provider, model, tools)
    vps-tools.mjs       tool VPS nyata (metrics, proses, pm2, docker, log, alert)
    runtime-data.mjs    akses snapshot live untuk tool
  monitor/
    system.mjs          baca /proc, df, ps, pm2, docker, ss
    collector.mjs       sampling periodik, simpan metrik, threshold → alert
  lifeform/
    identity.mjs        identitas, memori, goals, task steps
    core.mjs            awareness, planner, reflection, scheduler
  security/
    policy.mjs          3 level autonomy, klasifikasi risiko, approval queue
    terminal.mjs        eksekusi shell + timeout + audit
  routes/               auth, ai, lifeform, monitor, system
scripts/                lifeform.sh, backup.sh, pair.mjs, doctor.mjs
android/                project Android (Compose)
docs/                   DEPLOYMENT.md, API.md
```

## Database

SQLite di `data/lifeform.db` (WAL). Migrasi dijalankan otomatis saat start dan
dicatat di `schema_migrations`. Tabel utama: `users`, `devices`, `tokens`,
`pairing_sessions`, `conversations`, `messages`, `lifeform_identity`,
`lifeform_state`, `memories`, `goals`, `tasks`, `task_steps`, `server_nodes`,
`server_metrics`, `services`, `alerts`, `activities`, `approvals`,
`audit_logs`, `api_keys`, `plugin_registry`, `settings`, `notifications`,
`terminal_tasks`.

## Autonomy

| Level | Nama | Boleh |
|---|---|---|
| 1 | Observe | baca metrik/log, analisis, laporan. Tidak mengubah apa pun |
| 2 | Operate | tindakan rutin pada service yang dikenal (restart pm2, health check) |
| 3 | Autonomous | pekerjaan multi-langkah; tindakan berisiko tetap lewat approval |

Tindakan destruktif (rm -rf pada root, mkfs, firewall, sshd, DROP TABLE,
shutdown, dsb.) selalu masuk approval queue, apa pun levelnya.

## Build APK

```bash
cd android
/root/.gradle-dist/gradle-8.7/bin/gradle assembleDebug   # app-debug.apk
/root/.gradle-dist/gradle-8.7/bin/gradle assembleRelease # app-release.apk (signed)
```

Release memakai `android/keystore.properties` + `android/keystore/lifeform-release.jks`
(keduanya gitignored). **Simpan keystore itu**: tanpa file tersebut, update APK
tidak bisa ditandatangani dengan identitas yang sama.

APK rilis dipublikasikan di <https://github.com/miku208/apk1>:
`MikuHost-Lifeform-1.0.0.apk` (12 MB, sha256 `8b25a0bb…f448d2b`).

SDK: `/opt/android-sdk` (platform 34, build-tools 34.0.0), Java 17.
`local.properties` berisi `sdk.dir=/opt/android-sdk`.

Isi `Settings → Backend URL` di aplikasi dengan
`https://ashimusic.biz.id/lifeform` (atau `http://IP:8888` untuk uji lokal;
catatan: manifest memblokir cleartext, jadi gunakan HTTPS untuk perangkat nyata).

## Backup & restore

```bash
./scripts/backup.sh            # backups/lifeform-YYYYmmdd-HHMMSS.tar.gz
# restore
pm2 stop mikuhost-lifeform
tar -xzf backups/lifeform-....tar.gz -C data
pm2 start mikuhost-lifeform
```

## Log

```bash
./scripts/lifeform.sh logs     # pm2 logs
tail -f data/logs/lifeform-$(date +%F).log
./scripts/lifeform.sh logs; curl -s localhost:8888/health
```
