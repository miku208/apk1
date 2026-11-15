# Deployment

## 1. Backend

```bash
cd /root/mikuhost-lifeform
cp .env.example .env
node scripts/doctor.mjs
./scripts/lifeform.sh start
pm2 status mikuhost-lifeform
```

`scripts/lifeform.sh start` menjalankan PM2 dengan nama `mikuhost-lifeform`,
`--max-memory-restart 512M`, logrotate (module `pm2-logrotate` sudah terpasang),
dan `pm2 save` agar persisten setelah reboot.

Environment penting (`.env`):

```ini
HOST=127.0.0.1      # jangan 0.0.0.0; akses publik lewat nginx
PORT=8888
PUBLIC_BASE_URL=https://ashimusic.biz.id
BASE_PATH=/lifeform
MIKUHOST_AGENT_HOME=/root/mikuhost-agent
LIFEFORM_WORKSPACE=/root
OWNER_PASSWORD=            # opsional; pairing code tetap tersedia
```

## 2. Nginx (SUDAH dipasang — aditif)

Trafik publik `ashimusic.biz.id` masuk ke nginx **port 3838**
(`/etc/nginx/conf.d/mikuhost-api-ashimusic.conf`) lalu diteruskan ke
`127.0.0.1:13838` (mikuhost-api). Blok `location /lifeform/` ditambahkan di file
itu; tidak ada location existing yang diubah. Backup otomatis tersimpan sebagai
`mikuhost-api-ashimusic.conf.bak.<timestamp>`.

Blok yang dipasang:

```nginx
    # MikuHost Lifeform backend (127.0.0.1:8888)
    location /lifeform/ {
        proxy_pass http://127.0.0.1:8888/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        # streaming AI butuh timeout panjang
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        proxy_buffering off;
    }
```

`proxy_pass` berakhiran `/` agar prefix `/lifeform` dipotong sebelum diteruskan;
backend juga menerima prefix utuh (`BASE_PATH`) sehingga keduanya valid.

WebSocket memakai host yang sama: `wss://ashimusic.biz.id/lifeform/ws?token=...`
(sudah diuji: `connection.ready`, `subscribed`, `server.metrics`).

## 3. TLS

Sertifikat domain sudah dikelola vhost existing. Setelah blok di atas ditambahkan,
tidak perlu konfigurasi TLS tambahan. Verifikasi:

```bash
curl -sI https://ashimusic.biz.id/lifeform/health
```

## 4. Firewall

- Port 8888 **tidak** dibuka ke publik (hanya `127.0.0.1`).
- Port 80/443 tetap seperti konfigurasi existing.

## 5. Setelah deploy

```bash
npm run pair                      # kode pairing
curl -s localhost:8888/lifeform/api/v1/health
pm2 logs mikuhost-lifeform --lines 50
```

## 6. Rollback

```bash
pm2 stop mikuhost-lifeform && pm2 delete mikuhost-lifeform
# hapus blok location /lifeform/ dari vhost, nginx -t && nginx -s reload
```

Database dan log tetap di `data/` sehingga tidak ada data yang hilang.
