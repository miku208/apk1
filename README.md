# MikuHost Lifeform — APK

Aplikasi Android untuk mengendalikan **MikuHost Lifeform**, AI operator yang berjalan
sebagai service di VPS.

| | |
|---|---|
| Versi | 1.0.0 (versionCode 1) |
| Package | `id.mikuhost.lifeform` |
| Min Android | 8.0 (API 26) |
| Target SDK | 34 |
| Ukuran | ±12 MB |
| Ditandatangani | Ya (APK Signature Scheme v2) |

## Unduh

- [MikuHost-Lifeform-1.0.0.apk](https://github.com/miku208/apk1/raw/main/MikuHost-Lifeform-1.0.0.apk)
- Checksum: lihat `SHA256SUMS.txt`

```bash
sha256sum -c SHA256SUMS.txt
```

## Instalasi

1. Unduh APK di atas, lalu buka di perangkat Android.
2. Izinkan "Install unknown apps" untuk browser/file manager yang dipakai.
3. Buka aplikasi **MikuHost Lifeform**.

## Menghubungkan ke backend

Aplikasi ini **tidak** menyimpan API key provider AI. Semua pekerjaan AI berjalan
di VPS; aplikasi hanya menjadi client.

1. Di VPS, buat kode pairing 6 digit:

   ```bash
   cd /root/mikuhost-lifeform && npm run pair
   ```

2. Di aplikasi, isi **Backend URL**:

   ```
   https://ashimusic.biz.id/lifeform
   ```

3. Masukkan kode pairing → **Pair device**.

Kode berlaku 10 menit dan hanya bisa dipakai sekali. Device bisa dicabut dari
**Settings → Akun & device**.

## Fitur

- **Home** — CPU/RAM/Disk/Server dari metrik asli, status lifeform, alerts, aktivitas terbaru
- **Resources** — grafik historis 1 jam / 6 jam / 24 jam / 7 hari, proses teratas, services (PM2/Docker/systemd)
- **Lifeform** — chat streaming dengan AI, approval queue, tujuan, memori, refleksi terakhir
- **Activity** — timeline dengan filter AI / Server / Security / Warning / Error
- **Settings** — backend URL, provider & model, autonomy level 1–3, identitas AI, manajemen device

## Keamanan

- Token disimpan di EncryptedSharedPreferences.
- API key provider tidak pernah ada di APK.
- Tindakan berisiko (hapus file, firewall, SSH, shutdown, dll.) selalu masuk
  approval queue di backend.
- Autonomy Level 1 (default) bersifat read-only.
