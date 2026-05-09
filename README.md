<div align="center">
  <img src="apps/web/public/logo_cybersensei_maskot.png" alt="CyberSensei Logo" width="150" height="150" />
  <h1>🛡️ CyberSensei</h1>
  <p><strong>Deteksi Penipuan Digital &middot; Powered by AI</strong></p>
  <p>Dikembangkan untuk <b>#JuaraVibeCoding</b> 2026 oleh <b>Rizal TH</b></p>

  <br/>

  ![React](https://img.shields.io/badge/React_19-61DAFB?logo=react&logoColor=white&style=flat-square)
  ![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white&style=flat-square)
  ![Node.js](https://img.shields.io/badge/Node.js-339933?logo=nodedotjs&logoColor=white&style=flat-square)
  ![Express](https://img.shields.io/badge/Express.js-000000?logo=express&logoColor=white&style=flat-square)
  ![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white&style=flat-square)
  ![Cloud Run](https://img.shields.io/badge/Cloud_Run-4285F4?logo=googlecloud&logoColor=white&style=flat-square)
</div>

<div align="center">
  <br/>
  <img src="apps/web/public/screenshot_landing.png" alt="CyberSensei - Tampilan Utama" width="800" />
  <br/>
  <em>Tampilan utama CyberSensei — tempel pesan mencurigakan, dapatkan analisis instan.</em>
  <br/><br/>
</div>

---

## 📌 Apa itu CyberSensei?

**CyberSensei** adalah asisten keamanan siber yang mendeteksi modus penipuan digital modern (scam, phishing, vishing, sextortion, deepfake, pig butchering, dll.) dalam bahasa Indonesia. Tersedia dalam dua bentuk antarmuka: **Web Dashboard** interaktif dan **Chatbot Agent** (Telegram/WhatsApp) untuk respon instan di genggaman Anda.

Dibangun dengan arsitektur **Monorepo**, CyberSensei membagikan mesin analisis ancaman cerdasnya (`@cybersensei/core`) langsung ke Front-end React (`@cybersensei/web`) dan Back-end Bot Express (`@cybersensei/bot`), lalu di-deploy sebagai **Satu Service Tunggal** di Google Cloud Run.

---

## ✨ Fitur Utama & Interaksi Chatbot

Selain web dashboard interaktif, CyberSensei kini dilengkapi **Chatbot Agent**.

### Bagaimana Cara Pengguna Berinteraksi dengan Chatbot?
Sangat mudah! Pengguna berinteraksi dengan bot layaknya mengirim pesan ke teman biasa:

1. **Memulai (Start)**
   - Pengguna: `/start`
   - Bot: Menyapa dan memperkenalkan diri sebagai agen CyberSensei, serta menginstruksikan cara penggunaan.
2. **Menganalisis Pesan atau Link (Langsung Forward/Ketik)**
   - Pengguna *meneruskan (forward)* pesan penipuan dari chat orang lain, ATAU mengetik/menempel (paste) langsung teks/link ke dalam chat bot.
   - Contoh pengguna: *"Selamat Anda memenangkan Rp 100 Juta dari Shopee! Klik link ini: http://shopee-hadiah.com"*
3. **Respon Instan (Error Handler Terjamin)**
   - Bot: Akan langsung merespon "🔍 Sedang menganalisis pesan Anda..." agar pengguna tahu pesannya diterima.
   - Jika berhasil: Bot akan mengedit pesannya menjadi laporan lengkap yang berisi tingkat bahaya, penjelasan, dan red flags.
   - Jika terjadi *error/crash* (Error Handler): Bot akan merespon secara elegan (graceful failure) "❌ Maaf, terjadi kesalahan saat menganalisis pesan. Silakan coba lagi nanti."
4. **Anti-Spam di Grup Chat**
   - Jika bot dimasukkan ke dalam **Grup Telegram**, bot *tidak akan* menganalisis setiap pesan yang lewat (mencegah spam/bising). Bot **HANYA** akan merespon jika **di-mention langsung** (contoh: `@cybersensei_bot tolong cek ini`) atau jika pengguna me-*reply* pesan milik bot.

---

## 🏗️ Arsitektur Proyek (Monorepo) & Keputusan Desain

```text
cybersensei/
├── apps/
│   ├── bot/       # Backend Node.js/Express (Telegram/WA Bot & melayani Web Static Files)
│   └── web/       # Frontend React (Vite & TailwindCSS)
├── core/          # Engine Deteksi AI & Database Threat Intelligence (Dipakai Bot & Web)
├── Dockerfile     # Multi-stage build menyatukan bot & web ke dalam 1 image
└── package.json   # Monorepo Workspace Root
```

**Evaluasi Arsitektur (Mengapa Tidak Ada Fitur Konfigurasi API LLM/BYOM):**
Awalnya direncanakan fitur Bring Your Own Model (BYOM) dimana pengguna memasukkan API Key LLM eksternal. Namun, **dievaluasi bahwa ini tidak ideal untuk Google Cloud Run.** Cloud Run bersifat *stateless* dan *scale-to-zero*, sehingga menyimpan state konfigurasi lokal (In-Memory atau File JSON) akan hilang saat server restart. Oleh karena itu, fitur BYOM dibatalkan demi mempertahankan performa super cepat, hemat memori, dan kemudahan deployment murni tanpa perlu database eksternal. Seluruh analisis dijalankan murni, instan, dan aman oleh *engine local* (`@cybersensei/core`) yang mengombinasikan *Fuzzy Search* dan algoritma heuristik secara efisien.

---

## 💻 Panduan Menjalankan & Deployment

### 1. Menjalankan di Lokal (Development)

Pastikan Node.js v20+ terinstall.
```bash
# Install semua package monorepo
npm install

# Build semua package
npm run build

# Menjalankan Web Frontend
npm run dev:web  # Buka di http://localhost:3000

# Menjalankan Bot Backend
# (Pastikan sudah buat file .env berisi TELEGRAM_BOT_TOKEN)
npm run start:bot
```

### 2. Panduan Set-up Chatbot
**Untuk Telegram:**
1. Buka Telegram, cari **@BotFather**, ketik `/newbot`.
2. Dapatkan token API.
3. Masukkan ke file `.env` (Lokal) atau Environment Variables (Cloud Run):
   `TELEGRAM_BOT_TOKEN=token_anda`
4. **SANGAT PENTING (Untuk Cloud Run):** Karena Cloud Run bisa *scale-to-zero*, metode Long-Polling tidak efektif. Tambahkan Environment Variable `WEBHOOK_DOMAIN` berisi URL Cloud Run Anda (misal: `https://cybersensei-633534264127.asia-southeast2.run.app`). Server otomatis akan menggunakan arsitektur Webhook jika variable ini terdeteksi!

**Untuk WhatsApp (Template Disediakan):**
1. Buat aplikasi tipe *WhatsApp* di Meta for Developers.
2. Setup *Webhook* menuju URL Cloud Run Anda: `https://[URL-CLOUDRUN]/api/whatsapp/webhook`
3. Masukkan token verifikasi yang Anda buat ke dalam env: `WHATSAPP_VERIFY_TOKEN=token_bebas_anda`

### 3. Deployment Sekali Jalan ke Google Cloud Run

Proyek ini telah dikonfigurasi menggunakan **Multi-Stage Dockerfile**. Proses deploy akan mem-build *Core*, mem-build *Web*, mem-build *Bot*, dan akhirnya menjalankan Server Express (Bot) yang sekaligus melayani file *Frontend Web* di port yang sama!

Sesuai permintaan, gunakan perintah ini di terminal yang sudah terautentikasi gcloud (ganti `<TOKEN_ANDA>` dengan token dari BotFather dan `<URL_CLOUDRUN>` dengan URL asli dari Cloud Run Anda, misalnya `https://cybersensei-633534264127.asia-southeast2.run.app`):

```bash
gcloud run deploy cybersensei \
  --source . \
  --region asia-southeast2 \
  --allow-unauthenticated \
  --set-env-vars="TELEGRAM_BOT_TOKEN=<TOKEN_ANDA>,WEBHOOK_DOMAIN=<URL_CLOUDRUN>"
```
*(Atau, Anda dapat melakukan deploy tanpa `--set-env-vars` terlebih dahulu, lalu memasukkan variabel environment secara manual di menu "Edit & Deploy New Revision" -> "Variables & Secrets" di Console Google Cloud).*

---

## 🔒 Keamanan, Performa & Privasi

- ✅ **Error Handling Kuat** — Jika terjadi kesalahan tak terduga pada server, bot merespon dengan fallback pesan secara *graceful* (elegan) sehingga pengguna tidak dibiarkan menggantung, dan crash terisolasi tidak mematikan server.
- ✅ **Rate Limiting & Anti-Spam** — Bot menerapkan *cooldown* memori (2 detik antar pesan per pengguna) dan membatasi API web sebanyak 100 *request* per menit. Ini mencegah *race condition*, eksploitasi spammer, dan menjaga performa bot tetap secepat kilat (beban server minimal). Memori cooldown dibersihkan berkala untuk mencegah *memory leak*.
- ✅ **Input Truncation** — Otomatis memotong input teks panjang (>10.000 karakter) untuk mencegah serangan *Memory Exhaustion* dan ReDoS (Regular Expression Denial of Service).
- ✅ **Proteksi Keamanan Web (Helmet)** — Frontend disajikan melalui bot backend yang menggunakan modul keamanan modern seperti *Helmet.js* untuk injeksi Content Security Policy (CSP) dan perlindungan Header HTTP.
- ✅ **Satu Kontainer Efisien** — Hemat biaya cloud, UI Web dan API Bot disatukan di 1 kontainer Cloud Run. Cocok untuk skalabilitas Cloud Run yang otomatis mati-nyala menyesuaikan *traffic*.
- ✅ **Data Privacy** — Aplikasi **TIDAK** menyimpan riwayat chat maupun nomor pengguna ke dalam *database* permanen. Semuanya dianalisis dan dibuang dari memori sesudahnya (Zero-Data-Retention).

---

<div align="center">
  <p><i>Dibuat dengan ❤️ untuk menciptakan ruang digital Indonesia yang lebih aman.</i></p>
  <p><strong>© 2026 CyberSensei — Rizal TH</strong></p>
</div>
