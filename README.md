<div align="center">
  <img src="public/logo_cybersensei_maskot.png" alt="CyberSensei Logo" width="150" height="150" />
  <h1>🛡️ CyberSensei</h1>
  <p><strong>Deteksi Penipuan Digital &middot; Powered by AI (Local Engine)</strong></p>
  <p>Dikembangkan untuk <b>#JuaraVibeCoding</b> 2026</p>
</div>

## 📌 Apa itu CyberSensei?

**CyberSensei** adalah mesin analisis keamanan siber *client-side* yang berfungsi mendeteksi modus penipuan modern (scam, phishing, vishing, sextortion) dalam bahasa Indonesia secara *real-time*.

Aplikasi ini menggunakan pendekatan **Multi-Layered Detection**:
1. **Regex Pattern Matching**: Mendeteksi pola kalimat psikologis yang sering digunakan penipu (urgensi, ancaman, pamer kekayaan).
2. **Fuzzy Search (AI)**: Mencocokkan teks dengan 80+ *Threat Intelligence Database* lokal Indonesia (pinjol, jastip tiket, babi ngepet digital/pig butchering).
3. **IDN Homograph Analysis**: Mendeteksi serangan *spoofing* domain tingkat lanjut (contoh: `gооgle.com` dengan huruf Cyrillic 'о').
4. **URL Obfuscation Engine**: Mendeteksi tautan berbahaya dan manipulasi spasi (*zero-width joiner*).

## ✨ Fitur Utama
*   🚀 **Analisis < 1 Detik**: Sepenuhnya berjalan di peramban pengguna (*Client-Side Engine*), tanpa *latency* API *backend*.
*   🔒 **Privacy First**: Data tidak pernah dikirim ke *server* manapun. Pesan rahasiamu tetap rahasia.
*   🎮 **Mini-Kuis Edukasi**: Fitur interaktif untuk melatih kepekaan pengguna terhadap pesan penipuan.
*   📱 **Responsive & Accessible**: Nyaman digunakan di ponsel maupun laptop.

## 🛠️ Spesifikasi Teknis
*   **Frontend Framework**: React 18 (Vite) + TypeScript.
*   **Styling**: Tailwind CSS.
*   **AI Search Engine**: Fuse.js (Lightweight Fuzzy-search).
*   **Icons & Animation**: Lucide React & Motion.
*   **Deployment**: Docker + Nginx (Dioptimalkan untuk Google Cloud Run).

## 💡 Cara Penggunaan

1. **Buka Aplikasi**: Akses tautan aplikasi atau jalankan di *localhost*.
2. **Pilih Mode**: Pilih jenis input apakah berupa **Pesan/Email** teks panjang, atau **Tautan (Web/Link)**.
3. **Tempelkan Pesan**: Salin (*copy*) pesan mencurigakan dari WhatsApp/Email Anda dan tempelkan (*paste*) ke dalam kotak yang disediakan.
4. **Mulai Analisis**: Klik tombol **Periksa Sekarang**.
5. **Baca Hasil**: Dalam kurang dari sedetik, CyberSensei akan memberikan vonis (Aman, Mencurigakan, atau Berbahaya) beserta daftar "Tanda Bahaya" (Red Flags) yang ditemukannya.
6. **Simpan Bukti**: Jika perlu, gunakan tombol "Simpan Tangkapan Layar" (Ikon Share) untuk membagikan hasil analisis ke orang tua atau kerabat Anda.

## 💻 Panduan Instalasi Lokal

1. Pastikan Anda telah menginstal **Node.js** (v18+ direkomendasikan).
2. Kloning repositori ini dan masuk ke direktori:
   ```bash
   git clone <repo-url>
   cd cybersensei
   ```
3. Instal dependensi:
   ```bash
   npm install
   ```
4. Jalankan *server* pengembangan lokal:
   ```bash
   npm run dev
   ```
5. Buka `http://localhost:3000` di peramban Anda.

## ☁️ Panduan Deployment (Google Cloud Run)

CyberSensei dilengkapi dengan `Dockerfile` dan konfigurasi Nginx ringan yang dioptimalkan untuk **Google Cloud Run**.

1. **Pastikan Anda telah menginstal Google Cloud SDK (`gcloud`).**
2. Lakukan login ke akun GCP Anda:
   ```bash
   gcloud auth login
   gcloud config set project <PROJECT_ID>
   ```
3. Lakukan *deploy* langsung dari *source code*:
   ```bash
   gcloud run deploy cybersensei \
     --source . \
     --region asia-southeast2 \
     --allow-unauthenticated
   ```
4. Tunggu beberapa menit, dan aplikasi Anda akan *live* di *URL* yang diberikan oleh Cloud Run!

---
*Dibuat dengan ❤️ untuk menciptakan ruang digital Indonesia yang lebih aman.*
