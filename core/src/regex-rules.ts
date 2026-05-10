// ============================================================
// REGEX RULES — Modular regex-based detection rules
// ============================================================

import { RegexRule } from './types.js';

// ============================================================
// WEIGHTED SCORING SYSTEM
// ============================================================
export const WEIGHT_MULTIPLIERS: Record<string, number> = {
  critical: 1.5,
  high: 1.2,
  moderate: 1.0,
};

export const REGEX_RULES: RegexRule[] = [
  // === CRITICAL WEIGHT ===
  {
    id: 'otp_request',
    label: 'Permintaan OTP mencurigakan — tanda potensi pembajakan akun.',
    regex: /(kirim[^\n]{0,20}otp|otp[^\n]{0,5}(nya|mu|kamu|anda)|salah[^\n]{0,15}(kirim|masuk|input)[^\n]{0,10}(otp|kode|nomor)|butuh[^\n]{0,10}(otp|kode verifikasi)|tolong[^\n]{0,20}(kode|otp|verifikasi)|bagikan[^\n]{0,10}(otp|kode)|kode[^\n]{0,5}(otp|verifikasi)[^\n]{0,15}masuk|kode[^\n]{0,10}(6|enam)[^\n]{0,10}digit|pin[^\n]{0,10}verifikasi|masuk[^\n]{0,10}(kode|otp)[^\n]{0,10}(sms|hp|wa)|kasih[^\n]{0,10}(tau|tahu)[^\n]{0,10}(kode|otp)|share[^\n]{0,10}kode|kode[^\n]{0,10}nya[^\n]{0,5}(berapa|apa)|dong[^\n]{0,5}(kasih|kirim)[^\n]{0,10}kode|kode[^\n]{0,10}(masuk|nyangkut)[^\n]{0,10}(ke|di)[^\n]{0,10}(hp|wa|sms)|verif[^\n]{0,15}(otp|kode|pin|akun))/gi,
    score: 7,
    weight_category: 'critical'
  },
  {
    id: 'vishing',
    label: 'Mengaku aparat hukum dan meminta transfer uang — penipuan vishing berbahaya.',
    regex: /(penyidik|bareskrim|kejaksaan|jaksa|polri|polda|polres|polisi|pengadilan|tipikor|narkoba|tersangka)[^\n]{0,80}(transfer|jaminan|uang|rekening|bayar)|rekening[^\n]{0,30}(terlibat|terkait)[^\n]{0,30}(pencucian|penipuan|kejahatan)/gi,
    score: 7,
    weight_category: 'critical'
  },
  {
    id: 'sextortion',
    label: 'Ancaman pemerasan video/foto intim (Sextortion) — JANGAN transfer, laporkan ke polisi.',
    regex: /(video[^\n]{0,15}(call|mu|kamu)[^\n]{0,15}(rekam|sebar|viral)|(foto|video)[^\n]{0,10}(bugil|telanjang|intim)[^\n]{0,15}(sebar|kirim|viral)|bayar[^\n]{0,15}(atau|sebelum)[^\n]{0,15}(video|foto|malu)|aku (punya|sudah)[^\n]{0,15}(video|foto)[^\n]{0,10}(call|bugil|rekam))/gi,
    score: 8,
    weight_category: 'critical'
  },
  {
    id: 'virtual_kidnapping',
    label: 'Klaim penculikan/kecelakaan anak — modus Virtual Kidnapping. Verifikasi langsung ke anak/keluarga.',
    regex: /(anak (anda|mu)[^\n]{0,15}(diculik|disandera|di tangan|kecelakaan)|transfer (tebusan|uang)[^\n]{0,15}(atau|sebelum)[^\n]{0,10}(anak|celaka)|jangan (telepon|hubungi)[^\n]{0,10}(polisi|siapapun)[^\n]{0,15}anak|bayar[^\n]{0,15}tebusan)/gi,
    score: 8,
    weight_category: 'critical'
  },
  {
    id: 'money_mule',
    label: 'Ajakan menyewakan/menggunakan rekening — ini adalah modus money mule (pencucian uang) yang berisiko pidana.',
    regex: /(tampung[^\n]{0,15}uang|sewa[^\n]{0,10}rekening|jual[^\n]{0,10}rekening|teruskan[^\n]{0,10}dana|rekening penampung)/gi,
    score: 8,
    weight_category: 'critical'
  },
  {
    id: 'advance_fee_heritage',
    label: 'Klaim warisan/dana besar yang meminta biaya administrasi — modus penipuan Advance Fee.',
    regex: /(warisan|deposito[^\n]{0,15}luar negeri|biaya notaris[^\n]{0,15}warisan|pajak warisan|pewaris sah)/gi,
    score: 8,
    weight_category: 'critical'
  },
  {
    id: 'qris_overlay',
    label: 'Stiker QRIS palsu ditempel di merchant — periksa nama merchant sebelum bayar.',
    regex: /(qris.*tempel|stiker.*qr|qr.*ditimpa|qr.*overlay|scan.*qris.*palsu|ganti.*qris)/gi,
    score: 6,
    weight_category: 'critical'
  },
  {
    id: 'voice_cloning',
    label: 'Pola Voice Cloning Scam — suara bisa dipalsukan AI. Jangan transfer sebelum verifikasi ulang.',
    regex: /(suara[^\n]{0,15}mirip[^\n]{0,15}(keluarga|anak|istri|suami|teman)|voice[^\n]{0,10}cloning|suara asli tapi nomor beda|(mama|papa|anak|suami|istri|kakak|adik)[^\n]{0,15}ini aku[^\n]{0,30}(butuh|tolong|minta)[^\n]{0,15}(uang|transfer|kirim)|ini (anak|suami|istri|papa|mama)[^\n]{0,15}nomor[^\n]{0,10}(baru|beda|lain)|kecelakaan[^\n]{0,30}(transfer|kirim uang)[^\n]{0,30}(jangan|rahasia|cerita))/gi,
    score: 8,
    weight_category: 'critical'
  },
  {
    id: 'deepfake_invest',
    label: 'Video promosi investasi dari tokoh publik — kemungkinan deepfake AI.',
    regex: /(video[^\n]{0,10}(presiden|prabowo|jokowi|artis|selebriti)[^\n]{0,15}(dukung|rekomendasikan|endors)|deepfake[^\n]{0,10}(investasi|trading|kripto))/gi,
    score: 8,
    weight_category: 'critical'
  },
  {
    id: 'gov_impersonation',
    label: 'Tuduhan pelanggaran hukum/pencucian uang dari instansi — modus pemerasan.',
    regex: /(kominfo|ojk|polisi|dukcapil|pajak)[^\n]{0,30}(iklan ilegal|pencucian uang|tppu|pelanggaran|blokir nomor|pidana)/gi,
    score: 6,
    weight_category: 'critical'
  },
  {
    id: 'apk_install',
    label: 'Suruhan untuk menginstal file/aplikasi asing (.APK) — bisa menyadap OTP dan menguras M-Banking.',
    regex: /(\.apk|buka aplikasi|install aplikasi|download apk|file apk)/gi,
    score: 7,
    weight_category: 'critical'
  },
  {
    id: 'fake_dukcapil_apk',
    label: 'Pembaruan data KTP/KK via APK — Dukcapil tidak pernah mengirim APK. Modus ini bisa menguras M-Banking.',
    regex: /(pembaruan data|update data|sinkronisasi)[^\n]{0,20}(kk|ktp|dukcapil|identitas)[^\n]{0,20}(apk|aplikasi|link)/gi,
    score: 7,
    weight_category: 'critical'
  },
  {
    id: 'remote_access_scam',
    label: 'Permintaan instalasi aplikasi remote access — sangat berbahaya, penipu bisa mengintip layar dan OTP Anda.',
    regex: /(anydesk|teamviewer|bagikan layar|screen share|berbagi layar|remote access)/gi,
    score: 7,
    weight_category: 'critical'
  },
  {
    id: 'gambling',
    label: 'Ajakan bermain judi online (Slot/WD/JP) — ilegal di Indonesia dan dirancang untuk menguras uangmu.',
    regex: /(main slot[^\n]{0,10}(pasti menang|gacor|maxwin)|deposit[^\n]{0,10}(untuk|bisa)[^\n]{0,10}(main|slot|maxwin)|situs judi|slot gacor|rtp[^\n]{0,10}(tinggi|hari ini)|agen judi|togel online|modal[^\n]{0,15}(ribu|rbu|k)[^\n]{0,15}(jp|wd|jackpot|maxwin|juta|cair)|\b(jp|wd|withdraw)\b[^\n]{0,15}(\d+|puluhan)[^\n]{0,10}(juta|jt|k|ribu))/gi,
    score: 7,
    weight_category: 'critical'
  },
  {
    id: 'joki_pinjol',
    label: 'Tawaran joki pinjol/galbay — sangat berisiko pencurian data pribadi.',
    regex: /(joki pinjol|konsultan galbay|hapus utang pinjol|stop penagihan dc|hapus data pinjol)/gi,
    score: 5,
    weight_category: 'critical'
  },
  {
    id: 'pig_butchering',
    label: 'Modus "Salah Sambung" yang berujung pada penipuan investasi (Pig Butchering Scam) — kerugian terbesar secara global.',
    regex: /(maaf salah sambung|ini nomor[^\n]{0,10}bukan|simpan nomor saya|kita bisa jadi teman|trading kripto bareng|bimbingan trading|profit konsisten|meta online)/gi,
    score: 8,
    weight_category: 'critical'
  },
  // === HIGH WEIGHT ===
  {
    id: 'shortlink',
    label: 'Menggunakan Tautan Singkat/Pendek — situs penipu sering memakainya untuk sembunyikan URL phishing.',
    regex: /(s\.id|bit\.ly|tinyurl\.com|cutt\.ly|wa\.me|t\.me|rb\.gy|is\.gd|v\.ht|shorturl\.at|dwz\.id|lynk\.id)[^\s]*/gi,
    score: 4,
    weight_category: 'high'
  },
  {
    id: 'urgency_fear',
    label: 'Klaim mendesak dan menakut-nakuti — taktik penipu agar korban tidak berpikir jernih.',
    regex: /(diblokir|permanen|segera|dalam \d+ jam|terblokir|melanggar|dalam 24 jam|hari ini juga|sekarang juga|darurat|urgent|segera bertindak|batas waktu|jangan tunda|sebelum terlambat|waktu terbatas|buruan|gas\s|langsung\s|cepetan)/gi,
    score: 4,
    weight_category: 'high'
  },
  {
    id: 'recovery_scam',
    label: 'Tawaran pemulihan dana berbayar — kemungkinan besar Recovery Scam.',
    regex: /(pulihkan|kembalikan dana|tim pemulihan|ojk recovery|cairkan dana)[^\n]{0,50}(administrasi|bayar|transfer)/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'typosquatting',
    label: 'Domain mirip brand resmi (typosquatting) — kemungkinan situs phishing.',
    regex: /(tok0pedia|sh0pee|bca-|bri-|mandiri-|gojek-|grab-|google-|facebook-|instagram-|netflix-|secure-|login-|verify-)\S*\.(com|co\.id|net|org)/gi,
    score: 6,
    weight_category: 'high'
  },
  {
    id: 'pinjol_ilegal',
    label: 'Tawaran pinjaman online mencurigakan — pinjol legal tidak minta biaya di muka.',
    regex: /(pinjaman[^\n]{0,15}cair|dana cepat[^\n]{0,15}tanpa|biaya (asuransi|verifikasi|admin)[^\n]{0,20}(pinjaman|cair)|tanpa bi checking|plafon[^\n]{0,10}\d+\s*juta)/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'sim_reg_phishing',
    label: 'Permintaan NIK/KK/KTP via pesan — data identitas bisa disalahgunakan.',
    regex: /(kartu[^\n]{0,15}(diblokir|dinonaktifkan)[^\n]{0,15}registrasi|kirim[^\n]{0,10}(nik|kk)[^\n]{0,15}(aktivasi|verifikasi|registrasi)|registrasi ulang[^\n]{0,10}(kartu|sim)|kirim foto ktp)/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'id_theft',
    label: 'Permintaan data identitas (NIK/KK/KTP) via pesan — potensi pencurian identitas.',
    regex: /(kirim[^\n]{0,10}(nik|nomor kk|foto ktp|selfie ktp)|butuh[^\n]{0,10}(nik|kk|ktp)[^\n]{0,15}(untuk|verifikasi|daftar)|upload[^\n]{0,10}ktp)/gi,
    score: 6,
    weight_category: 'high'
  },
  {
    id: 'ceo_scam',
    label: 'Modus CEO/Boss Scam — permintaan transfer mendadak dengan embel-embel rahasia.',
    regex: /(jangan bilang siapapun|ini rahasia|proses segera|atasan[^\n]{0,15}butuh|transfer[^\n]{0,20}vendor|bos[^\n]{0,10}ganti nomor)/gi,
    score: 6,
    weight_category: 'high'
  },
  {
    id: 'wrong_transfer',
    label: 'Permintaan pengembalian dana salah transfer — waspadai modus pinjol ilegal atau pencucian uang.',
    regex: /(salah transfer|kembalikan uang|uang masuk|transfer balik|salah kirim)/gi,
    score: 4,
    weight_category: 'high'
  },
  {
    id: 'tax_phishing',
    label: 'Klaim tagihan/denda pajak — waspadai phishing DJP. Cek hanya di pajak.go.id.',
    regex: /(tunggakan pajak|denda pajak|peringatan pajak|coretax akun|kode billing pajak)/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'hacked_medsos',
    label: 'Laporan akun diretas atau pesan dari akun yang dibajak — jangan transfer sebelum verifikasi langsung.',
    regex: /(akun[^\n]{0,10}kena hack|akun[^\n]{0,10}dibajak|akun palsu atas nama|clone akun)/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'dangerous_short_url',
    label: 'Tautan undangan digital tak dikenal — bisa memicu unduhan malware tersembunyi.',
    regex: /(buka undangan di link|undangan digital[^\n]{0,15}link|tautan undangan)/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'tech_support',
    label: 'Pop-up "virus detected" palsu — modus Tech Support Scam.',
    regex: /(perangkat[^\n]{0,15}(terinfeksi|terkena)[^\n]{0,10}(virus|malware)|hubungi[^\n]{0,10}(teknisi|support|nomor)[^\n]{0,15}(segera|untuk perbaikan)|browser[^\n]{0,10}(terkunci|diblokir)|system[^\n]{0,10}(error|dalam bahaya))/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'quishing',
    label: 'Permintaan scan QR Code mencurigakan — waspadai modus Quishing yang semakin marak.',
    regex: /(scan qr|pindai qr|kode qr|qr code|scan barcode)/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'fake_lapor_scam',
    label: 'Tautan pengaduan penipuan palsu — lapor hanya ke kanal resmi IASC/OJK/Polri.',
    regex: /(lapor penipuan|pusat bantuan penipuan|satgas pasti|appk ojk|pengembalian dana penipuan|iasc|indonesia anti.?scam|lapor[^\n]{0,10}scam)[^\n]{0,30}(link|klik|hubungi|whatsapp|palsu|penipu)/gi,
    score: 6,
    weight_category: 'high'
  },
  {
    id: 'jual_beli_segitiga',
    label: 'Modus Penipuan Segitiga — Jangan transfer ke orang yang berbeda dari nama STNK/Pemilik asli.',
    regex: /(transfer ke rekening (istri|suami|saudara|kakak) saya|jangan bahas harga (dengan|sama) orang rumah|saya suruh orang ngecek barang|nanti orang saya yang ambil)/gi,
    score: 6,
    weight_category: 'high'
  },
  {
    id: 'military_romance',
    label: 'Identitas tentara/dokter/insinyur asing — modus Romance Scam dengan profesi terpercaya, dampak finansial besar.',
    regex: /(aku (tentara|dokter|insinyur)[^\n]{0,15}(di|sedang)[^\n]{0,15}(bertugas|yaman|suriah|afghanistan|rig)|butuh uang[^\n]{0,15}(cuti|dokumen|tiket)|aku[^\n]{0,10}(single|duda|janda)[^\n]{0,10}(parent|anak))/gi,
    score: 6,
    weight_category: 'high'
  },
  // === MODERATE WEIGHT ===
  {
    id: 'unrealistic_invest',
    label: 'Klaim keuntungan investasi tidak realistis — ciri khas penipuan investasi bodong.',
    regex: /(return|profit|keuntungan|cuan)[^\n]{0,30}(\d+\s*%|persen)[^\n]{0,20}(bulan|minggu|hari)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'bansos',
    label: 'Klaim bantuan sosial/pemerintah — verifikasi hanya di situs resmi Kemensos.',
    regex: /(bansos|bantuan sosial|blt|bpnt|pkh|kemensos|pemerintah[^\n]{0,15}bantuan|subsidi[^\n]{0,10}cair)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'crypto_drainer',
    label: 'Ajakan hubungkan wallet atau klaim token gratis — waspadai Crypto Drainer.',
    regex: /(connect wallet|claim[^\n]{0,15}airdrop|approve[^\n]{0,15}token|seed phrase|free[^\n]{0,10}nft|limited[^\n]{0,10}token)/gi,
    score: 5,
    weight_category: 'moderate'
  },
  {
    id: 'ecom_scam',
    label: 'Penawaran e-commerce mencurigakan — harga terlalu murah atau minta transfer langsung.',
    regex: /(diskon[^\n]{0,10}\d{2,}\s*%|flash sale|harga grosir|order via whatsapp|transfer ke rekening|iphone[^\n]{0,10}murah|branded[^\n]{0,10}\d{2,3}\s*ribu)/gi,
    score: 3,
    weight_category: 'moderate'
  },
  {
    id: 'email_phishing',
    label: 'Pola email phishing — klaim masalah akun atau tagihan mendesak.',
    regex: /(akun[^\n]{0,15}(ditangguhkan|dibekukan|suspended)|unusual activity|password[^\n]{0,10}(expired|reset)|invoice[^\n]{0,10}terlampir|jatuh tempo[^\n]{0,10}segera)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'job_abroad',
    label: 'Tawaran kerja luar negeri via pesan — verifikasi di bp2mi.go.id.',
    regex: /(kerja[^\n]{0,15}(luar negeri|malaysia|singapura|taiwan|hongkong)|gaji[^\n]{0,10}\d{4}[^\n]{0,10}(ringgit|dollar|sgd)|biaya[^\n]{0,10}(agen|penempatan)|tki|pmi)/gi,
    score: 5,
    weight_category: 'moderate'
  },
  {
    id: 'friend_imperson',
    label: 'Pura-pura kenal lalu minta uang — modus impersonasi teman/keluarga.',
    regex: /(ingat aku|teman lama|nomor baruku|isiin pulsa|aku kecelakaan|pinjam dulu|di rumah sakit|tolong transfer ke)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'payment_pressure',
    label: 'Tekanan pembayaran mendesak — taktik umum penipu agar korban tidak berpikir jernih.',
    regex: /(bayar[^\n]{0,15}sekarang|transfer[^\n]{0,15}segera|jatuh tempo[^\n]{0,10}hari ini|dalam[^\n]{0,10}\d+\s*jam|sebelum[^\n]{0,10}(hangus|expired|ditutup)|\b(tf|trf)\s[^\n]{0,15}(sekarang|segera|asap|cepet))/gi,
    score: 3,
    weight_category: 'moderate'
  },
  {
    id: 'marketplace_fraud',
    label: 'Ajakan keluar dari marketplace atau bukti transfer mencurigakan — modus penipuan jual-beli.',
    regex: /(keluar[^\n]{0,10}marketplace|order via wa[^\n]{0,10}biar murah|transfer ke rekening (ini|pribadi)[^\n]{0,10}(aja|langsung)|sudah transfer[^\n]{0,10}silahkan cek|ini bukti transfer)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'vehicle_rental',
    label: 'Penawaran rental kendaraan mencurigakan — verifikasi tempat rental sebelum transfer DP.',
    regex: /(sewa (mobil|motor)[^\n]{0,10}(murah|lepas kunci)|rental[^\n]{0,10}(mobil|motor)[^\n]{0,10}promo|transfer dp[^\n]{0,15}(booking|sewa)[^\n]{0,10}(mobil|motor|kendaraan))/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'subscription_phishing',
    label: 'Pesan klaim masalah langganan/subscription — verifikasi di aplikasi resmi.',
    regex: /(langganan[^\n]{0,15}(diperpanjang|akan diperpanjang|dibatalkan)|subscription[^\n]{0,10}(expired|gagal|akan berakhir)|pembayaran[^\n]{0,10}(auto.?debit|gagal)[^\n]{0,15}(langganan|layanan))/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'survey_scam',
    label: 'Tawaran survey/review berbayar yang minta deposit — modus Task Scam lanjutan.',
    regex: /(isi survey[^\n]{0,10}(dapat|dibayar)|review[^\n]{0,10}(produk|aplikasi)[^\n]{0,10}(dapat|komisi)|deposit[^\n]{0,15}(untuk|akses)[^\n]{0,10}(survey|misi)|upgrade[^\n]{0,10}(member|akun)[^\n]{0,15}(survey|misi))/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'bi_checking',
    label: 'Tawaran hapus BI checking/SLIK — tidak ada yang bisa hapus riwayat kredit secara instan.',
    regex: /(hapus[^\n]{0,10}(bi checking|slik|blacklist|riwayat kredit|data kredit)|perbaiki[^\n]{0,10}(skor kredit|credit score)[^\n]{0,10}(instan|cepat|1 minggu)|jasa[^\n]{0,10}(hapus|penghapusan)[^\n]{0,10}(bi checking|slik|kredit))/gi,
    score: 5,
    weight_category: 'moderate'
  },
  {
    id: 'crowdfunding',
    label: 'Permintaan patungan / crowdfunding — waspadai penipuan, verifikasi penggalang dana.',
    regex: /(patungan|crowdfunding|urunan|iuran grup|galang dana)/gi,
    score: 3,
    weight_category: 'moderate'
  },
  {
    id: 'property_rental',
    label: 'Penawaran sewa properti yang minta DP sebelum survei — kemungkinan fiktif.',
    regex: /(transfer dp[^\n]{0,15}(booking|kamar|kos)|bayar[^\n]{0,10}uang muka[^\n]{0,15}(sebelum|survei)|properti[^\n]{0,10}(diminati|segera booking))/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'skimming',
    label: 'Indikasi transaksi skimming/pencurian data kartu — segera blokir kartu dan lapor bank.',
    regex: /(transaksi tidak dikenal|limit kartu tiba-tiba habis|tagihan[^\n]{0,15}membengkak|charge dari luar negeri)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'courier_intl',
    label: 'Phishing kurir internasional — lacak paket hanya di situs resmi kurir.',
    regex: /(paket[^\n]{0,10}(dhl|fedex|ups|ems)[^\n]{0,15}(tertahan|ditahan|bea cukai)|bayar[^\n]{0,10}(pajak impor|bea cukai)[^\n]{0,15}(rilis|paket))/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'giveaway',
    label: 'Klaim giveaway yang minta pembayaran — giveaway resmi tidak dipungut biaya.',
    regex: /(menang giveaway|giveaway[^\n]{0,10}(dari|from)|klaim hadiah giveaway|transfer[^\n]{0,15}(biaya kirim|pajak hadiah)|bayar[^\n]{0,10}untuk klaim)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'trading_group',
    label: 'Undangan grup sinyal trading — hampir pasti skema Ponzi atau pump-and-dump.',
    regex: /(join[^\n]{0,10}(grup|group)[^\n]{0,15}(signal|sinyal|trading|vip)|sinyal trading[^\n]{0,10}(akurat|pasti profit)|komunitas trader[^\n]{0,10}profit|copy trade[^\n]{0,10}(master|profit))/gi,
    score: 5,
    weight_category: 'moderate'
  },
  {
    id: 'asuransi_phishing',
    label: 'Klaim terkait asuransi/BPJS mencurigakan — verifikasi di aplikasi resmi.',
    regex: /(polis[^\n]{0,15}(hangus|dibatalkan)|bpjs[^\n]{0,15}(tidak aktif|diblokir)|premi[^\n]{0,15}(belum|gagal)|klaim asuransi[^\n]{0,15}cair|auto debit[^\n]{0,15}gagal)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'topup_scam',
    label: 'Penawaran top-up game/voucher mencurigakan — beli hanya dari platform resmi.',
    regex: /(top up[^\n]{0,15}(murah|diskon)|diamond[^\n]{0,10}(murah|grosir)|voucher[^\n]{0,10}(game|google play)[^\n]{0,10}(diskon|murah)|gift card[^\n]{0,10}murah)/gi,
    score: 3,
    weight_category: 'moderate'
  },
  {
    id: 'travel_scam',
    label: 'Tawaran travel/umroh mencurigakan — pastikan izin PPIU dari Kemenag.',
    regex: /(paket (umroh|haji|wisata)[^\n]{0,15}murah|biro (umroh|travel)[^\n]{0,10}berangkat|transfer dp[^\n]{0,15}(booking|seat)|umroh[^\n]{0,10}promo)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'donasi_scam',
    label: 'Permintaan donasi ke rekening pribadi — verifikasi melalui platform resmi.',
    regex: /(donasi[^\n]{0,15}rekening|sedekah[^\n]{0,15}ke rekening|transfer[^\n]{0,15}donasi|galang dana[^\n]{0,15}rekening)/gi,
    score: 3,
    weight_category: 'moderate'
  },
  // === NEW MODUS 2025-2026 ===
  {
    id: 'false_trust',
    label: 'Jaminan keamanan berlebihan — taktik psikologis untuk memanipulasi kepercayaan (reverse social proof).',
    regex: /(100% aman|dijamin resmi ojk|bukan penipuan|tanpa resiko|pasti cair|jaminan resmi)/gi,
    score: 3,
    weight_category: 'moderate'
  },
  // === Code-switching ===
  {
    id: 'code_switching_phishing',
    label: 'Pesan mencampur Bahasa Indonesia dan Inggris — pola umum phishing modern.',
    regex: /(your account[^\n]{0,20}(limited|suspended|blocked|verified)|account[^\n]{0,10}has been[^\n]{0,20}(limited|suspended|blocked)|click[^\n]{0,10}(link|here|button)[^\n]{0,10}(untuk|verifikasi|konfirmasi)|verify[^\n]{0,15}(akun|account|sekarang)|your[^\n]{0,10}(wallet|balance|saldo)[^\n]{0,15}(terpotong|hilang|terblokir)|kindly[^\n]{0,10}(klik|transfer|konfirmasi)|dear[^\n]{0,10}(nasabah|pelanggan|customer)[^\n]{0,15}(segera|immediately)|we detected[^\n]{0,20}(aktivitas|transaksi|activity))/gi,
    score: 4,
    weight_category: 'high'
  },
  {
    id: 'url_obfuscation',
    label: 'URL disamarkan dengan format tidak biasa (hxxps://, [.]) — tanda penipuan yang mencoba lolos filter.',
    regex: /(hxxps?:\/\/|\[\.]|h\s+t\s+t\s+p)/gi,
    score: 5,
    weight_category: 'high'
  },
  // === EMERGING SCAM PATTERNS 2025-2026 ===
  {
    id: 'task_scam',
    label: 'Tawaran tugas berbayar (like/review/follow) dengan deposit — modus Task Scam.',
    regex: /(tugas[^\n]{0,15}(berbayar|dibayar|komisi)|like[^\n]{0,10}(video|foto|postingan)[^\n]{0,15}(dapat|dibayar|komisi)|follow[^\n]{0,10}(akun|instagram|tiktok)[^\n]{0,15}(dibayar|komisi)|deposit[^\n]{0,15}(untuk|naik)[^\n]{0,10}(level|tier|misi)|kerja[^\n]{0,10}(online|sampingan)[^\n]{0,15}(hp|handphone|mudah)|misi[^\n]{0,10}(berbayar|dibayar|penghasilan))/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'investment_seminar',
    label: 'Undangan seminar/webinar investasi gratis yang menjual produk — modus seminar bodong.',
    regex: /(seminar[^\n]{0,15}(investasi|trading|saham|kripto)[^\n]{0,15}(gratis|free|eksklusif)|webinar[^\n]{0,10}(profit|cuan|trading)[^\n]{0,15}(gratis|daftar)|kelas[^\n]{0,10}(trading|investasi)[^\n]{0,15}(gratis|free|limited)|mentor[^\n]{0,10}(trading|investasi)[^\n]{0,15}(bimbing|ajar|guidance))/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'romance_scam',
    label: 'Pendekatan romantis yang berujung minta uang — modus Romance Scam.',
    regex: /(aku[^\n]{0,15}(jatuh cinta|sayang|cinta)[^\n]{0,30}(transfer|kirim|uang|butuh|minta)|kita[^\n]{0,10}(sudah|telah)[^\n]{0,15}(dekat|kenal)[^\n]{0,30}(tolong|bantu|transfer|kirim)|aku[^\n]{0,15}(di luar negeri|di perantauan)[^\n]{0,30}(butuh|tolong|minta)[^\n]{0,15}(uang|transfer|kirim))/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'family_emergency',
    label: 'Klaim darurat keluarga yang meminta transfer mendadak — verifikasi langsung ke keluarga.',
    regex: /(kecelakaan[^\n]{0,30}(butuh|segera)[^\n]{0,15}(uang|transfer|biaya|operasi)|di rumah sakit[^\n]{0,30}(butuh|segera|minta)[^\n]{0,15}(uang|transfer|biaya)|anak[^\n]{0,15}(sakit|kecelakaan|masuk)[^\n]{0,30}(transfer|kirim|bayar)[^\n]{0,15}(segera|cepat|asap))/gi,
    score: 6,
    weight_category: 'high'
  },
  // === EMERGING THREATS 2025-2026 ===
  {
    id: 'sim_swap_fraud',
    label: 'Indikasi SIM Swap Fraud — penipu mengganti kartu SIM korban untuk membajak OTP dan akun.',
    regex: /(kartu[^\n]{0,15}(tidak aktif|mati|hilang sinyal|no service)|sim[^\n]{0,10}(diganti|ditukar|diaktifkan ulang|swap)|nomor[^\n]{0,15}(tidak bisa|gagal)[^\n]{0,10}(telepon|sms|wa)|(tiba.?tiba|tanpa)[^\n]{0,15}(otp|kode verifikasi)[^\n]{0,15}masuk|provider[^\n]{0,15}(ganti|tukar)[^\n]{0,10}sim)/gi,
    score: 7,
    weight_category: 'high'
  },
  {
    id: 'qris_crossborder',
    label: 'Permintaan pembayaran QRIS lintas negara — QRIS hanya berlaku di Indonesia, modus penipuan emerging.',
    regex: /(qris[^\n]{0,15}(luar negeri|asean|internasional|malaysia|singapura|thailand|跨境)|bayar[^\n]{0,10}(qris|qr)[^\n]{0,15}(dollar|usd|myr|sgd|asing|international)|scan[^\n]{0,10}qr[^\n]{0,15}(luar|asing|internasional))/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'fake_ojk_website',
    label: 'Website OJK/IASC palsu — verifikasi hanya di ojk.go.id dan iasc.ojk.go.id resmi.',
    regex: /(ojk[^\n]{0,15}(palsu|fake|tiruan|bukan resmi)|iasc[^\n]{0,15}(palsu|fake|tiruan)|situs[^\n]{0,10}(ojk|iasc)[^\n]{0,15}(tidak resmi|bukan asli|penipuan)|ojk[^\n]{0,10}(recovery|pengembalian)[^\n]{0,15}dana)/gi,
    score: 6,
    weight_category: 'high'
  },
  {
    id: 'referral_pyramid',
    label: 'Skema referral berlapis — ciri penipuan piramida/MLM ilegal yang membutuhkan korban baru terus-menerus.',
    regex: /(ajak[^\n]{0,15}teman[^\n]{0,15}(daftar|pakai|referral|gabung)|referral[^\n]{0,15}(kamu|aku|link|kode)[^\n]{0,15}(daftar|join|pakai)|komisi[^\n]{0,15}(ajak|rekrut|referral|downline)|bonus[^\n]{0,15}member[^\n]{0,15}baru|rekrut[^\n]{0,15}(orang|teman|member)[^\n]{0,15}(dapat|komisi|bonus)|downline|passive income[^\n]{0,15}(ajak|rekrut))/gi,
    score: 5,
    weight_category: 'high'
  },
];

// ID rule yang dianggap sinyal KRITIS — langsung BERBAHAYA tanpa perlu DB match
export const CRITICAL_RULE_IDS = new Set([
  'otp_request',
  'vishing',
  'sextortion',
  'virtual_kidnapping',
  'money_mule',
  'advance_fee_heritage',
  'voice_cloning',
  'deepfake_invest',
  'gov_impersonation',
  'qris_overlay',
  'gambling',
  'apk_install',
  'fake_dukcapil_apk',
  'remote_access_scam',
  'joki_pinjol',
  'pig_butchering',
  'sim_swap_fraud',
]);

// Pre-compile regexForPosition untuk performa
REGEX_RULES.forEach(rule => {
  rule.regexForPosition = new RegExp(rule.regex.source, 'i');
});

// URL-IRRELEVANT RULES — Blocklist untuk isUrlInput
export const URL_IRRELEVANT_RULES = new Set([
  'otp_request',
  'urgency_fear',
  'payment_pressure',
  'vishing',
  'sextortion',
  'virtual_kidnapping',
  'money_mule',
  'advance_fee_heritage',
  'referral_pyramid',
]);

// DANGEROUS COMBOS — Rule Interaction Scoring
export const DANGEROUS_COMBOS: { rules: string[]; bonus: number; label: string }[] = [
  { rules: ['shortlink', 'urgency_fear'], bonus: 4, label: 'Link pendek + tekanan waktu palsu — pola phishing klasik' },
  { rules: ['shortlink', 'giveaway'], bonus: 4, label: 'Link pendek + klaim hadiah/undian — modus prize scam' },
  { rules: ['shortlink', 'bansos'], bonus: 4, label: 'Link pendek + klaim bansos — phishing program pemerintah palsu' },
  { rules: ['shortlink', 'apk_install'], bonus: 5, label: 'Link pendek ke APK — distribusi malware via shortener' },
  { rules: ['apk_install', 'urgency_fear'], bonus: 4, label: 'Instalasi APK mendesak — social engineering malware' },
  { rules: ['otp_request', 'urgency_fear'], bonus: 5, label: 'Permintaan OTP + tekanan waktu — modus pembajakan akun cepat' },
  { rules: ['vishing', 'payment_pressure'], bonus: 6, label: 'Aparat/jaksa palsu + desakan bayar segera — vishing ekstrem' },
  { rules: ['gov_impersonation', 'payment_pressure'], bonus: 5, label: 'Penyamaran instansi resmi + tekanan bayar — pemerasan digital' },
  { rules: ['recovery_scam', 'payment_pressure'], bonus: 4, label: 'Tawaran pemulihan dana + biaya di muka — double victimization' },
  { rules: ['pig_butchering', 'unrealistic_invest'], bonus: 4, label: 'Modus salah sambung + investasi bodong — pig butchering' },
  { rules: ['friend_imperson', 'payment_pressure'], bonus: 3, label: 'Pura-pura kenal + minta transfer segera — impersonasi teman' },
  { rules: ['quishing', 'urgency_fear'], bonus: 3, label: 'QR code + urgensi palsu — quishing scam' },
  { rules: ['shortlink', 'id_theft'], bonus: 5, label: 'Link pendek + minta data identitas — phishing data KTP/NIK' },
  { rules: ['voice_cloning', 'payment_pressure'], bonus: 5, label: 'Deepfake/suara palsu + desakan transfer — modus voice cloning berbahaya' },
  { rules: ['friend_imperson', 'urgency_fear'], bonus: 3, label: 'Impersonasi teman + tekanan waktu — modus penipuan kenalan mendesak' },
  { rules: ['pig_butchering', 'payment_pressure'], bonus: 4, label: 'Salah sambung + desakan bayar — pig butchering lanjutan' },
  { rules: ['job_abroad', 'payment_pressure'], bonus: 4, label: 'Tawaran kerja luar negeri + minta DP — penipuan TKI/PMI' },
  { rules: ['fake_dukcapil_apk', 'urgency_fear'], bonus: 5, label: 'Update data Dukcapil via APK + tekanan waktu — malware berkedok pemerintah' },
  { rules: ['sim_swap_fraud', 'urgency_fear'], bonus: 5, label: 'Indikasi SIM Swap + tekanan waktu — pembajakan akun tingkat lanjut' },
  { rules: ['sim_swap_fraud', 'otp_request'], bonus: 6, label: 'SIM Swap + permintaan OTP — modus pembajakan akun penuh' },
  { rules: ['qris_crossborder', 'urgency_fear'], bonus: 4, label: 'QRIS lintas negara + tekanan waktu — penipuan emerging ASEAN' },
  { rules: ['fake_ojk_website', 'recovery_scam'], bonus: 5, label: 'Website OJK palsu + tawaran pemulihan dana — double scam' },
  { rules: ['shortlink', 'sim_swap_fraud'], bonus: 5, label: 'Link pendek + indikasi SIM Swap — phishing data operator' },
  { rules: ['gambling', 'referral_pyramid'], bonus: 4, label: 'Judi online + skema referral — penipuan berlapis paling berbahaya' },
  { rules: ['referral_pyramid', 'urgency_fear'], bonus: 3, label: 'Skema referral + tekanan waktu — rekrutmen piramida mendesak' },
  { rules: ['unrealistic_invest', 'referral_pyramid'], bonus: 4, label: 'Investasi bodong + skema referral — Ponzi scheme klasik' },
];

// NEGATION DETECTION
export const NEGATION_PATTERN = /\b(jangan|tidak|bukan|jgn|dilarang|hindari|awas|waspada|peringatan|hati-hati|ingat)\b/i;
export const NEGATION_WINDOW = 60;
