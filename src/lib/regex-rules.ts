// ============================================================
// REGEX RULES — Modular regex-based detection rules
// ============================================================

import { RegexRule } from './types';

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
    regex: /(kirim.{0,20}otp|otp.{0,5}(nya|mu|kamu|anda)|salah.{0,15}(kirim|masuk|input).{0,10}(otp|kode|nomor)|butuh.{0,10}(otp|kode verifikasi)|tolong.{0,20}(kode|otp|verifikasi)|bagikan.{0,10}(otp|kode)|kode.{0,5}(otp|verifikasi).{0,15}masuk|kode.{0,10}(6|enam).{0,10}digit|pin.{0,10}verifikasi|masuk.{0,10}(kode|otp).{0,10}(sms|hp|wa)|kasih.{0,10}(tau|tahu).{0,10}(kode|otp)|share.{0,10}kode|kode.{0,10}nya.{0,5}(berapa|apa)|dong.{0,5}(kasih|kirim).{0,10}kode|kode.{0,10}(masuk|nyangkut).{0,10}(ke|di).{0,10}(hp|wa|sms)|verif.{0,15}(otp|kode|pin|akun))/gi,
    score: 7,
    weight_category: 'critical'
  },
  {
    id: 'vishing',
    label: 'Mengaku aparat hukum dan meminta transfer uang — penipuan vishing berbahaya.',
    regex: /(penyidik|bareskrim|kejaksaan|jaksa|polri|polda|polres|polisi|pengadilan|tipikor|narkoba|tersangka).{0,80}(transfer|jaminan|uang|rekening|bayar)|rekening.{0,30}(terlibat|terkait).{0,30}(pencucian|penipuan|kejahatan)/gi,
    score: 7,
    weight_category: 'critical'
  },
  {
    id: 'sextortion',
    label: 'Ancaman pemerasan video/foto intim (Sextortion) — JANGAN transfer, laporkan ke polisi.',
    regex: /(video.{0,15}(call|mu|kamu).{0,15}(rekam|sebar|viral)|(foto|video).{0,10}(bugil|telanjang|intim).{0,15}(sebar|kirim|viral)|bayar.{0,15}(atau|sebelum).{0,15}(video|foto|malu)|aku (punya|sudah).{0,15}(video|foto).{0,10}(call|bugil|rekam))/gi,
    score: 8,
    weight_category: 'critical'
  },
  {
    id: 'virtual_kidnapping',
    label: 'Klaim penculikan/kecelakaan anak — modus Virtual Kidnapping. Verifikasi langsung ke anak/keluarga.',
    regex: /(anak (anda|mu).{0,15}(diculik|disandera|di tangan|kecelakaan)|transfer (tebusan|uang).{0,15}(atau|sebelum).{0,10}(anak|celaka)|jangan (telepon|hubungi).{0,10}(polisi|siapapun).{0,15}anak|bayar.{0,15}tebusan)/gi,
    score: 8,
    weight_category: 'critical'
  },
  {
    id: 'money_mule',
    label: 'Ajakan menyewakan/menggunakan rekening — ini adalah modus money mule (pencucian uang) yang berisiko pidana.',
    regex: /(tampung.{0,15}uang|sewa.{0,10}rekening|jual.{0,10}rekening|teruskan.{0,10}dana|rekening penampung)/gi,
    score: 8,
    weight_category: 'critical'
  },
  {
    id: 'advance_fee_heritage',
    label: 'Klaim warisan/dana besar yang meminta biaya administrasi — modus penipuan Advance Fee.',
    regex: /(warisan|deposito.{0,15}luar negeri|biaya notaris.{0,15}warisan|pajak warisan|pewaris sah)/gi,
    score: 8,
    weight_category: 'critical'
  },
  {
    id: 'qris_overlay',
    label: 'Stiker QRIS palsu ditempel di merchant — periksa nama merchant sebelum bayar.',
    regex: /(qris.*tempel|stiker.*qr|qr.*ditimpa|qr.*overlay|scan.*qris.*palsu|ganti.*qris)/gi,
    score: 6,
    weight_category: 'high'
  },
  {
    id: 'voice_cloning',
    label: 'Pola Voice Cloning Scam — suara bisa dipalsukan AI. Jangan transfer sebelum verifikasi ulang.',
    regex: /(suara.{0,15}mirip.{0,15}(keluarga|anak|istri|suami|teman)|voice.{0,10}cloning|suara asli tapi nomor beda|(mama|papa|anak|suami|istri|kakak|adik).{0,15}ini aku.{0,30}(butuh|tolong|minta).{0,15}(uang|transfer|kirim)|ini (anak|suami|istri|papa|mama).{0,15}nomor.{0,10}(baru|beda|lain)|kecelakaan.{0,30}(transfer|kirim uang).{0,30}(jangan|rahasia|cerita))/gi,
    score: 7,
    weight_category: 'critical'
  },
  {
    id: 'deepfake_invest',
    label: 'Video promosi investasi dari tokoh publik — kemungkinan deepfake AI.',
    regex: /(video.{0,10}(presiden|prabowo|jokowi|artis|selebriti).{0,15}(dukung|rekomendasikan|endors)|deepfake.{0,10}(investasi|trading|kripto))/gi,
    score: 7,
    weight_category: 'critical'
  },
  {
    id: 'gov_impersonation',
    label: 'Tuduhan pelanggaran hukum/pencucian uang dari instansi — modus pemerasan.',
    regex: /(kominfo|ojk|polisi|dukcapil|pajak).{0,30}(iklan ilegal|pencucian uang|tppu|pelanggaran|blokir nomor|pidana)/gi,
    score: 6,
    weight_category: 'critical'
  },
  // === HIGH WEIGHT ===
  {
    id: 'apk_install',
    label: 'Suruhan untuk menginstal file/aplikasi asing (.APK).',
    regex: /(\.apk|buka aplikasi|install aplikasi|download apk|file apk)/gi,
    score: 6,
    weight_category: 'high'
  },
  {
    id: 'shortlink',
    label: 'Menggunakan Tautan Singkat/Pendek. Situs penipu sering memakainya.',
    regex: /(s\.id|bit\.ly|tinyurl\.com|cutt\.ly|wa\.me|t\.me|rb\.gy|is\.gd|v\.ht|shorturl\.at|dwz\.id|lynk\.id)[^\s]*/gi,
    score: 2,
    weight_category: 'moderate'
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
    regex: /(pulihkan|kembalikan dana|tim pemulihan|ojk recovery|cairkan dana).{0,50}(administrasi|bayar|transfer)/gi,
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
    regex: /(pinjaman.{0,15}cair|dana cepat.{0,15}tanpa|biaya (asuransi|verifikasi|admin).{0,20}(pinjaman|cair)|tanpa bi checking|plafon.{0,10}\d+\s*juta)/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'sim_reg_phishing',
    label: 'Permintaan NIK/KK/KTP via pesan — data identitas bisa disalahgunakan.',
    regex: /(kartu.{0,15}(diblokir|dinonaktifkan).{0,15}registrasi|kirim.{0,10}(nik|kk).{0,15}(aktivasi|verifikasi|registrasi)|registrasi ulang.{0,10}(kartu|sim)|kirim foto ktp)/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'id_theft',
    label: 'Permintaan data identitas (NIK/KK/KTP) via pesan — potensi pencurian identitas.',
    regex: /(kirim.{0,10}(nik|nomor kk|foto ktp|selfie ktp)|butuh.{0,10}(nik|kk|ktp).{0,15}(untuk|verifikasi|daftar)|upload.{0,10}ktp)/gi,
    score: 6,
    weight_category: 'high'
  },
  {
    id: 'ceo_scam',
    label: 'Modus CEO/Boss Scam — permintaan transfer mendadak dengan embel-embel rahasia.',
    regex: /(jangan bilang siapapun|ini rahasia|proses segera|atasan.{0,15}butuh|transfer.{0,20}vendor|bos.{0,10}ganti nomor)/gi,
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
    id: 'joki_pinjol',
    label: 'Tawaran joki pinjol/galbay — sangat berisiko pencurian data pribadi.',
    regex: /(joki pinjol|konsultan galbay|hapus utang pinjol|stop penagihan dc|hapus data pinjol)/gi,
    score: 5,
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
    regex: /(akun.{0,10}kena hack|akun.{0,10}dibajak|akun palsu atas nama|clone akun)/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'dangerous_short_url',
    label: 'Tautan undangan digital tak dikenal — bisa memicu unduhan malware tersembunyi.',
    regex: /(buka undangan di link|undangan digital.{0,15}link|tautan undangan)/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'tech_support',
    label: 'Pop-up "virus detected" palsu — modus Tech Support Scam.',
    regex: /(perangkat.{0,15}(terinfeksi|terkena).{0,10}(virus|malware)|hubungi.{0,10}(teknisi|support|nomor).{0,15}(segera|untuk perbaikan)|browser.{0,10}(terkunci|diblokir)|system.{0,10}(error|dalam bahaya))/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'quishing',
    label: 'Permintaan scan QR Code mencurigakan — waspadai modus Quishing.',
    regex: /(scan qr|pindai qr|kode qr|qr code|scan barcode)/gi,
    score: 3,
    weight_category: 'high'
  },
  {
    id: 'fake_dukcapil_apk',
    label: 'Pembaruan data KTP/KK via APK — Dukcapil tidak pernah mengirim APK.',
    regex: /(pembaruan data|update data|sinkronisasi).{0,20}(kk|ktp|dukcapil|identitas).{0,20}(apk|aplikasi|link)/gi,
    score: 6,
    weight_category: 'high'
  },
  {
    id: 'fake_lapor_scam',
    label: 'Tautan pengaduan penipuan palsu — lapor hanya ke kanal resmi OJK/Polri.',
    regex: /(lapor penipuan|pusat bantuan penipuan|satgas pasti|appk ojk|pengembalian dana penipuan).{0,30}(link|klik|hubungi|whatsapp)/gi,
    score: 5,
    weight_category: 'high'
  },
  {
    id: 'pig_butchering',
    label: 'Modus "Salah Sambung" yang berujung pada penipuan investasi (Pig Butchering Scam).',
    regex: /(maaf salah sambung|ini nomor.{0,10}bukan|simpan nomor saya|kita bisa jadi teman|trading kripto bareng|bimbingan trading|profit konsisten|meta online)/gi,
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
  // === MODERATE WEIGHT ===
  {
    id: 'unrealistic_invest',
    label: 'Klaim keuntungan investasi tidak realistis — ciri khas penipuan investasi bodong.',
    regex: /(return|profit|keuntungan|cuan).{0,30}(\d+\s*%|persen).{0,20}(bulan|minggu|hari)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'bansos',
    label: 'Klaim bantuan sosial/pemerintah — verifikasi hanya di situs resmi Kemensos.',
    regex: /(bansos|bantuan sosial|blt|bpnt|pkh|kemensos|pemerintah.{0,15}bantuan|subsidi.{0,10}cair)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'crypto_drainer',
    label: 'Ajakan hubungkan wallet atau klaim token gratis — waspadai Crypto Drainer.',
    regex: /(connect wallet|claim.{0,15}airdrop|approve.{0,15}token|seed phrase|free.{0,10}nft|limited.{0,10}token)/gi,
    score: 5,
    weight_category: 'moderate'
  },
  {
    id: 'ecom_scam',
    label: 'Penawaran e-commerce mencurigakan — harga terlalu murah atau minta transfer langsung.',
    regex: /(diskon.{0,10}\d{2,}\s*%|flash sale|harga grosir|order via whatsapp|transfer ke rekening|iphone.{0,10}murah|branded.{0,10}\d{2,3}\s*ribu)/gi,
    score: 3,
    weight_category: 'moderate'
  },
  {
    id: 'email_phishing',
    label: 'Pola email phishing — klaim masalah akun atau tagihan mendesak.',
    regex: /(akun.{0,15}(ditangguhkan|dibekukan|suspended)|unusual activity|password.{0,10}(expired|reset)|invoice.{0,10}terlampir|jatuh tempo.{0,10}segera)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'job_abroad',
    label: 'Tawaran kerja luar negeri via pesan — verifikasi di bp2mi.go.id.',
    regex: /(kerja.{0,15}(luar negeri|malaysia|singapura|taiwan|hongkong)|gaji.{0,10}\d{4}.{0,10}(ringgit|dollar|sgd)|biaya.{0,10}(agen|penempatan)|tki|pmi)/gi,
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
    regex: /(bayar.{0,15}sekarang|transfer.{0,15}segera|jatuh tempo.{0,10}hari ini|dalam.{0,10}\d+\s*jam|sebelum.{0,10}(hangus|expired|ditutup)|\b(tf|trf)\s.{0,15}(sekarang|segera|asap|cepet))/gi,
    score: 3,
    weight_category: 'moderate'
  },
  {
    id: 'marketplace_fraud',
    label: 'Ajakan keluar dari marketplace atau bukti transfer mencurigakan — modus penipuan jual-beli.',
    regex: /(keluar.{0,10}marketplace|order via wa.{0,10}biar murah|transfer ke rekening (ini|pribadi).{0,10}(aja|langsung)|sudah transfer.{0,10}silahkan cek|ini bukti transfer)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'vehicle_rental',
    label: 'Penawaran rental kendaraan mencurigakan — verifikasi tempat rental sebelum transfer DP.',
    regex: /(sewa (mobil|motor).{0,10}(murah|lepas kunci)|rental.{0,10}(mobil|motor).{0,10}promo|transfer dp.{0,15}(booking|sewa).{0,10}(mobil|motor|kendaraan))/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'subscription_phishing',
    label: 'Pesan klaim masalah langganan/subscription — verifikasi di aplikasi resmi.',
    regex: /(langganan.{0,15}(diperpanjang|akan diperpanjang|dibatalkan)|subscription.{0,10}(expired|gagal|akan berakhir)|pembayaran.{0,10}(auto.?debit|gagal).{0,15}(langganan|layanan))/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'gambling',
    label: 'Ajakan bermain judi online — ilegal di Indonesia dan dirancang untuk menguras uangmu.',
    regex: /(main slot.{0,10}(pasti menang|gacor|maxwin)|deposit.{0,10}(untuk|bisa).{0,10}(main|slot|maxwin)|situs judi|slot gacor|rtp.{0,10}(tinggi|hari ini)|agen judi|togel online)/gi,
    score: 6,
    weight_category: 'moderate'
  },
  {
    id: 'survey_scam',
    label: 'Tawaran survey/review berbayar yang minta deposit — modus Task Scam lanjutan.',
    regex: /(isi survey.{0,10}(dapat|dibayar)|review.{0,10}(produk|aplikasi).{0,10}(dapat|komisi)|deposit.{0,15}(untuk|akses).{0,10}(survey|misi)|upgrade.{0,10}(member|akun).{0,15}(survey|misi))/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'military_romance',
    label: 'Identitas tentara/dokter/insinyur asing — modus Romance Scam dengan profesi terpercaya.',
    regex: /(aku (tentara|dokter|insinyur).{0,15}(di|sedang).{0,15}(bertugas|yaman|suriah|afghanistan|rig)|butuh uang.{0,15}(cuti|dokumen|tiket)|aku.{0,10}(single|duda|janda).{0,10}(parent|anak))/gi,
    score: 6,
    weight_category: 'moderate'
  },
  {
    id: 'bi_checking',
    label: 'Tawaran hapus BI checking/SLIK — tidak ada yang bisa hapus riwayat kredit secara instan.',
    regex: /(hapus.{0,10}(bi checking|slik|blacklist|riwayat kredit|data kredit)|perbaiki.{0,10}(skor kredit|credit score).{0,10}(instan|cepat|1 minggu)|jasa.{0,10}(hapus|penghapusan).{0,10}(bi checking|slik|kredit))/gi,
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
    regex: /(transfer dp.{0,15}(booking|kamar|kos)|bayar.{0,10}uang muka.{0,15}(sebelum|survei)|properti.{0,10}(diminati|segera booking))/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'skimming',
    label: 'Indikasi transaksi skimming/pencurian data kartu — segera blokir kartu dan lapor bank.',
    regex: /(transaksi tidak dikenal|limit kartu tiba-tiba habis|tagihan.{0,15}membengkak|charge dari luar negeri)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'courier_intl',
    label: 'Phishing kurir internasional — lacak paket hanya di situs resmi kurir.',
    regex: /(paket.{0,10}(dhl|fedex|ups|ems).{0,15}(tertahan|ditahan|bea cukai)|bayar.{0,10}(pajak impor|bea cukai).{0,15}(rilis|paket))/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'giveaway',
    label: 'Klaim giveaway yang minta pembayaran — giveaway resmi tidak dipungut biaya.',
    regex: /(menang giveaway|giveaway.{0,10}(dari|from)|klaim hadiah giveaway|transfer.{0,15}(biaya kirim|pajak hadiah)|bayar.{0,10}untuk klaim)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'trading_group',
    label: 'Undangan grup sinyal trading — hampir pasti skema Ponzi atau pump-and-dump.',
    regex: /(join.{0,10}(grup|group).{0,15}(signal|sinyal|trading|vip)|sinyal trading.{0,10}(akurat|pasti profit)|komunitas trader.{0,10}profit|copy trade.{0,10}(master|profit))/gi,
    score: 5,
    weight_category: 'moderate'
  },
  {
    id: 'asuransi_phishing',
    label: 'Klaim terkait asuransi/BPJS mencurigakan — verifikasi di aplikasi resmi.',
    regex: /(polis.{0,15}(hangus|dibatalkan)|bpjs.{0,15}(tidak aktif|diblokir)|premi.{0,15}(belum|gagal)|klaim asuransi.{0,15}cair|auto debit.{0,15}gagal)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'topup_scam',
    label: 'Penawaran top-up game/voucher mencurigakan — beli hanya dari platform resmi.',
    regex: /(top up.{0,15}(murah|diskon)|diamond.{0,10}(murah|grosir)|voucher.{0,10}(game|google play).{0,10}(diskon|murah)|gift card.{0,10}murah)/gi,
    score: 3,
    weight_category: 'moderate'
  },
  {
    id: 'travel_scam',
    label: 'Tawaran travel/umroh mencurigakan — pastikan izin PPIU dari Kemenag.',
    regex: /(paket (umroh|haji|wisata).{0,15}murah|biro (umroh|travel).{0,10}berangkat|transfer dp.{0,15}(booking|seat)|umroh.{0,10}promo)/gi,
    score: 4,
    weight_category: 'moderate'
  },
  {
    id: 'donasi_scam',
    label: 'Permintaan donasi ke rekening pribadi — verifikasi melalui platform resmi.',
    regex: /(donasi.{0,15}rekening|sedekah.{0,15}ke rekening|transfer.{0,15}donasi|galang dana.{0,15}rekening)/gi,
    score: 3,
    weight_category: 'moderate'
  },
  // === BACKLOG: Deteksi code-switching (Bahasa Indonesia + English campur) ===
  {
    id: 'code_switching_phishing',
    label: 'Pesan mencampur Bahasa Indonesia dan Inggris — pola umum phishing modern.',
    regex: /(your account.{0,20}(limited|suspended|blocked|verified)|account.{0,10}has been.{0,20}(limited|suspended|blocked)|click.{0,10}(link|here|button).{0,10}(untuk|verifikasi|konfirmasi)|verify.{0,15}(akun|account|sekarang)|your.{0,10}(wallet|balance|saldo).{0,15}(terpotong|hilang|terblokir)|kindly.{0,10}(klik|transfer|konfirmasi)|dear.{0,10}(nasabah|pelanggan|customer).{0,15}(segera|immediately)|we detected.{0,20}(aktivitas|transaksi|activity))/gi,
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
]);

// DANGEROUS COMBOS — Rule Interaction Scoring
export const DANGEROUS_COMBOS: { rules: string[]; bonus: number; label: string }[] = [
  { rules: ['shortlink', 'urgency_fear'],              bonus: 4, label: 'Link pendek + tekanan waktu palsu — pola phishing klasik' },
  { rules: ['shortlink', 'giveaway'],                  bonus: 4, label: 'Link pendek + klaim hadiah/undian — modus prize scam' },
  { rules: ['shortlink', 'bansos'],                    bonus: 4, label: 'Link pendek + klaim bansos — phishing program pemerintah palsu' },
  { rules: ['shortlink', 'apk_install'],               bonus: 5, label: 'Link pendek ke APK — distribusi malware via shortener' },
  { rules: ['apk_install', 'urgency_fear'],            bonus: 4, label: 'Instalasi APK mendesak — social engineering malware' },
  { rules: ['otp_request', 'urgency_fear'],            bonus: 5, label: 'Permintaan OTP + tekanan waktu — modus pembajakan akun cepat' },
  { rules: ['vishing', 'payment_pressure'],            bonus: 6, label: 'Aparat/jaksa palsu + desakan bayar segera — vishing ekstrem' },
  { rules: ['gov_impersonation', 'payment_pressure'],  bonus: 5, label: 'Penyamaran instansi resmi + tekanan bayar — pemerasan digital' },
  { rules: ['recovery_scam', 'payment_pressure'],      bonus: 4, label: 'Tawaran pemulihan dana + biaya di muka — double victimization' },
  { rules: ['pig_butchering', 'unrealistic_invest'],   bonus: 4, label: 'Modus salah sambung + investasi bodong — pig butchering' },
  { rules: ['friend_imperson', 'payment_pressure'],    bonus: 3, label: 'Pura-pura kenal + minta transfer segera — impersonasi teman' },
  { rules: ['quishing', 'urgency_fear'],               bonus: 3, label: 'QR code + urgensi palsu — quishing scam' },
  { rules: ['shortlink', 'id_theft'],                  bonus: 5, label: 'Link pendek + minta data identitas — phishing data KTP/NIK' },
];

// NEGATION DETECTION
export const NEGATION_PATTERN = /\b(jangan|tidak|bukan|jgn|dilarang|hindari|awas|waspada|peringatan|hati-hati|ingat)\b/i;
export const NEGATION_WINDOW = 45;
