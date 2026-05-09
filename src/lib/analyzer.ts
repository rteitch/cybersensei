import Fuse from 'fuse.js';
import { AnalysisResult } from '../types';

// ============================================================
// 1. TYPES
// ============================================================

interface ScamDatabaseItem {
  id: string;
  category: string;
  threat_level: "High" | "Critical" | "Warning";
  action: string;
  keywords: string[];
  patterns: string[];
  analysis_result: string;
  micro_lesson: string;
  weight_category?: "critical" | "high" | "moderate";
}

function getWeightCategory(item: ScamDatabaseItem): "critical" | "high" | "moderate" {
  if (item.weight_category) return item.weight_category;
  if (item.threat_level === "Critical") return "critical";
  if (item.threat_level === "High") return "high";
  return "moderate";
}

interface RegexRule {
  id: string;
  label: string;
  regex: RegExp;
  score: number;
  weight_category: "critical" | "high" | "moderate";
}

interface URLAnalysis {
  url: string;
  domain: string;
  isSuspicious: boolean;
  reasons: string[];
  score: number;
}

// ============================================================
// 2. TEXT PREPROCESSING
// ============================================================

const EMOJI_REGEX = /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{FE00}-\u{FE0F}\u{1F900}-\u{1F9FF}\u{1FA00}-\u{1FA6F}\u{1FA70}-\u{1FAFF}\u{200D}\u{20E3}\u{E0020}-\u{E007F}]/gu;

const HOMOGLYPH_MAP: Record<string, string> = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X',
  '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
  '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
};

// ============================================================
// UNICODE HOMOGLYPH MAP untuk URL/Domain (IDN Homograph Attack)
// Referensi: Python script homograph_attack.py + Unicode Confusables
// Mencakup: Cyrillic, Greek, Armenian, Latin Extended
// ============================================================
const UNICODE_HOMOGLYPH_MAP: Record<string, string> = {
  // === Cyrillic → Latin (dari Python script referensi user) ===
  'а': 'a', // U+0430 Cyrillic a
  'е': 'e', // U+0435 Cyrillic ie
  'о': 'o', // U+043E Cyrillic o
  'с': 'c', // U+0441 Cyrillic es
  'у': 'y', // U+0443 Cyrillic u
  'х': 'x', // U+0445 Cyrillic ha
  'р': 'p', // U+0440 Cyrillic er
  'і': 'i', // U+0456 Cyrillic byelorussian-ukrainian i
  'ј': 'j', // U+0458 Cyrillic je
  'ѕ': 's', // U+0455 Cyrillic dze
  'ԁ': 'd', // U+0501 Cyrillic komi de
  'ԛ': 'q', // U+051B Cyrillic qa
  'ԝ': 'w', // U+051D Cyrillic we
  'А': 'A', // U+0410 Cyrillic A
  'В': 'B', // U+0412 Cyrillic Ve
  'Е': 'E', // U+0415 Cyrillic IE
  'К': 'K', // U+041A Cyrillic Ka
  'М': 'M', // U+041C Cyrillic Em
  'Н': 'H', // U+041D Cyrillic En
  'О': 'O', // U+041E Cyrillic O
  'Р': 'P', // U+0420 Cyrillic Er
  'С': 'C', // U+0421 Cyrillic Es
  'Т': 'T', // U+0422 Cyrillic Te
  'У': 'Y', // U+0423 Cyrillic U
  'Х': 'X', // U+0425 Cyrillic Kha

  // === Greek → Latin ===
  'ο': 'o', // U+03BF Greek small omicron
  'ρ': 'p', // U+03C1 Greek small rho
  'ν': 'v', // U+03BD Greek small nu
  'Α': 'A', // U+0391 Greek Alpha
  'Β': 'B', // U+0392 Greek Beta
  'Ε': 'E', // U+0395 Greek Epsilon
  'Η': 'H', // U+0397 Greek Eta
  'Ι': 'I', // U+0399 Greek Iota
  'Κ': 'K', // U+039A Greek Kappa
  'Μ': 'M', // U+039C Greek Mu
  'Ν': 'N', // U+039D Greek Nu
  'Ο': 'O', // U+039F Greek Omicron
  'Ρ': 'R', // U+03A1 Greek Rho (visual P)
  'Τ': 'T', // U+03A4 Greek Tau
  'Υ': 'Y', // U+03A5 Greek Upsilon
  'Χ': 'X', // U+03A7 Greek Chi
  'Ζ': 'Z', // U+0396 Greek Zeta

  // === Latin Extended / Visually Similar ===
  'ɑ': 'a', // U+0251 Latin alpha
  'ɡ': 'g', // U+0261 Latin script g
  'ɩ': 'i', // U+0269 Latin iota
  'ɾ': 'r', // U+027E Latin r
  'ʂ': 's', // U+0282 Latin s
  'ᴋ': 'k', // U+1D0B Latin small capital K
  'ᴍ': 'm', // U+1D0D Latin small capital M

  // === Fullwidth ASCII (U+FF01–FF5E) ===
  'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e',
  'ｆ': 'f', 'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j',
  'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o',
  'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't',
  'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z',
  'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E',
  'Ｆ': 'F', 'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I', 'Ｊ': 'J',
  'Ｋ': 'K', 'Ｌ': 'L', 'Ｍ': 'M', 'Ｎ': 'N', 'Ｏ': 'O',
  'Ｐ': 'P', 'Ｑ': 'Q', 'Ｒ': 'R', 'Ｓ': 'S', 'Ｔ': 'T',
  'Ｕ': 'U', 'Ｖ': 'V', 'Ｗ': 'W', 'Ｘ': 'X', 'Ｙ': 'Y', 'Ｚ': 'Z',
  '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
  '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
};

export function cleanText(raw: string): string {
  if (!raw) return '';
  let text = raw;

  // Normalize Unicode (NFKD) to decompose combined characters
  text = text.normalize('NFKD');

  // Remove emojis and zero-width characters
  text = text.replace(EMOJI_REGEX, '');
  text = text.replace(/[​-‍﻿­]/g, '');

  // Replace homoglyphs (Cyrillic lookalikes → Latin)
  for (const [glyph, replacement] of Object.entries(HOMOGLYPH_MAP)) {
    text = text.split(glyph).join(replacement);
  }

  // FIX: Hapus karakter zero-width (U+200B, U+200C, U+200D, U+FEFF, dll) yang sering dipakai penipu untuk mengelabui filter
  text = text.replace(/[\u200B-\u200D\uFEFF]/g, '');

  // Collapse multiple spaces/tabs into single space
  text = text.replace(/[ \t]+/g, ' ');

  // FIX 1: Perbaikan logika obfuscation collapse
  // Cek apakah karakter sebelum DAN sesudah spasi adalah huruf tunggal
  // (yaitu bukan diawali/diakhiri oleh huruf lain → artinya token 1 karakter)
  // Sebelumnya: before.length <= 3 selalu false karena before mengambil 20 karakter
  text = text.replace(/(?<=\b\w)\s(?=\w\b)/g, (match, offset, str) => {
    const prevChar = str[offset - 1] || '';
    const nextChar = str[offset + 2] || '';
    const prevIsSingle = prevChar && !/\s/.test(prevChar) && (offset < 2 || /\s/.test(str[offset - 2]));
    const nextIsSingle = nextChar && !/\s/.test(nextChar) && (str[offset + 3] === undefined || /\s/.test(str[offset + 3]));
    if (prevIsSingle && nextIsSingle) return '';
    return match;
  });

  return text.trim();
}

// ============================================================
// 3. URL / DOMAIN ANALYZER
// ============================================================

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'buzz', 'club', 'click', 'icu', 'tk', 'ml', 'ga', 'cf', 'gq',
  'work', 'loan', 'racing', 'win', 'bid', 'download', 'stream', 'gdn',
  'men', 'party', 'trade', 'date', 'faith', 'review', 'science', 'cricket',
  'accountant', 'zip', 'mov', 'page', 'dev', 'app'
]);

const SHORTENER_DOMAINS = new Set([
  's.id', 'bit.ly', 'tinyurl.com', 'cutt.ly', 'wa.me', 't.me',
  'rb.gy', 'is.gd', 'v.ht', 'shorturl.at', 'dwz.id', 'lynk.id',
  'tiny.cc', 'buff.ly', 'bl.ink', 'lnkd.in', 't.co'
]);

const BRAND_DOMAINS: Record<string, string[]> = {
  // FIX 9: Hapus duplikat bca.co.id
  'bca': ['bca.co.id', 'klikbca.com'],
  'bri': ['bri.co.id', 'brimo.id'],
  'mandiri': ['bankmandiri.co.id', 'livin.bankmandiri.co.id'],
  'bni': ['bni.co.id', 'bnionline.com'],
  'shopee': ['shopee.co.id', 'shopee.com'],
  'tokopedia': ['tokopedia.com'],
  'gojek': ['gojek.com', 'grab.com'],
  'grab': ['grab.com', 'grab.id'],
  'google': ['google.com', 'google.co.id', 'gmail.com', 'youtube.com'],
  'facebook': ['facebook.com', 'fb.com', 'meta.com'],
  'instagram': ['instagram.com'],
  'netflix': ['netflix.com'],
  'spotify': ['spotify.com'],
  'apple': ['apple.com', 'icloud.com'],
  'microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'hotmail.com'],
  'telkomsel': ['telkomsel.com', 'mytelkomsel.com'],
  'indosat': ['indosat.com', 'indosatooredoo.com', 'myim3.com'],
  'xl': ['xl.co.id', 'myxl.xl.co.id'],
  'pln': ['pln.co.id', 'plnmobile.co.id'],
  'bpjs': ['bpjs-kesehatan.go.id', 'bpjsketenagakerjaan.go.id'],
  'ojk': ['ojk.go.id'],
  'pajak': ['pajak.go.id', 'coretax.pajak.go.id'],
  'djp': ['pajak.go.id'],
  'kemenag': ['kemenag.go.id'],
  'kemensos': ['kemensos.go.id', 'dtks.kemensos.go.id'],
};

const WHITELIST_DOMAINS = new Set([
  'google.com', 'google.co.id', 'gmail.com', 'youtube.com', 'googleapis.com',
  'facebook.com', 'fb.com', 'meta.com', 'instagram.com', 'whatsapp.com',
  'tokopedia.com', 'shopee.co.id', 'shopee.com', 'lazada.co.id', 'blibli.com',
  'bukalapak.com', 'traveloka.com',
  'bca.co.id', 'klikbca.com', 'bri.co.id', 'brimo.id',
  'bankmandiri.co.id', 'bni.co.id', 'bnionline.com',
  'gojek.com', 'grab.com', 'grab.id',
  'telkomsel.com', 'indosat.com', 'xl.co.id',
  'pln.co.id', 'bpjs-kesehatan.go.id', 'pajak.go.id', 'ojk.go.id',
  'kemenag.go.id', 'kemensos.go.id', 'kominfo.go.id',
  'github.com', 'gitlab.com', 'stackoverflow.com',
  'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com', 'spotify.com',
  'wikipedia.org', 'wikimedia.org',
  // FIX 4: Hapus TLD generik — terlalu luas, bisa di-bypass oleh domain seperti evil.go.id.hack.xyz
  // Validasi domain .go.id/.co.id dilakukan secara struktural di analyzeURL()
  'kitabisa.com', 'rumahzakat.org', 'baznas.go.id',
  'kemenkes.go.id', 'kemendikbud.go.id', 'polri.go.id',
  'dana.id', 'ovo.id', 'gopay.co.id',
  'tiket.com', 'pegipegi.com',
  'bpjsketenagakerjaan.go.id', 'disnaker.go.id',
  'indodax.com', 'tokocrypto.com',
]);

function extractUrls(text: string): string[] {
  // FIX 11: Pre-process text untuk menangkap URL obfuscation format:
  // (a) hxxps://phishing-site[.]com  → format penulisan di report keamanan
  // (b) h t t p s://phishing.com     → dipisah spasi (obfuscation umum)
  let normalized = text
    // Konversi hxxps:// / hxxp:// → https:// / http://
    .replace(/hxxps?:\/\//gi, 'https://')
    // Hapus bracket notation: [.] → .
    .replace(/\[\.\]/g, '.')
    // Konversi h t t p s : / / atau h t t p : / / (spasi antar huruf URL scheme)
    .replace(/h\s+t\s+t\s+p\s+s?\s*:\s*\/\s*\//gi, 'https://');

  const urlRegex = /https?:\/\/[^\s<>"'`,;)}\]]+/gi;
  const matches = normalized.match(urlRegex) || [];
  // Also catch bare domains with suspicious patterns
  const bareDomainRegex = /(?:www\.)?[a-zA-Z0-9-]+\.(?:com|co\.id|net|org|xyz|top|buzz|club|click|icu|tk|ml|ga|cf|gq|id)[^\s]*/gi;
  const bareMatches = normalized.match(bareDomainRegex) || [];
  return [...new Set([...matches, ...bareMatches])];
}

function extractDomain(url: string): string {
  try {
    const fullUrl = url.startsWith('http') ? url : `http://${url}`;
    const parsed = new URL(fullUrl);
    return parsed.hostname.replace(/^www\./, '');
  } catch {
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/\s:?#]+)/i);
    return match ? match[1].toLowerCase() : '';
  }
}

// Untuk mengambil raw unicode string sebelum di-convert ke punycode oleh new URL()
function extractRawDomain(url: string): string {
  const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/\s:?#]+)/i);
  return match ? match[1].toLowerCase() : '';
}

// ============================================================
// IDN HOMOGRAPH ATTACK DETECTOR
// Mengidentifikasi domain yang menggunakan karakter Unicode untuk
// meniru domain brand resmi (e.g. gооgle.com pakai Cyrillic о)
// ============================================================
interface HomographResult {
  isHomograph: boolean;
  hasUnicode: boolean;
  isPunycode: boolean;
  normalizedDomain: string;  // domain setelah homoglyph di-normalize ke ASCII
  spoofedBrand: string | null; // brand mana yang ditiru, jika ada
  visualDomain: string;       // tampilan visual yang user lihat
}

function detectHomographAttack(domain: string): HomographResult {
  // 1. Cek apakah domain mengandung karakter non-ASCII (di luar range printable ASCII)
  const hasUnicode = /[^\x00-\x7F]/.test(domain);

  // 2. Cek apakah domain berisi punycode (xn--) — encoding IDN ke ASCII
  const isPunycode = domain.includes('xn--');

  // 3. Decode punycode ke bentuk Unicode visual jika perlu
  // Browser URL API secara native decode punycode → kita bisa pakai cara ini
  let visualDomain = domain;
  if (isPunycode) {
    try {
      // URL API akan decode xn-- ke Unicode display form
      const parsed = new URL(`http://${domain}`);
      // Gunakan hostname dari URL — browser handles IDN decoding
      visualDomain = parsed.hostname.replace(/^www\./, '');
    } catch {
      visualDomain = domain;
    }
  }

  // 4. Normalisasi: ganti semua karakter Unicode lookalike → ASCII
  let normalizedDomain = visualDomain.toLowerCase();
  for (const [glyph, replacement] of Object.entries(UNICODE_HOMOGLYPH_MAP)) {
    normalizedDomain = normalizedDomain.split(glyph).join(replacement.toLowerCase());
  }
  // Juga apply NFKD normalization
  normalizedDomain = normalizedDomain.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');

  // 5. Bandingkan normalized domain dengan semua legitimate brand domains
  let spoofedBrand: string | null = null;
  if (hasUnicode || isPunycode) {
    for (const [brand, legitimateDomains] of Object.entries(BRAND_DOMAINS)) {
      for (const legit of legitimateDomains) {
        // Cek apakah setelah normalisasi, domain menjadi identik dengan domain resmi
        const normalizedLegit = legit.toLowerCase();
        if (normalizedDomain === normalizedLegit && visualDomain !== legit) {
          spoofedBrand = brand;
          break;
        }
        // Juga cek apakah brand name-nya match setelah normalisasi
        if (normalizedDomain.includes(brand) && visualDomain !== legit
          && !legitimateDomains.some(d => visualDomain === d)) {
          spoofedBrand = brand;
          break;
        }
      }
      if (spoofedBrand) break;
    }
  }

  const isHomograph = (hasUnicode || isPunycode) && (
    spoofedBrand !== null ||
    normalizedDomain !== visualDomain.toLowerCase() // normalisasi mengubah sesuatu
  );

  return { isHomograph, hasUnicode, isPunycode, normalizedDomain, spoofedBrand, visualDomain };
}

function analyzeURL(url: string): URLAnalysis {
  const domain = extractDomain(url);
  const rawDomain = extractRawDomain(url); // Dapatkan format unicode asli (non-punycode)
  const reasons: string[] = [];
  let score = 0;

  // Check shortener
  if (SHORTENER_DOMAINS.has(domain)) {
    reasons.push(`Menggunakan shortener (${domain}) — tujuan asli tersembunyi`);
    score += 3;
  }

  // Check suspicious TLD
  const tld = domain.split('.').pop() || '';
  if (SUSPICIOUS_TLDS.has(tld)) {
    reasons.push(`TLD mencurigakan (.${tld}) — sering digunakan situs phishing`);
    score += 3;
  }

  // Check IP address as domain
  if (/^\d{1,3}(\.\d{1,3}){3}/.test(domain)) {
    reasons.push('Menggunakan IP address langsung — situs resmi tidak melakukan ini');
    score += 5;
  }

  // Check typosquatting against known brands
  for (const [brand, legitimateDomains] of Object.entries(BRAND_DOMAINS)) {
    if (domain.includes(brand) && !legitimateDomains.some(d => domain === d || domain.endsWith('.' + d))) {
      // Domain contains brand name but is NOT the legitimate domain
      const hasSuspiciousModifier = /[-]?(login|verify|secure|update|online|account|signin|auth|confirm|check|support)/i.test(domain);
      const hasNumberSubstitution = domain.replace(brand, '').match(/[0-9]/);
      const hasHyphenBrand = domain.includes(`-${brand}`) || domain.includes(`${brand}-`);

      if (hasSuspiciousModifier || hasNumberSubstitution || hasHyphenBrand) {
        reasons.push(`Domain meniru brand "${brand}" dengan pola typosquatting`);
        score += 6;
      }
    }
  }

  // Check for suspicious patterns in domain
  if (/secure-|login-|verify-|update-|account-|signin-/.test(domain)) {
    reasons.push('Domain mengandung kata kunci phishing (secure/login/verify)');
    score += 4;
  }

  // Check for excessive hyphens (common in phishing domains)
  // Gunakan rawDomain agar 'xn--' dari punycode tidak terhitung sebagai 3 hyphens
  const hyphenCount = (rawDomain.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    reasons.push(`Domain terlalu banyak tanda hubung (${hyphenCount}) — ciri domain phishing`);
    score += 3;
  }

  // Check for very long domain (phishing domains tend to be long)
  if (domain.length > 30) {
    reasons.push('Domain sangat panjang — ciri domain phishing');
    score += 2;
  }

  // Check URL encoding obfuscation
  if (/%[0-9a-f]{2}/i.test(url)) {
    reasons.push('Mengandung URL encoding — bisa jadi penyamaran tujuan asli');
    score += 2;
  }

  // Check for data: URI or javascript: URI
  if (/^(data|javascript|vbscript):/i.test(url)) {
    reasons.push('Menggunakan skema URI berbahaya (data/javascript)');
    score += 8;
  }

  // ── IDN HOMOGRAPH ATTACK DETECTION ──────────────────────────────────────
  // Deteksi domain yang menggunakan karakter Unicode mirip ASCII untuk meniru
  // brand resmi. Contoh: gооgle.com (Cyrillic о) vs google.com (Latin o)
  // GUNAKAN rawDomain karena 'domain' dari new URL() otomatis diconvert ke xn-- punycode di browser
  const homographResult = detectHomographAttack(rawDomain);
  if (homographResult.isHomograph) {
    if (homographResult.spoofedBrand) {
      // KRITIS: Domain ini secara visual meniru brand yang dikenal
      reasons.push(
        `⚠️ SERANGAN HOMOGRAPH TERDETEKSI: Domain "${homographResult.visualDomain}" menggunakan ` +
        `karakter Unicode (Cyrillic/Greek) untuk meniru "${homographResult.spoofedBrand}" yang asli. ` +
        `Setelah dinormalisasi: "${homographResult.normalizedDomain}"`
      );
      score += 9;
    } else if (homographResult.hasUnicode) {
      // MENCURIGAKAN: Ada karakter Unicode di domain tapi tidak match brand spesifik
      reasons.push(
        `Domain mengandung karakter Unicode mencurigakan — kemungkinan serangan IDN Homograph. ` +
        `Verifikasi domain asli: "${homographResult.normalizedDomain}"`
      );
      score += 6;
    } else if (homographResult.isPunycode) {
      // WASPADA: Domain menggunakan encoding IDN
      reasons.push(
        `Domain menggunakan format IDN/Punycode (${domain}) — selalu cek tujuan aslinya`
      );
      score += 4;
    }
  }

  // FIX 4: Whitelist check — validasi struktural untuk domain .go.id / .co.id / dll.
  // Domain harus 2-4 level saja (e.g. kemensos.go.id = 3 level, sub.kemensos.go.id = 4 level)
  const isWhitelisted = WHITELIST_DOMAINS.has(domain) ||
    [...WHITELIST_DOMAINS].some(wl => {
      if (domain === wl) return true;
      if (domain.endsWith('.' + wl)) {
        // Pastikan tidak ada segmen tambahan yang mencurigakan di depan domain yang di-whitelist
        // Max 4 segmen: sub.domain.go.id → ['sub', 'domain', 'go', 'id']
        return domain.split('.').length <= 4;
      }
      return false;
    });

  return {
    url,
    domain,
    isSuspicious: score >= 3 && !isWhitelisted,
    reasons,
    score: isWhitelisted ? 0 : score
  };
}

// ============================================================
// 4. WEIGHTED SCORING SYSTEM
// ============================================================

const WEIGHT_MULTIPLIERS: Record<string, number> = {
  critical: 1.5,   // OTP theft, money mule, kidnapping, sextortion
  high: 1.2,       // Phishing, vishing, recovery scam
  moderate: 1.0,   // E-commerce, travel, giveaway
};

// ============================================================
// 5. MODULAR REGEX RULES
// ============================================================

export const REGEX_RULES: RegexRule[] = [
  // === CRITICAL WEIGHT ===
  {
    id: 'otp_request',
    label: 'Permintaan OTP mencurigakan — tanda potensi pembajakan akun.',
    // FIX 6: Tambah slang OTP Indonesia informal
    regex: /(kirim.{0,20}otp|otp.{0,5}(nya|mu|kamu|anda)|salah.{0,15}(kirim|masuk|input).{0,10}(otp|kode|nomor)|butuh.{0,10}(otp|kode verifikasi)|tolong.{0,20}(kode|otp|verifikasi)|bagikan.{0,10}(otp|kode)|kode.{0,5}(otp|verifikasi).{0,15}masuk|kode.{0,10}(6|enam).{0,10}digit|pin.{0,10}verifikasi|masuk.{0,10}(kode|otp).{0,10}(sms|hp|wa)|kasih.{0,10}(tau|tahu).{0,10}(kode|otp)|share.{0,10}kode|kode.{0,10}nya.{0,5}(berapa|apa)|dong.{0,5}(kasih|kirim).{0,10}kode|kode.{0,10}(masuk|nyangkut).{0,10}(ke|di).{0,10}(hp|wa|sms))/gi,
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
    score: 3,
    weight_category: 'high'
  },
  {
    id: 'urgency_fear',
    // Audit: score 2 terlalu kecil untuk pesan pure urgency
    // FIX: naik ke 4, dan perluas pattern agar SEGERA/DARURAT/URGENT juga ter-cover
    label: 'Klaim mendesak dan menakut-nakuti — taktik penipu agar korban tidak berpikir jernih.',
    regex: /(diblokir|permanen|segera|dalam \d+ jam|terblokir|melanggar|dalam 24 jam|hari ini juga|sekarang juga|darurat|urgent|segera bertindak|batas waktu|jangan tunda|sebelum terlambat|waktu terbatas)/gi,
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
    regex: /(bayar.{0,15}sekarang|transfer.{0,15}segera|jatuh tempo.{0,10}hari ini|dalam.{0,10}\d+\s*jam|sebelum.{0,10}(hangus|expired|ditutup))/gi,
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
  // Audit: modus modern banyak pakai hybrid seperti "Hi sis, your account has been LIMITED, klik link ini"
  {
    id: 'code_switching_phishing',
    label: 'Pesan mencampur Bahasa Indonesia dan Inggris — pola umum phishing modern.',
    regex: /(your account.{0,20}(limited|suspended|blocked|verified)|account.{0,10}has been.{0,20}(limited|suspended|blocked)|click.{0,10}(link|here|button).{0,10}(untuk|verifikasi|konfirmasi)|verify.{0,15}(akun|account|sekarang)|your.{0,10}(wallet|balance|saldo).{0,15}(terpotong|hilang|terblokir)|kindly.{0,10}(klik|transfer|konfirmasi)|dear.{0,10}(nasabah|pelanggan|customer).{0,15}(segera|immediately)|we detected.{0,20}(aktivitas|transaksi|activity))/gi,
    score: 4,
    weight_category: 'high'
  },
  // Deteksi URL obfuscation dalam teks (hxxps, bracket notation)
  {
    id: 'url_obfuscation',
    label: 'URL disamarkan dengan format tidak biasa (hxxps://, [.]) — tanda penipuan yang mencoba lolos filter.',
    regex: /(hxxps?:\/\/|\[\.]|h\s+t\s+t\s+p)/gi,
    score: 5,
    weight_category: 'high'
  },
];

// ============================================================
// 6. NEW SCAM ENTRIES (2025-2026)
// ============================================================

const NEW_SCAM_ENTRIES: ScamDatabaseItem[] = [
  {
    id: "fraud_56",
    category: "Phishing Shopee/Tokopedia Login via WhatsApp",
    threat_level: "Critical",
    action: "Jangan pernah login marketplace dari tautan WA. Buka langsung aplikasi Shopee/Tokopedia dari HP.",
    keywords: ["shopee", "tokopedia", "login", "verifikasi", "akun", "toko", "toko anda", "toko dinonaktifkan", "pelanggan", "pesanan"],
    patterns: [
      "toko shopee anda akan dinonaktifkan",
      "verifikasi akun tokopedia segera",
      "login untuk mengaktifkan toko kembali",
      "toko anda bermasalah klik link",
      "akun seller shopee perlu verifikasi",
      "pesanan ditahan login untuk konfirmasi",
      "toko dinonaktifkan karena pelanggaran",
      "verifikasi ulang akun seller"
    ],
    analysis_result: "Ini adalah modus **Phishing Marketplace Seller** yang marak di 2025-2026. Pelaku mengirim WA ke penjual di Shopee/Tokopedia dengan klaim toko akan dinonaktifkan atau pesanan ditahan. Tautan mengarah ke situs login palsu yang mencuri kredensial seller. Setelah berhasil, pelaku menguras saldo penjual atau mengubah rekening tujuan pencairan.",
    micro_lesson: "Shopee/Tokopedia TIDAK PERNAH mengirim notifikasi masalah akun via WhatsApp. Semua notifikasi seller hanya melalui aplikasi resmi. Jika ada masalah akun, cek langsung di aplikasi.",
    weight_category: "critical"
  },
  {
    id: "fraud_57",
    category: "Saldo e-Wallet 'Kena Hack' (GoPay/OVO/DANA)",
    threat_level: "Critical",
    action: "Jangan panik dan jangan klik tautan apapun. Cek saldo langsung di aplikasi e-wallet resmi.",
    keywords: ["gopay", "ovo", "dana", "shopeepay", "saldo", "hack", "diretas", "hilang", "terpotong", "transaksi tidak dikenal", "e-wallet"],
    patterns: [
      "saldo gopay anda terpotong",
      "transaksi tidak dikenal di dana",
      "ovo anda diretas segera amankan",
      "shopeepay terpotong otomatis",
      "klik link untuk amankan saldo e-wallet",
      "saldo e-wallet hilang verifikasi segera",
      "ada yang akses akun dana anda",
      "transaksi mencurigakan di gopay"
    ],
    analysis_result: "Ini adalah modus **Phishing e-Wallet** yang mengincar pengguna GoPay, OVO, DANA, dan ShopeePay. Pelaku mengirim pesan yang mengklaim saldo e-wallet terpotong atau diretas, lalu meminta klik tautan untuk 'mengamankan akun'. Tautan mengarah ke situs phishing yang mencuri PIN e-wallet dan data pribadi. Setelah mendapat akses, pelaku menguras seluruh saldo.",
    micro_lesson: "Cek saldo e-wallet HANYA di aplikasi resmi (Gojek, OVO, DANA, Shopee). Jika ada transaksi mencurigakan, hubungi customer service resmi melalui fitur di aplikasi—bukan dari tautan pesan.",
    weight_category: "critical"
  },
  {
    id: "fraud_58",
    category: "Fake Invoice + Domain Baru (2026)",
    threat_level: "High",
    action: "Jangan bayar invoice dari email/WA tanpa verifikasi. Cek domain pengirim—domain baru (< 6 bulan) patut dicurigai.",
    keywords: ["invoice", "tagihan", "pembayaran", "jatuh tempo", "faktur", "purchase order", "po", "billing"],
    patterns: [
      "invoice terlampir mohon segera dibayar",
      "tagihan proyek sudah jatuh tempo",
      "purchase order silakan bayar ke rekening",
      "faktur pembayaran lampiran ini",
      "reminder tagihan overdue segera lunasi",
      "invoice dari vendor baru mohon diproses",
      "pembayaran termin sudah jatuh tempo",
      "mohon transfer ke rekening baru vendor"
    ],
    analysis_result: "Ini adalah modus **Fake Invoice dengan Domain Baru** yang semakin canggih di 2026. Pelaku mendaftarkan domain baru yang mirip nama perusahaan asli, lalu mengirim invoice palsu ke bagian keuangan. Invoice terlihat sangat profesional dengan logo, nomor PO, dan detail bank. Domain yang baru dibuat (< 6 bulan) adalah tanda merah besar. Modus ini sangat efektif menargetkan UMKM dan departemen keuangan.",
    micro_lesson: "Sebelum membayar invoice dari email baru: (1) cek umur domain di whois.com, (2) verifikasi langsung ke vendor melalui kontak yang sudah ada (bukan dari email invoice), (3) perhatikan apakah ada perubahan rekening tujuan pembayaran.",
    weight_category: "high"
  },
  {
    id: "fraud_59",
    category: "Penipuan Lowongan Kerja Digital (Telegram/Discord)",
    threat_level: "High",
    action: "Jangan deposit atau transfer uang untuk 'misi' apapun. Kerja asli TIDAK PERNAH minta bayaran dari pekerja.",
    keywords: ["lowongan", "kerja", "remote", "wfh", "gaji", "komisi", "deposit", "misi", "tugas", "telegram", "discord", "whatsapp", "grup"],
    patterns: [
      "lowongan kerja remote gaji besar",
      "kerja dari rumah gaji 5 juta",
      "hanya modal hp bisa kerja",
      "gabung grup telegram untuk info kerja",
      "deposit untuk akses misi premium",
      "kerja online tanpa pengalaman",
      "rekrutmen admin online shop",
      "tugas harian dapat komisi langsung"
    ],
    analysis_result: "Ini adalah modus **Lowongan Kerja Digital Palsu** yang sangat masif di 2025-2026. Pelaku memposting lowongan kerja remote/WFH di media sosial, lalu mengarahkan korban ke grup Telegram/Discord. Di awal, korban diberi tugas mudah (like, subscribe, review) dengan bayaran kecil. Setelah percaya, korban diminta deposit untuk 'misi premium' dengan komisi lebih besar. Uang deposit tidak pernah bisa ditarik.",
    micro_lesson: "Kerja asli TIDAK PERNAH minta deposit atau bayaran. Platform freelance resmi (Upwork, Freelancer, Sribulancer) tidak meminta uang dari pekerja. Jika diminta transfer untuk dapat kerja = PASTI penipuan.",
    weight_category: "high"
  },
  {
    id: "fraud_60",
    category: "Penipuan Investasi Kripto via AI Bot",
    threat_level: "Critical",
    action: "Jangan percaya bot trading yang menjanjikan profit otomatis. Tidak ada bot yang 'tidak pernah rugi'.",
    keywords: ["bot trading", "auto profit", "robot trading", "kripto", "crypto", "bitcoin", "ethereum", "solana", "trading bot", "passive income", "hasilkan uang otomatis"],
    patterns: [
      "bot trading auto profit setiap hari",
      "robot trading tidak pernah rugi",
      "passive income dari bot kripto",
      "deposit minimal untuk jalankan bot",
      "profit otomatis tanpa pengawasan",
      "bot trading ai terbaru 2026",
      "hasilkan uang sambil tidur",
      "bot ini sudah terbukti profit"
    ],
    analysis_result: "Ini adalah modus **Investasi Kripto via AI Bot** yang marak di 2025-2026. Pelaku menawarkan 'bot trading AI' yang menjanjikan profit otomatis tanpa risiko. Setelah deposit, bot menampilkan profit palsu di dashboard. Saat korban ingin withdraw, diminta bayar 'biaya penarikan' atau 'pajak profit'. Platform trading yang digunakan adalah milik penipu—uang tidak pernah benar-benar diinvestasikan.",
    micro_lesson: "Tidak ada bot trading yang 'tidak pernah rugi' atau 'pasti profit'. Jika ada, semua orang sudah kaya. Investasi kripto resmi melalui exchange terdaftar Bappebti (Indodax, Tokocrypto, dll). Jangan pernah deposit ke platform yang tidak terdaftar.",
    weight_category: "critical"
  },
  {
    id: "fraud_61",
    category: "SMS/WA Phishing BPJS Ketenagakerjaan (JHT)",
    threat_level: "High",
    action: "Cek saldo JHT hanya di aplikasi BPJSTKU atau bpjsketenagakerjaan.go.id. Jangan klik tautan dari SMS/WA.",
    keywords: ["bpjs", "ketenagakerjaan", "jht", "jaminan hari tua", "saldo", "cair", "klaim", "bpjstku", "pesangon"],
    patterns: [
      "saldo jht anda bisa dicairkan",
      "klaim bpjs ketenagakerjaan via link",
      "cairkan dana jht sekarang",
      "bpjs ketenagakerjaan saldo anda hangus",
      "verifikasi data bpjstku di link ini",
      "dana pesangon bisa dicairkan",
      "update data bpjs ketenagakerjaan",
      "saldo jht sudah bisa diambil"
    ],
    analysis_result: "Ini adalah modus **Phishing BPJS Ketenagakerjaan** yang marak di 2025-2026. Pelaku mengirim SMS/WA yang mengaku dari BPJS Ketenagakerjaan, mengklaim saldo JHT (Jaminan Hari Tua) bisa dicairkan atau akan hangus. Tautan mengarah ke situs phishing yang mencuri data identitas dan rekening bank. Modus ini sangat efektif karena banyak pekerja yang memang ingin mencairkan JHT.",
    micro_lesson: "Klaim JHT HANYA melalui aplikasi BPJSTKU atau kantor BPJS Ketenagakerjaan langsung. Proses klaim membutuhkan dokumen fisik (KTP, KK, surat kerja)—tidak bisa melalui tautan SMS/WA.",
    weight_category: "high"
  },
  {
    id: "fraud_62",
    category: "Penipuan Palsu Pemerintah (Bansos Digital 2026)",
    threat_level: "Critical",
    action: "Bansos resmi TIDAK PERNAH diminta melalui SMS/WA. Cek status bansos hanya di dtks.kemensos.go.id atau kelurahan.",
    keywords: ["bansos", "bantuan", "pemerintah", "cair", "rp", "ratusan ribu", "juta", "formulir", "daftar", "dtks", "kemensos"],
    patterns: [
      "anda terdaftar sebagai penerima bansos rp",
      "bantuan pemerintah rp 600 ribu cair",
      "isi formulir untuk klaim bansos",
      "bantuan sosial digital 2026",
      "transfer biaya verifikasi bansos",
      "dana bantuan sudah masuk segera cairkan",
      "verifikasi data penerima bantuan di link",
      "bansos cair hari ini daftar sekarang"
    ],
    analysis_result: "Ini adalah evolusi modus **Bansos Palsu di era Digital 2026**. Pelaku mengirim pesan massal yang mengklaim penerima bansos berhak mendapat bantuan Rp 600rb-3jt. Untuk 'mencairkan', korban diminta isi formulir di situs palsu (mencuri NIK/KK) atau transfer 'biaya verifikasi'. Modus ini sangat efektif karena menargetkan masyarakat ekonomi lemah yang memang berharap bantuan pemerintah.",
    micro_lesson: "Bansos resmi dicairkan langsung ke rekening/KKS penerima—TANPA biaya apapun. Cek status penerima di dtks.kemensos.go.id atau datangi kelurahan/desa. Pesan WA/SMS tentang bansos = hampir pasti penipuan.",
    weight_category: "critical"
  },
  {
    id: "fraud_63",
    category: "Penipuan QRIS Merchant (Sticker Overlay)",
    threat_level: "High",
    action: "Sebelum bayar QRIS, pastikan QR tidak ditempel menimpa stiker lain. Cek nama merchant setelah scan.",
    keywords: ["qris", "bayar", "scan", "merchant", "stiker", "tempel", "kode bayar", "pembayaran", "restoran", "warung"],
    patterns: [
      "scan qris untuk bayar",
      "stiker qr di kasir",
      "qr code ditempel di merchant",
      "bayar pakai qris",
      "kode qr pembayaran",
      "scan untuk bayar makanan",
      "qris restoran",
      "pembayaran qris warung"
    ],
    analysis_result: "Ini adalah modus **QRIS Sticker Overlay** yang marak di 2025-2026. Pelaku menempelkan QR code palsu di atas QRIS asli merchant (restoran, warung, parkir). Saat pelanggan scan, uang justru masuk ke rekening penipu, bukan ke merchant. Modus ini sangat sulit dideteksi karena QR palsu terlihat persis sama. Kerugian bisa mencapai jutaan per hari per lokasi.",
    micro_lesson: "Sebelum bayar QRIS: (1) periksa apakah ada stiker yang ditempel menimpa stiker lain, (2) setelah scan, pastikan nama merchant muncul (bukan nama orang pribadi), (3) jika ragu, bayar tunai atau minta merchant menunjukkan QR resmi dari aplikasi.",
    weight_category: "high"
  },
  {
    id: "fraud_64",
    category: "Penipuan Asuransi Unit Link dari Bank",
    threat_level: "High",
    action: "Jangan langsung setujui produk investasi dari telepon/WA yang mengaku dari bank. Minta waktu untuk riset dan baca polis dengan teliti.",
    keywords: ["asuransi", "unit link", "investasi", "bank", "telepon", "polis", "premi", "tabungan", "proteksi", "customer service", "cs bank"],
    patterns: [
      "ini dari bank untuk penawaran asuransi",
      "anda terpilih untuk program proteksi",
      "investasi sekaligus perlindungan",
      "premi hanya 500 ribu per bulan",
      "tabungan plus asuransi",
      "program loyalitas nasabah bank",
      "customer service bank menawarkan produk",
      "polis asuransi dari rekening bank"
    ],
    analysis_result: "Ini adalah modus **Penipuan Asuransi Unit Link** yang sering menyamar sebagai penawaran resmi dari bank. Pelaku menelepon/WA mengaku dari bank tempat kamu menabung, menawarkan 'program proteksi' atau 'investasi plus asuransi'. Produk yang ditawarkan sebenarnya adalah unit link dengan biaya tinggi dan return rendah. Modus ini sangat efektif karena memanfaatkan kepercayaan terhadap bank.",
    micro_lesson: "Bank resmi TIDAK PERNAH menawarkan produk asuransi via telepon/WA tanpa janji temu. Jika ditawari asuransi unit link: (1) minta waktu untuk baca polis, (2) bandingkan dengan produk serupa, (3) pahami semua biaya (admin, top-up, withdrawal), (4) jangan tekan 'setuju' di telepon.",
    weight_category: "high"
  },
  {
    id: "fraud_65",
    category: "Penipuan Sewa Properti Digital (Virtual Tour Palsu)",
    threat_level: "High",
    action: "Jangan transfer DP properti hanya berdasarkan video/foto virtual. Kunjungi langsung properti sebelum bayar.",
    keywords: ["sewa", "apartemen", "kost", "kontrakan", "virtual tour", "video", "foto", "dp", "booking", "properti", "hunian"],
    patterns: [
      "ini video apartemennya",
      "lihat foto kost dari dalam",
      "transfer dp untuk booking unit",
      "virtual tour properti",
      "unit ini sangat diminati segera booking",
      "saya di luar kota jadi pakai video",
      "properti ini baru listing segera amankan",
      "transfer ke rekening owner untuk booking"
    ],
    analysis_result: "Ini adalah modus **Sewa Properti Digital** yang berkembang di 2025-2026. Pelaku memasang iklan properti dengan foto/video profesional (bahkan virtual tour), lalu meminta DP sebelum survei langsung. Alasannya bermacam-macam: 'saya di luar kota', 'unit sangat diminati', 'booking sebelum kehabisan'. Setelah DP ditransfer, pelaku menghilang—properti ternyata tidak ada atau bukan miliknya.",
    micro_lesson: "SEBELUM transfer DP properti: (1) kunjungi langsung properti, (2) verifikasi pemilik melalui sertifikat/IMB, (3) gunakan platform properti terpercaya dengan sistem verifikasi, (4) jangan percaya video/foto saja—deepfake dan editing sangat canggih.",
    weight_category: "high"
  },
  // === 10 MODUS BARU DARI BACKLOG AUDIT ===
  {
    id: "fraud_66",
    category: "WhatsApp OTP via Link (bukan teks langsung)",
    threat_level: "Critical",
    action: "Jangan klik tautan apapun yang mengklaim mengirimkan OTP. OTP resmi hanya dikirim via SMS/WA dalam bentuk TEKS, bukan tautan.",
    keywords: ["otp", "link", "klik", "verifikasi", "tautan", "kode", "whatsapp", "wa", "konfirmasi", "tap", "tombol"],
    patterns: [
      "klik link untuk dapatkan kode otp",
      "tap tombol untuk verifikasi nomor",
      "link otp whatsapp",
      "kode verifikasi ada di tautan ini",
      "klik di sini untuk konfirmasi wa",
      "tekan tombol verify untuk lanjut",
      "otp dikirim via link berikut",
      "ketuk untuk dapat kode masuk"
    ],
    analysis_result: "Ini adalah modus **WhatsApp OTP via Link** — evolusi penipuan OTP yang lebih canggih. Alih-alih meminta kode langsung, pelaku mengirim tautan yang seolah-olah adalah 'pengiriman OTP'. Saat diklik, tautan justru melakukan auto-verifikasi akun WA korban ke perangkat penipu, atau mengarahkan ke situs phishing yang mencuri sesi WhatsApp. OTP resmi dari WhatsApp/Telegram SELALU berupa teks 6 digit, tidak pernah berupa tautan.",
    micro_lesson: "WhatsApp, Telegram, dan layanan resmi lainnya TIDAK PERNAH mengirim OTP dalam bentuk tautan/link. Jika ada pesan 'klik link untuk dapat OTP' = 100% penipuan. Langsung blokir dan laporkan.",
    weight_category: "critical"
  },
  {
    id: "fraud_67",
    category: "Telegram Scam Bot (Fake Verify)",
    threat_level: "Critical",
    action: "Jangan klik tombol verify di bot Telegram yang tidak kamu kenal. Bot resmi dari platform besar tidak mengirim permintaan verifikasi tiba-tiba.",
    keywords: ["telegram", "bot", "verify", "verifikasi", "tombol", "klik", "channel", "grup", "join", "konfirmasi", "captcha"],
    patterns: [
      "klik tombol verify untuk masuk grup",
      "bot telegram minta verifikasi",
      "selesaikan captcha untuk lanjut",
      "tekan verify di bot ini",
      "join channel telegram eksklusif",
      "bot verifikasi telegram",
      "klik start untuk aktifkan akun",
      "konfirmasi identitas di bot kami"
    ],
    analysis_result: "Ini adalah modus **Telegram Scam Bot** yang marak di 2025-2026. Pelaku mengirim undangan ke grup/channel Telegram eksklusif yang mengharuskan 'verifikasi' melalui bot. Saat korban menekan tombol di bot, sebenarnya korban memberikan izin akses ke akun Telegramnya, atau bot mencuri sesi login. Bot bisa juga menipu korban untuk mengirim OTP Telegram mereka. Setelah akun diambil, digunakan untuk menipu kontak-kontak korban.",
    micro_lesson: "Bot Telegram dari grup/channel asing yang meminta verifikasi = RED FLAG. Bot resmi dari @GroupAnonymousBot, @BotFather, dll. tidak pernah meminta OTP atau data login. Jangan pernah berikan kode apapun ke bot yang tidak dikenal.",
    weight_category: "critical"
  },
  {
    id: "fraud_68",
    category: "Penipuan Dompet Digital Regional (SAKUKU, FLIP, JENIUS)",
    threat_level: "High",
    action: "Cek saldo dan notifikasi HANYA di aplikasi resmi SAKUKU, FLIP, atau JENIUS. Jangan klik tautan dari SMS/WA.",
    keywords: ["sakuku", "flip", "jenius", "dompet", "saldo", "transfer", "kirim uang", "ewallet", "e-wallet", "digital banking", "bca", "btpn"],
    patterns: [
      "saldo sakuku anda terpotong",
      "akun jenius anda bermasalah",
      "flip transfer gagal verifikasi segera",
      "sakuku anda akan dinonaktifkan",
      "update data jenius di link ini",
      "flip saldo hilang klik untuk amankan",
      "verifikasi akun sakuku sekarang",
      "jenius account limited klik di sini"
    ],
    analysis_result: "Ini adalah modus **Phishing Dompet Digital Regional** yang menargetkan pengguna SAKUKU (BCA), FLIP, dan JENIUS (BTPN). Pelaku mengirim SMS/WA yang mengklaim ada masalah pada akun atau saldo terpotong, lalu mengarahkan ke situs phishing. Modus ini memanfaatkan popularitas aplikasi fintech Indonesia yang penggunanya masih banyak yang belum familiar dengan tanda-tanda phishing.",
    micro_lesson: "SAKUKU, FLIP, dan JENIUS TIDAK PERNAH mengirim tautan verifikasi via SMS/WA. Semua notifikasi resmi hanya melalui aplikasi atau email terdaftar. Jika ada masalah akun, buka langsung aplikasinya.",
    weight_category: "high"
  },
  {
    id: "fraud_69",
    category: "Penipuan Akun Netflix Sharing Palsu",
    threat_level: "High",
    action: "Beli langganan Netflix hanya di netflix.com resmi atau Google Play/App Store. Jangan beli akun sharing dari penjual WA/Telegram.",
    keywords: ["netflix", "sharing", "akun", "premium", "murah", "nonton", "subscription", "langganan", "password", "login", "email"],
    patterns: [
      "jual akun netflix sharing murah",
      "netflix premium sharing 1 slot",
      "akun netflix private murah",
      "beli netflix sharing via wa",
      "netflix 1 bulan 30 ribu",
      "sharing akun streaming murah",
      "akun netflix full hd termurah",
      "netflix sharing slot tersedia"
    ],
    analysis_result: "Ini adalah modus **Penipuan Akun Netflix Sharing**. Pelaku menjual akun Netflix dengan harga sangat murah (Rp 15-30 ribu per bulan) via WhatsApp/Telegram. Akun ini sebenarnya adalah akun bajakan, akun yang dibuat dengan kartu kredit curian, atau akun yang akan di-reset setelah pembayaran. Pembeli bisa kehilangan uang, dan akun bisa tiba-tiba mati kapanpun. Risiko tambahan: penjual mungkin mencuri data login kamu jika kamu diminta 'login ke akun mereka'.",
    micro_lesson: "Akun Netflix sharing yang dijual di bawah harga resmi hampir pasti bermasalah. Harga resmi Netflix Indonesia mulai Rp 54.000/bulan. Alternatif legal: gunakan satu akun bersama keluarga serumah (Netflix Family Plan).",
    weight_category: "high"
  },
  {
    id: "fraud_70",
    category: "Phishing via Google Forms / Microsoft Forms",
    threat_level: "High",
    action: "Jangan isi data sensitif (password, PIN, NIK, data rekening) di Google Forms atau Microsoft Forms dari sumber tidak resmi.",
    keywords: ["google forms", "microsoft forms", "form", "formulir", "isi data", "survey", "kuesioner", "docs.google", "forms.office", "link form"],
    patterns: [
      "isi formulir google form berikut",
      "verifikasi data di google forms",
      "link form untuk klaim hadiah",
      "isi data di microsoft forms",
      "formulir pendaftaran bansos google form",
      "survey berhadiah isi di link form",
      "update data di forms.office.com",
      "konfirmasi identitas via google form"
    ],
    analysis_result: "Ini adalah modus **Phishing via Google Forms / Microsoft Forms**. Penipu memanfaatkan legitimasi platform Google dan Microsoft untuk membuat formulir phishing yang terlihat resmi. Korban diminta mengisi data sensitif seperti password, PIN, NIK, nomor rekening, atau OTP di formulir yang tampak 'aman' karena menggunakan domain Google/Microsoft. Setelah submit, data langsung ke tangan penipu.",
    micro_lesson: "Google Forms dan Microsoft Forms bisa dibuat SIAPAPUN — bukan hanya perusahaan resmi. Jangan pernah masukkan password, PIN, OTP, atau data rekening di form manapun, termasuk Google Forms. Instansi resmi tidak mengumpulkan data sensitif lewat forms.",
    weight_category: "high"
  },
  {
    id: "fraud_71",
    category: "Penipuan Kartu ATM Tertelan + Minta PIN",
    threat_level: "Critical",
    action: "Jangan berikan PIN ATM kepada siapapun, termasuk yang mengaku petugas bank. Segera telepon call center bank dari nomor di belakang kartu.",
    keywords: ["atm", "kartu", "tertelan", "nyangkut", "petugas", "pin", "bank", "blokir", "ganti kartu", "mesin atm", "cs bank", "customer service"],
    patterns: [
      "kartu atm anda tertelan mesin",
      "saya petugas bank akan bantu",
      "masukkan pin untuk proses kartu",
      "kartu anda nyangkut di mesin",
      "saya teknisi atm bisa bantu",
      "ketik pin untuk keluarkan kartu",
      "hubungi nomor ini untuk kartu tertelan",
      "petugas bank minta pin untuk bantu"
    ],
    analysis_result: "Ini adalah modus **Kartu ATM Tertelan + Minta PIN**. Pelaku beroperasi di sekitar mesin ATM. Saat korban kesulitan (kartu nyangkut/tertelan), pelaku berpura-pura sebagai 'petugas bank' yang bisa membantu. Pelaku meminta PIN korban dengan alasan 'untuk proses pengeluaran kartu'. Setelah dapat PIN, pelaku menggunakan kartu yang sudah diambilnya (atau sudah direkam datanya) untuk menguras rekening. Ini adalah salah satu modus phishing offline paling tua tapi masih efektif.",
    micro_lesson: "Petugas bank dan teknisi ATM TIDAK PERNAH meminta PIN kartu. PIN adalah rahasia mutlak—tidak boleh diketahui siapapun termasuk petugas bank. Jika kartu tertelan, langsung telepon call center bank dari nomor di belakang kartu ATM.",
    weight_category: "critical"
  },
  {
    id: "fraud_72",
    category: "Modus Sudah/Pernah Kenal dari Acara/Event",
    threat_level: "High",
    action: "Verifikasi identitas melalui saluran lain yang sudah kamu kenal. Jangan percaya klaim 'ketemu di event' dari nomor tidak dikenal.",
    keywords: ["kenal", "event", "acara", "seminar", "konferensi", "pelatihan", "workshop", "reuni", "ketemu", "ingat", "pernah ketemu", "teman baru"],
    patterns: [
      "kita pernah ketemu di acara",
      "ingat nggak kita ketemu di seminar",
      "aku teman dari event kemarin",
      "kita pernah kenal di workshop",
      "aku dari komunitas yang sama",
      "kita satu reuni kan",
      "kamu hadir di konferensi itu kan",
      "aku temanmu dari pelatihan"
    ],
    analysis_result: "Ini adalah modus **Impersonasi Kenalan dari Acara/Event**. Pelaku menghubungi target dengan klaim sudah kenal dari event, seminar, workshop, atau reuni. Karena korban tidak ingat pasti siapa saja yang ditemui di acara tersebut, pelaku memanfaatkan keraguan itu untuk membangun kepercayaan. Setelah 'perkenalan ulang', pelaku mulai meminta bantuan keuangan, mengajak bisnis palsu, atau melancarkan romance scam.",
    micro_lesson: "Jika seseorang klaim kenal dari acara tapi kamu tidak ingat sama sekali, verifikasi melalui panitia acara atau teman yang hadir di event yang sama. Jangan beri data pribadi atau transfer uang hanya karena klaim kenal dari acara.",
    weight_category: "high"
  },
  {
    id: "fraud_73",
    category: "Deepfake Image untuk Romance Scam",
    threat_level: "Critical",
    action: "Lakukan reverse image search (cari gambar di Google Images) untuk memverifikasi foto profil kenalan online. Waspada profil yang terlalu sempurna.",
    keywords: ["foto", "profil", "cantik", "tampan", "handsome", "beautiful", "ai generated", "deepfake", "foto palsu", "kenalan online", "dating", "match", "instagram"],
    patterns: [
      "foto profilnya terlalu sempurna",
      "kenalan online dengan foto model",
      "profil dating app terlalu bagus",
      "foto instagram terlalu profesional",
      "tidak mau video call hanya chat",
      "selalu punya alasan tidak bisa video call",
      "foto seperti model tapi minta uang",
      "kenalan online tidak pernah mau ketemu"
    ],
    analysis_result: "Ini adalah modus **Deepfake Image untuk Romance Scam** yang berkembang pesat di 2025-2026. Pelaku menggunakan AI image generator (Midjourney, DALL-E, Stable Diffusion) untuk membuat foto profil yang sangat realistis dan menarik. Foto-foto ini tidak ada di internet (tidak bisa ditemukan via reverse image search) karena dibuat AI. Setelah membangun hubungan emosional, pelaku mulai meminta uang dengan berbagai alasan. Tanda merahnya: selalu menolak video call, foto terlalu sempurna, dan cepat jatuh cinta.",
    micro_lesson: "Untuk verifikasi kenalan online: (1) lakukan reverse image search di Google Images atau TinEye, (2) minta video call langsung (penipu biasanya menolak), (3) profil yang terlalu sempurna dan cepat jatuh cinta = tanda merah besar. Jangan transfer uang ke orang yang belum pernah kamu temui langsung.",
    weight_category: "critical"
  },
  {
    id: "fraud_74",
    category: "Penipuan COD (Bayar Dulu Baru Kirim Barang)",
    threat_level: "High",
    action: "Bayar COD HANYA saat barang sudah di tangan dan sesuai pesanan. Jangan transfer uang sebelum barang diterima. Tolak paket COD jika tidak sesuai.",
    keywords: ["cod", "cash on delivery", "bayar di tempat", "bayar dulu", "transfer dp", "ongkir", "kirim", "paket", "belanja online", "barang", "rekber"],
    patterns: [
      "cod tapi bayar dp dulu",
      "transfer ongkir sebelum barang dikirim",
      "bayar dulu baru barang dikirim besok",
      "cod tapi perlu konfirmasi bayar",
      "transfer biaya packing sebelum cod",
      "bayar separuh dulu sisanya pas terima",
      "rekber tapi transfer ke rekening saya dulu",
      "cod tapi butuh tanda jadi transfer"
    ],
    analysis_result: "Ini adalah modus **Penipuan COD (Cash on Delivery) Palsu**. COD sejati artinya pembayaran dilakukan SAAT barang diterima, bukan sebelumnya. Pelaku membalik konsep COD dengan meminta 'DP', 'biaya packing', 'ongkir di muka', atau 'tanda jadi' sebelum barang dikirim. Setelah transfer, barang tidak pernah dikirim. Modus ini sangat efektif karena banyak yang tidak memahami bahwa 'COD + transfer dulu' adalah kontradiksi.",
    micro_lesson: "COD = bayar SETELAH barang ada di tangan kamu. Jika penjual minta transfer apapun sebelum barang diterima, itu bukan COD—itu penipuan. Tolak semua permintaan 'DP COD' atau 'ongkir dulu'. Belanja di marketplace dengan sistem escrow agar lebih aman.",
    weight_category: "high"
  },
  {
    id: "fraud_75",
    category: "Phishing Email Berkedok HRD / Fake Job Offer",
    threat_level: "High",
    action: "Verifikasi tawaran kerja melalui website resmi perusahaan atau LinkedIn. Perusahaan resmi tidak meminta biaya apapun dari pelamar.",
    keywords: ["hrd", "rekrutmen", "lowongan", "kerja", "interview", "wawancara", "tawaran kerja", "job offer", "gaji", "kontrak", "dokumen", "biaya", "administrasi", "seleksi"],
    patterns: [
      "tawaran kerja dari hrd perusahaan",
      "anda lolos seleksi administrasi",
      "interview online segera konfirmasi",
      "transfer biaya pelatihan untuk onboarding",
      "bayar biaya seragam sebelum mulai kerja",
      "terpilih sebagai kandidat kirim berkas",
      "job offer dari perusahaan multinasional",
      "konfirmasi kehadiran interview dengan transfer"
    ],
    analysis_result: "Ini adalah modus **Phishing Email Berkedok HRD / Fake Job Offer**. Pelaku mengirim email atau WA yang mengaku dari HRD perusahaan terkemuka, mengklaim pelamar lolos seleksi dan mendapat tawaran kerja. Untuk 'konfirmasi', korban diminta membayar 'biaya pelatihan', 'seragam', 'medical check up', atau 'administrasi'. Perusahaan nyata TIDAK PERNAH meminta biaya dari pelamar. Email menggunakan domain gratis (Gmail, Yahoo) atau domain yang mirip perusahaan asli.",
    micro_lesson: "Perusahaan bonafide TIDAK PERNAH meminta biaya dari pelamar kerja. Cek apakah email HRD menggunakan domain resmi perusahaan (bukan Gmail/Yahoo). Verifikasi lowongan di website resmi atau LinkedIn perusahaan. Laporkan ke Disnaker jika dimintai uang untuk dapat pekerjaan.",
    weight_category: "high"
  },
  {
    id: "fraud_76",
    category: "Penipuan Jasa Titip (Jastip) / Tiket Konser WTS",
    threat_level: "High",
    action: "Hati-hati membeli tiket konser dari calo atau WTS di media sosial (X/Twitter). Gunakan rekber terpercaya atau COD (Cash On Delivery) fisik jika memungkinkan.",
    keywords: ["tiket", "konser", "wts", "want to sell", "wtb", "want to buy", "jastip", "calo", "sold out", "coldplay", "taylor swift", "kpop", "seat", "cat", "transfer full"],
    patterns: [
      "wts tiket konser",
      "jastip tiket murah",
      "tiket sold out saya ada lebih",
      "jual tiket festival",
      "transfer full baru tiket dikirim",
      "jangan hit and run",
      "bisa pindah tangan ktp",
      "jual rugi tiket konser"
    ],
    analysis_result: "Ini adalah modus **Penipuan WTS Tiket Konser**. Saat tiket konser artis besar (Coldplay, K-Pop) habis terjual (sold out), banyak penipu memposting 'WTS (Want To Sell)' di Twitter/X. Mereka menggunakan foto tiket curian atau hasil editan, dan mendesak korban untuk segera mentransfer uang dengan alasan 'banyak yang mau'. Setelah uang ditransfer, akun penipu akan memblokir korban dan menghilang.",
    micro_lesson: "Jangan pernah membeli tiket konser dari akun anonim di Twitter/Instagram yang meminta transfer penuh di muka. Jika terpaksa membeli dari tangan kedua, pastikan COD fisik atau gunakan sistem Rekber (Rekening Bersama) dari e-commerce yang menahan uang sampai tiket dipastikan valid/bisa masuk venue.",
    weight_category: "high"
  },
  {
    id: "fraud_77",
    category: "Customer Service (CS) Palsu di Twitter/X",
    threat_level: "Critical",
    action: "Jangan pernah merespon akun CS yang me-reply keluhanmu di Twitter jika akun tersebut tidak memiliki centang verifikasi resmi (Centang Biru/Kuning) dari institusi terkait.",
    keywords: ["halo", "bca", "mandiri", "bri", "jne", "jnt", "shopee", "tokopedia", "cs", "customer service", "bantuan", "kendala", "dm", "whatsapp", "link", "keluhan"],
    patterns: [
      "mohon maaf atas kendalanya kak",
      "bisa kami bantu silakan dm",
      "silakan hubungi wa cs kami",
      "klik link berikut untuk bantuan",
      "halo kak untuk proses refund",
      "kendala transaksi akan kami bantu",
      "mohon info nomor handphone aktif",
      "silakan lanjut di whatsapp resmi kami"
    ],
    analysis_result: "Ini adalah modus **CS Bank/Instansi Palsu di Media Sosial**. Saat kamu mengeluh (mention) tentang kendala transaksi ke akun resmi (misal @HaloBCA), penipu yang menggunakan bot akan langsung membalas tweet kamu lebih cepat dari CS asli. Akun mereka dibuat sangat mirip (misal @HaloBCA_Bantuan). Mereka akan mengarahkan kamu ke WhatsApp palsu atau mengirim link phishing untuk 'memproses keluhan/refund', yang ujungnya mencuri data perbankanmu.",
    micro_lesson: "CS Bank ASLI TIDAK PERNAH meminta kamu menghubungi nomor WhatsApp pribadi, TIDAK PERNAH meminta OTP/PIN/CVV, dan TIDAK PERNAH mengirimkan link form untuk diisi. Selalu perhatikan *handle* (username) dengan teliti dan centang verifikasinya.",
    weight_category: "critical"
  },
  {
    id: "fraud_78",
    category: "Impersonasi Pemerintah (Tuduhan Iklan Ilegal/TPPU)",
    threat_level: "Critical",
    action: "Jangan panik. Instansi pemerintah TIDAK PERNAH menelpon/WA untuk menuduh kejahatan dan meminta transfer uang 'pengamanan'.",
    keywords: ["kominfo", "ojk", "polisi", "bareskrim", "pencucian uang", "tppu", "iklan ilegal", "blokir nomor", "pidana", "denda", "tersangka", "kasus"],
    patterns: [
      "nomor anda akan diblokir kominfo",
      "terlibat kasus pencucian uang tppu",
      "ditemukan iklan ilegal atas nama anda",
      "panggilan dari bareskrim polri",
      "transfer dana untuk pengamanan sementara",
      "rekening anda dibekukan ojk",
      "hubungi penyidik untuk klarifikasi",
      "surat panggilan polisi digital"
    ],
    analysis_result: "Ini adalah modus **Penyamaran Instansi Pemerintah**. Pelaku menelpon atau WA mengaku dari Kominfo, OJK, atau Kepolisian, menuduh kamu terlibat kejahatan (pencucian uang, iklan ilegal, narkoba). Mereka sengaja membuat kamu panik agar tidak bisa berpikir jernih. Ujung-ujungnya, mereka akan meminta kamu mentransfer uang ke 'rekening pengaman' atau meminta OTP dengan alasan investigasi.",
    micro_lesson: "Instansi penegak hukum TIDAK PERNAH meminta uang 'pengamanan' atau menyelesaikan kasus lewat telepon/WA. Jika ditelpon orang yang menuduh kamu berbuat kriminal, langsung matikan teleponnya. Itu 100% penipuan.",
    weight_category: "critical"
  },
  {
    id: "fraud_79",
    category: "Phishing APK Dukcapil (Update KTP/KK)",
    threat_level: "High",
    action: "Abaikan dan jangan unduh apapun. Update data kependudukan hanya dilakukan di kantor Dukcapil atau aplikasi Identitas Kependudukan Digital (IKD) resmi dari Play Store.",
    keywords: ["dukcapil", "ktp", "kk", "update data", "pembaruan", "sinkronisasi", "identitas", "nik", "diblokir", "apk", "aplikasi"],
    patterns: [
      "pembaruan data kk dukcapil",
      "nik anda akan dinonaktifkan",
      "sinkronisasi ktp klik aplikasi ini",
      "download apk update data dukcapil",
      "verifikasi ulang data kependudukan",
      "surat peringatan dukcapil",
      "buka file untuk cek data kk",
      "data ktp tidak valid"
    ],
    analysis_result: "Ini adalah modus **Malware APK berkedok Dukcapil**. Pelaku menyamar sebagai petugas Disdukcapil dan mengklaim data NIK/KTP kamu akan diblokir jika tidak diperbarui. Mereka mengirimkan file APK untuk 'sinkronisasi data'. Jika diinstal, aplikasi ini akan mencuri semua SMS (termasuk OTP perbankan) dan menguras saldo rekeningmu.",
    micro_lesson: "Dukcapil TIDAK PERNAH mengirim file APK melalui WhatsApp. Semua aplikasi resmi pemerintah (seperti IKD) HANYA tersedia di Google Play Store atau Apple App Store.",
    weight_category: "high"
  },
  {
    id: "fraud_80",
    category: "Layanan Lapor Penipuan / Satgas PASTI Palsu",
    threat_level: "High",
    action: "Lapor penipuan HANYA melalui kanal resmi: hubungi 157, WA OJK 081157157157, atau lapor.go.id. Jangan pernah lapor ke nomor WA asing dari internet.",
    keywords: ["lapor", "penipuan", "pengaduan", "satgas pasti", "ojk", "appk", "pengembalian dana", "recovery", "cyber crime", "pusat bantuan", "bantu lapor"],
    patterns: [
      "pusat pengaduan penipuan online",
      "lapor ke cyber crime kami",
      "satgas pasti ojk bantuan",
      "pengembalian dana korban penipuan",
      "hubungi wa pengaduan untuk lapor",
      "bantu urus rekening penipu",
      "layanan recovery dana scam",
      "link lapor penipuan resmi"
    ],
    analysis_result: "Ini adalah modus **Recovery Scam berkedok Lapor Penipuan**. Penipu membuat akun atau iklan palsu di internet/sosmed (misal 'Pusat Bantuan Cyber' atau 'Satgas PASTI Palsu') untuk menjebak korban yang baru saja tertipu. Ketika korban melapor ke mereka, penipu akan memeras korban lagi dengan dalih 'biaya administrasi blokir rekening' atau 'pajak pengembalian dana'.",
    micro_lesson: "Korban penipuan sangat rentan ditipu DUA KALI. Layanan pengaduan OJK atau Polri 100% GRATIS dan tidak pernah menjanjikan 'dana pasti kembali hari ini juga'. Jangan pernah mentransfer uang kepada pihak yang mengaku bisa mengembalikan uang curianmu.",
    weight_category: "high"
  },
  {
    id: "fraud_81",
    category: "Pig Butchering Scam / Modus Salah Sambung",
    threat_level: "Critical",
    action: "Jangan tanggapi pesan dari orang tak dikenal yang mencoba membangun keakraban, terutama jika obrolan mulai mengarah ke pamer kekayaan atau ajakan investasi kripto.",
    keywords: ["salah sambung", "maaf", "teman", "trading", "kripto", "bitcoin", "bimbingan", "profit", "kaya", "meta online", "investasi"],
    patterns: [
      "maaf salah sambung ini bukan nomor pak",
      "boleh simpan nomor saya untuk nambah teman",
      "saya sedang sibuk trading kripto",
      "mari saya bimbing trading bareng",
      "dapatkan profit konsisten tiap hari",
      "saya punya info orang dalam untuk koin ini",
      "gabung ke platform meta online",
      "saya sudah kaya dari trading mari ikut"
    ],
    analysis_result: "Ini adalah modus **Pig Butchering Scam** (Penipuan Penyembelihan Babi), kejahatan transnasional yang sedang merajalela. Pelaku (biasanya beroperasi dari sindikat di luar negeri) mengirim chat WA/Telegram dengan alasan 'salah sambung'. Jika dibalas, mereka mulai merayu, membangun kedekatan emosional/asmara selama berminggu-minggu (menggemukkan babi). Setelah korban percaya, mereka ditawari investasi fiktif berbunga tinggi. Ujungnya, uang tidak bisa ditarik dan pelaku menghilang (menyembelih babi).",
    micro_lesson: "Investasi asli tidak ditawarkan lewat perkenalan 'salah sambung' di WhatsApp. Jika seseorang yang baru kamu kenal di internet terus-menerus pamer kesuksesan finansial dan mengajakmu berinvestasi di platform asing, itu 100% Pig Butchering Scam.",
    weight_category: "critical"
  },
  {
    id: "fraud_82",
    category: "Sextortion (Pemerasan Video Call Intim)",
    threat_level: "Critical",
    action: "JANGAN pernah melakukan video call tanpa busana dengan siapapun di internet. Jika sudah terjadi, jangan transfer uang karena mereka akan terus memeras. Laporkan ke polisi.",
    keywords: ["video call", "vc", "bugil", "sebar", "viral", "bayar", "tebusan", "malu", "rekam", "telanjang", "intim", "open cs"],
    patterns: [
      "mau video call asik gak",
      "aku udah rekam video call kita",
      "bayar atau video mu aku sebar",
      "aku viralin video telanjang mu",
      "transfer sekarang kalau nggak mau malu",
      "video vc mu udah aku kirim ke temanmu",
      "open cs bayar transfer dulu",
      "tebus video ini 5 juta"
    ],
    analysis_result: "Ini adalah tindak kejahatan pemerasan seksual atau **Sextortion**. Pelaku biasanya menggunakan akun profil palsu perempuan/laki-laki menarik, mengajak korban melakukan *video call* berbau seksual. Tanpa disadari, pelaku merekam layar korban. Setelah itu, wajah dan video korban digunakan sebagai senjata untuk memeras uang secara terus-menerus dengan ancaman akan disebarkan ke keluarga/teman di sosmed.",
    micro_lesson: "Membayar pemeras TIDAK AKAN menghentikan ancaman, mereka justru akan meminta lebih banyak karena tahu kamu takut. Segera matikan akun sosmed sementara, jangan bayar, kumpulkan bukti, dan lapor ke kepolisian cyber crime.",
    weight_category: "critical"
  },
  {
    id: "fraud_83",
    category: "Penipuan Jual Beli Segitiga (Properti/Kendaraan)",
    threat_level: "High",
    action: "JANGAN PERNAH mentransfer uang ke rekening yang namanya berbeda dengan nama pemilik sah barang (sesuai STNK/Sertifikat) atau orang yang kamu temui langsung.",
    keywords: ["jual mobil", "jual motor", "jual tanah", "segitiga", "perantara", "transfer ke istri", "transfer ke suami", "jangan bahas harga", "orang saya"],
    patterns: [
      "nanti orang saya yang lihat barangnya",
      "transfernya ke rekening istri saya saja",
      "jangan bahas harga dengan orang di rumah",
      "saya suruh teknisi ngecek mobilnya",
      "nanti stnk sama bpkb langsung diserahkan",
      "uangnya ditransfer ke saya barang diambil dia",
      "saya perantara pemilik aslinya",
      "nanti yang ke sana adik saya"
    ],
    analysis_result: "Ini adalah **Modus Penipuan Segitiga**. Pelaku menipu dua pihak sekaligus: Penjual asli dan Pembeli asli. Pelaku berpura-pura jadi pembeli ke penjual asli, dan berpura-pura jadi penjual ke pembeli asli. Pelaku menyuruh Pembeli asli untuk mengecek barang ke Penjual asli, namun melarang mereka membahas harga. Saat sepakat, Pembeli mentransfer uang ke rekening PENIPU, bukan ke Penjual asli. Akibatnya, Pembeli kehilangan uang, dan Penjual asli tidak mau memberikan barang karena merasa belum dibayar.",
    micro_lesson: "Saat bertransaksi COD barang bernilai tinggi: (1) Bahas harga langsung di tempat, jangan diam saja. (2) TRANSFER HANYA KE NAMA PEMILIK ASLI YANG MEMBAWA BARANG/STNK. Abaikan instruksi untuk mentransfer ke 'rekening istri/suami/saudara' dari orang di WhatsApp.",
    weight_category: "high"
  },
  {
    id: "fraud_84",
    category: "Penipuan eSIM / Transfer Nomor",
    threat_level: "Critical",
    action: "JANGAN pernah scan QR code eSIM dari orang yang tidak dikenal. Transfer nomor eSIM hanya dilakukan di gerai provider resmi.",
    keywords: ["esim", "qr esim", "scan esim", "transfer nomor", "pindah esim", "aktivasi esim", "esim baru", "ganti esim", "qr code esim", "esim digital"],
    patterns: [
      "scan qr esim ini untuk aktivasi",
      "transfer nomor ke esim baru",
      "pindah esim ke hp baru lewat qr",
      "esim anda perlu diaktivasi ulang",
      "scan kode qr untuk esim",
      "download esim dari link ini",
      "esim tidak aktif scan untuk perbaiki",
      "kirim qr esim untuk verifikasi"
    ],
    analysis_result: "Ini adalah modus **Penipuan eSIM / Transfer Nomor** yang berkembang pesat di 2025-2026. Pelaku meminta korban scan QR code eSIM yang sebenarnya adalah kode transfer nomor. Saat QR di-scan, nomor telepon korban secara resmi dipindahkan ke perangkat penipu (dikenal sebagai SIM swap generasi baru). Dengan menguasai nomor HP korban, pelaku bisa menerima semua OTP perbankan, reset password akun digital, dan menguras rekening. Modus ini lebih berbahaya dari SIM swap tradisional karena prosesnya lebih cepat dan sulit dilacak.",
    micro_lesson: "eSIM bisa ditransfer hanya dengan scan QR code—itulah mengapa penipu sangat menginginkanmu scan QR mereka. JANGAN pernah scan QR eSIM dari sumber tidak resmi. Aktivasi eSIM HANYA melalui aplikasi provider (MyTelkomsel, myIM3, MyXL) atau gerai resmi.",
    weight_category: "critical"
  },
  {
    id: "fraud_85",
    category: "Phishing via Threads / Platform Sosial Baru",
    threat_level: "High",
    action: "Waspadai DM atau mention di Threads/Bluesky/Telegram yang mengarahkan ke tautan login. Platform baru sering jadi target phishing karena moderasi belum ketat.",
    keywords: ["threads", "bluesky", "mastodon", "dm", "direct message", "mention", "tag", "login", "verifikasi", "centang", "verified", "follow", "link bio"],
    patterns: [
      "cek link di bio threads ku",
      "mention di threads untuk klaim",
      "verifikasi akun threads di sini",
      "login untuk dapat centang biru",
      "follow back di threads ya",
      "dm aku di threads untuk info",
      "threads official minta verifikasi",
      "klik link dari threads untuk konfirmasi"
    ],
    analysis_result: "Ini adalah modus **Phishing via Platform Sosial Baru** (Threads, Bluesky, Mastodon). Saat platform baru booming, penipu memanfaatkan fakta bahwa pengguna belum familiar dengan keamanan platform tersebut. Pelaku mengirim DM atau mention yang mengaku dari 'Tim Threads' atau 'Threads Official', meminta verifikasi akun atau login melalui tautan palsu. Karena platform baru biasanya memiliki celah keamanan dan moderasi yang belum matang, penipuan lebih mudah menyebar.",
    micro_lesson: "Platform sosial baru (Threads, Bluesky) TIDAK PERNAH meminta login atau verifikasi melalui DM/mention. Semua verifikasi akun dilakukan melalui pengaturan aplikasi. Jika ada yang minta klik tautan untuk 'dapat centang biru' = 100% penipuan.",
    weight_category: "high"
  },
  {
    id: "fraud_86",
    category: "Scam Telegram Premium / Telegram Stars",
    threat_level: "High",
    action: "Jangan beli Telegram Premium atau Stars dari penjual pihak ketiga di luar aplikasi resmi. Pembelian hanya melalui pengaturan Telegram.",
    keywords: ["telegram premium", "telegram stars", "stars", "premium telegram", "beli stars", "beli premium", "gift premium", "donasi stars", "top up stars", "telegram paid"],
    patterns: [
      "jual telegram premium murah",
      "beli stars telegram harga agen",
      "telegram premium diskon 50 persen",
      "gift premium telegram untukmu",
      "top up stars telegram via wa",
      "donasi stars telegram ke channel",
      "beli premium telegram bayar transfer",
      "stars telegram grosir murah"
    ],
    analysis_result: "Ini adalah modus **Scam Telegram Premium / Telegram Stars**. Telegram Stars adalah mata uang digital di Telegram untuk membayar layanan premium, channel berbayar, dan donasi ke kreator. Pelaku menjual Telegram Premium atau Stars dengan harga sangat murah melalui WhatsApp/Telegram pihak ketiga. Setelah transfer, pembeli tidak pernah menerima Stars, atau menerima Stars curian yang kemudian di-revoke oleh Telegram. Modus lain: phishing yang mengaku dari 'Telegram Official' untuk mencuri akun.",
    micro_lesson: "Pembelian Telegram Premium dan Stars HANYA melalui pengaturan di aplikasi Telegram resmi. Penjual pihak ketiga yang menawarkan harga murah hampir pasti menggunakan metode ilegal (kartu kredit curian, dsb) yang bisa berakibat akunmu diblokir.",
    weight_category: "high"
  },
  {
    id: "fraud_87",
    category: "Penipuan Deepfake Video Call Real-Time",
    threat_level: "Critical",
    action: "Jika video call dengan kenalan online terasa 'aneh' (gerakan bibir tidak sinkron, wajah terlalu mulus, cahaya tidak natural), kemungkinan besar itu deepfake. Akhiri panggilan dan verifikasi melalui cara lain.",
    keywords: ["video call", "vc", "deepfake", "wajah palsu", "ai video", "face swap", "tidak mau ketemu", "gerakan aneh", "bibir tidak sinkron", "wajah terlalu mulus", "video call aneh"],
    patterns: [
      "video call gerakannya aneh",
      "bibir tidak sinkron dengan suara",
      "wajah di video call terlalu mulus",
      "video call seperti bukan orang asli",
      "cahaya di wajah tidak natural",
      "dia tidak mau video call lama",
      "video call cuma sebentar langsung mati",
      "vc tapi wajahnya seperti efek filter"
    ],
    analysis_result: "Ini adalah modus **Deepfake Video Call Real-Time** yang sangat canggih dan berbahaya di 2025-2026. Berbeda dengan deepfake statis (foto/video), teknologi kini memungkinkan manipulasi wajah secara real-time saat video call. Pelaku menggunakan software face-swap (seperti DeepFaceLive) untuk menampilkan wajah orang lain di kamera mereka saat video call. Tanda-tandanya: gerakan bibir tidak sinkron dengan suara, wajah terlalu mulus/ideal, cahaya di wajah berbeda dengan latar belakang, dan pelaku selalu membatasi durasi video call.",
    micro_lesson: "Deepfake video call sudah sangat canggih di 2026—bisa meniru wajah siapapun secara real-time. Verifikasi kenalan online dengan: (1) meminta gerakan spesifik (tunjukkan tangan, putar kepala), (2) perhatikan sinkronisasi bibir-suara, (3) cek apakah cahaya di wajah konsisten dengan lingkungan, (4) jika ragu, minta video call sambil pegang kertas bertuliskan nama/kode tertentu.",
    weight_category: "critical"
  }
];

export const SCAM_DB: ScamDatabaseItem[] = [
  {
    "id": "fraud_01",
    "category": "Phishing Paket / Kurir APK",
    "threat_level": "High",
    "action": "Jangan klik tautan atau mengunduh aplikasi! Kurir resmi tidak akan meminta update alamat via tautan tak dikenal yang memaksa instalasi file APK.",
    "keywords": ["paket", "kurir", "alamat", "ekspedisi", "resi", "tertunda", "jnt", "jne", "sicepat", "anteraja", "wahana", "pos", "tiki", "lazada", "shopee express", "paket gagal", "gagal kirim", "pengiriman", "alamat tidak ditemukan", "update alamat"],
    "patterns": [
      "paket anda tertunda",
      "kurir tidak menemukan alamat anda",
      "silakan cek resi di aplikasi apk ini",
      "untuk memperbarui alamat pengiriman",
      "lihat foto resi paket",
      "paket gagal dikirim",
      "paket anda gagal dikirim karena alamat tidak lengkap",
      "download aplikasi untuk melihat status pengiriman",
      "kurir sudah 2 kali mengantar tapi alamat salah",
      "konfirmasi ulang alamat pengiriman anda",
      "paket dari shopee/lazada sedang dalam masalah",
      "update alamat pengiriman sebelum paket dikembalikan",
      "silahkan download apk resi dibawah ini",
      "buka file ini untuk cek foto kurir di depan rumah"
    ],
    "analysis_result": "Ini adalah ciri khas **Modus Penipuan Kurir/Paket APK**. Pelaku menyamar sebagai kurir dari JNE, J&T, SiCepat, atau Shopee Express dan meminta kamu menginstal file APK dengan dalih 'cek resi' atau 'update alamat'. Jika diinstal, aplikasi ini dapat mencuri data pribadimu, membaca SMS (termasuk OTP), dan menguras saldo bank atau e-wallet. Modus ini juga dikenal sebagai Sniffing Phishing.",
    "micro_lesson": "File berakhiran .APK di luar Google Play Store ibarat memberikan kunci rumahmu pada orang asing. Kurir resmi TIDAK PERNAH mengirim file APK—mereka menelepon atau WA biasa jika alamat bermasalah."
  },
  {
    "id": "fraud_02",
    "category": "Undian Palsu WhatsApp / SMS",
    "threat_level": "Critical",
    "action": "Blokir nomor ini dan abaikan. Perusahaan resmi hanya mengumumkan pemenang undian lewat aplikasi resmi, televisi, atau surat resmi—BUKAN pesan WA/SMS dari nomor tidak dikenal.",
    "keywords": ["undian", "selamat", "pemenang", "hadiah", "juta", "shopee", "tokopedia", "bank", "kampanye", "klaim", "menang", "grand prize", "lucky draw", "keberuntungan", "undian berhadiah", "roda keberuntungan", "hadiah utama", "mobil", "motor", "emas"],
    "patterns": [
      "selamat nomor anda terpilih",
      "memenangkan undian",
      "uang tunai",
      "dari kampanye",
      "klik link berikut untuk klaim",
      "info resmi pemenang",
      "selamat anda memenangkan grand prize",
      "nomor anda beruntung mendapatkan hadiah",
      "anda terpilih sebagai pemenang ke",
      "klaim hadiah sebelum tanggal",
      "hubungi kami untuk proses pengambilan hadiah",
      "transfer biaya pengiriman hadiah",
      "pajak hadiah harus dibayar dulu",
      "roda keberuntungan shopee/tokopedia",
      "selamat dari telkomsel poin reward"
    ],
    "analysis_result": "Ini merupakan modus **Klaim Undian/Hadiah Palsu (Phishing Info)**. Pelaku mengirim pesan yang mengaku dari Shopee, Tokopedia, Telkomsel, atau bank bahwa kamu memenangkan undian. Tautan pendek digunakan untuk menyembunyikan situs phishing. Setelah membuka tautan, kamu diminta membayar 'pajak hadiah' atau 'biaya pengiriman' yang sebenarnya tidak pernah ada. Bahkan ada yang meminta login untuk mencuri akun marketplace kamu.",
    "micro_lesson": "Setiap promosi hadiah asli TIDAK PERNAH memungut biaya sepeserpun, dan selalu tercatat di dalam aplikasi resmi. Jika diminta transfer untuk 'klaim hadiah', itu 100% penipuan."
  },
  {
    "id": "fraud_03",
    "category": "Tautan Perbankan Palsu (Bank Phishing)",
    "threat_level": "Critical",
    "action": "Tutup tautan itu segera, jangan pernah isi informasi apapun. Login hanya pada aplikasi mobile banking resmi (BCA Mobile, BRImo, Livin by Mandiri, BNI Mobile).",
    "keywords": ["bank", "verifikasi", "akun", "terblokir", "aktivitas", "mencurigakan", "bca", "bri", "mandiri", "bni", "btn", "cimb", "permata", "danamon", "mega", "sinarmas", "muamalat", "bukopin", "m-banking", "mobile banking", "internet banking", "kartu atm", "kartu kredit", "debit", "transaksi", "saldo"],
    "patterns": [
      "klikbca-verifikasi-akun",
      "kami mendeteksi aktivitas mencurigakan",
      "segera klik link di bawah ini",
      "akun anda akan diblokir",
      "menghindari pemblokiran permanen",
      "verifikasi akun bca anda segera",
      "transaksi tidak dikenal sebesar rp",
      "kartu atm anda akan dinonaktifkan",
      "update data nasabah segera",
      "klik link untuk buka blokir rekening",
      "brimo anda terkunci",
      "livin mandiri perlu verifikasi ulang",
      "login untuk konfirmasi transaksi terakhir",
      "akun mobile banking akan suspended",
      "kami dari bca pusat meminta verifikasi"
    ],
    "analysis_result": "Situs atau pesan ini mencoba melakukan **Phishing Kredensial Bank**. Pelaku membuat website yang 100% mirip dengan tampilan BCA, BRI, Mandiri, atau BNI. URL palsu biasanya mengandung kata 'verifikasi', '-id', 'secure-', atau domain aneh seperti .xyz, .top, .buzz. Setelah kamu memasukkan User ID dan PIN, pelaku langsung menguras rekeningmu.",
    "micro_lesson": "Pihak Bank TIDAK PERNAH mengirim SMS/WA dengan tautan login. Jika ragu, buka langsung aplikasi BCA Mobile, BRImo, Livin, atau BNI Mobile dari HP—JANGAN dari tautan pesan."
  },
  {
    "id": "fraud_04",
    "category": "Surat Tilang Digital Palsu (APK)",
    "threat_level": "High",
    "action": "Abaikan pesannya. Polisi tidak mengirimkan file APK untuk surat tilang. Cek tilang ETLE hanya melalui aplikasi Korlantas Polri resmi.",
    "keywords": ["tilang", "surat", "polisi", "etle", "pelanggaran", "kendaraan", "lalu lintas", "apk", "korlantas", "e-tilang", "denda", "pelanggar", "ranmor", "plat nomor", "stnk", "sim"],
    "patterns": [
      "surat tilang digital format apk",
      "anda terdeteksi melanggar lalu lintas",
      "silakan buka aplikasi untuk melihat bukti",
      "buka file untuk membayar denda",
      "anda tercatat melanggar rambu lalu lintas",
      "download surat tilang digital",
      "bukti pelanggaran cctv etle",
      "bayar denda tilang sebelum rekening diblokir",
      "plat kendaraan anda terdeteksi melanggar",
      "foto pelanggaran silahkan buka file ini"
    ],
    "analysis_result": "Ini adalah modus **File APK Berbahaya berkedok Surat Tilang**. Dengan dalih ketakutan kamu saat ditilang ETLE, pelaku menyisipkan malware ke HP kamu melalui file APK. Malware ini bisa mencuri SMS (termasuk OTP bank), merekam layar, dan menguras rekening. Polisi asli TIDAK PERNAH mengirim file APK.",
    "micro_lesson": "Surat tilang ETLE asli dikirimkan FISIK melalui PT Pos Indonesia ke alamat STNK, atau bisa dicek di aplikasi resmi Korlantas Polri. Tidak pernah via APK."
  },
  {
    "id": "fraud_06",
    "category": "Undangan Pernikahan Digital Palsu (APK)",
    "threat_level": "High",
    "action": "Jangan buka atau instal file apapun dari nomor tidak dikenal! Undangan pernikahan asli berbentuk gambar/PDF/tautan website, BUKAN file .apk.",
    "keywords": ["undangan", "pernikahan", "nikah", "resepsi", "mohon doa restu", "hadir", "akad", "walimahan", "tasyakuran", "khitbah", "lamaran", "pernikahan digital", "undangan digital", "mempelai", "pelaminan"],
    "patterns": [
      "undangan pernikahan digital",
      "mohon doa restunya",
      "harap konfirmasi kehadiran",
      "surat undangan pernikahan digital",
      "cek detail undangan di file ini",
      "buka file untuk lihat lokasi",
      "kami mengundang ke acara pernikahan",
      "download undangan pernikahan kami",
      "file undangan pernikahan dari hp",
      "mohon buka file untuk detail acara",
      "undangan dari teman lama",
      "buka apk undangan nikah"
    ],
    "analysis_result": "Ini adalah **Modus APK Undangan Pernikahan Palsu** yang sangat marak di Indonesia. File .apk berukuran ~6.6MB ini terlihat seperti undangan digital biasa, namun jika diinstal ia akan meminta izin akses SMS, kontak, dan notifikasi. Dengan akses itu, pelaku dapat mencegat kode OTP dari bank, m-banking, dan e-wallet kamu, lalu menguras saldo dalam hitungan menit.",
    "micro_lesson": "Undangan asli selalu berupa gambar (.jpg/.png), PDF, atau tautan website—BUKAN file .apk. Jika seseorang mengirim file .apk dengan dalih apapun, langsung hapus dan blokir."
  },
  {
    "id": "fraud_07",
    "category": "Penipuan Quishing (QR Code Phishing)",
    "threat_level": "High",
    "action": "Jangan sembarangan scan QR Code dari sumber tidak dikenal atau yang ditempel di tempat umum. Selalu verifikasi asal-usul QR sebelum memindai.",
    "keywords": ["qr", "qr code", "scan", "pindai", "kode qr", "barcode", "bayar", "voucher", "cashback", "qris", "stiker qr", "tempel qr"],
    "patterns": [
      "scan qr code ini untuk klaim hadiah",
      "pindai kode untuk verifikasi akun",
      "bayar dengan scan qr berikut",
      "scan untuk dapatkan cashback",
      "konfirmasi pembayaran via qr code",
      "qr code berhadiah",
      "scan qr untuk dapat diskon",
      "pindai barcode untuk klaim voucher",
      "scan qris berikut untuk pembayaran",
      "tempel qr code palsu di merchant"
    ],
    "analysis_result": "Ini adalah modus **Quishing** (gabungan QR Code + Phishing) yang marak di 2026. QR code palsu mengarahkan kamu ke situs tiruan yang mencuri data login, atau bahkan langsung menginstal malware. Modus lain: QR code palsu ditempel menimpa QRIS asli di merchant/restoran, sehingga pembayaran kamu justru masuk ke rekening penipu.",
    "micro_lesson": "Sebelum scan QR, perhatikan apakah QR itu ditempel menimpa stiker lain (tanda QR palsu). Untuk pembayaran, pastikan nama merchant muncul setelah scan. Gunakan kamera bawaan yang menampilkan preview URL."
  },
  {
    "id": "fraud_08",
    "category": "Penipuan Deepfake & AI (Investasi/Tokoh Publik)",
    "threat_level": "Critical",
    "action": "Jangan percaya video promosi investasi dari tokoh publik di media sosial! Video tersebut bisa dipalsukan dengan AI Deepfake. Selalu cek legalitas platform investasi di ojk.go.id.",
    "keywords": ["investasi", "profit", "keuntungan", "return", "kripto", "trading", "saham", "deposito", "endorse", "pejabat", "artis", "selebriti", "deepfake", "ai", "presiden", "menteri", "gubernur", "robot trading", "auto profit", "copy trading", "signal trading", "trading bot"],
    "patterns": [
      "bergabung sekarang dapatkan keuntungan",
      "return 10 persen per bulan",
      "investasi modal kecil untung besar",
      "platform trading terpercaya",
      "sudah terbukti menguntungkan",
      "pak presiden merekomendasikan",
      "artis terkenal sudah membuktikan",
      "penawaran terbatas hari ini saja",
      "video ini bukti pak jokowi/prabowo dukung",
      "robot trading auto profit setiap hari",
      "copy trading dari trader profesional",
      "deposit minimal 500 ribu profit 10 juta",
      "keuntungan konsisten tanpa risiko",
      "sudah ribuan member berhasil",
      "gabung grup VIP signal trading"
    ],
    "analysis_result": "Ini adalah **Penipuan Investasi Bodong berbasis Deepfake AI**. Pelaku membuat video palsu menggunakan AI yang memperlihatkan tokoh publik, pejabat, atau artis seolah-olah merekomendasikan platform investasi. Teknologi deepfake sudah sangat canggih—suara dan wajah hampir tidak bisa dibedakan dari aslinya. Modus lain: robot trading yang menjanjikan profit otomatis, padahal skema Ponzi. OJK mencatat kerugian triliunan rupiah dari modus ini.",
    "micro_lesson": "Tidak ada investasi legal yang menawarkan return di atas 10% per bulan secara konsisten. Video tokoh publik bisa dipalsukan AI. Cek SELALU izin OJK di ojk.go.id sebelum menyetor uang ke platform apapun."
  },
  {
    "id": "fraud_09",
    "category": "Penipuan Impersonasi Aparat/Jaksa (Vishing)",
    "threat_level": "Critical",
    "action": "Tutup telepon segera! Polisi/Jaksa TIDAK PERNAH menelepon meminta uang jaminan via transfer. Jika ragu, datangi kantor polisi/kejaksaan terdekat secara langsung.",
    "keywords": ["polisi", "jaksa", "pengadilan", "kasus", "tersangka", "pencucian uang", "rekening", "diblokir", "jaminan", "penyidik", "bareskrim", "kejaksaan", "polri", "polda", "polres", "tipikor", "narkoba", "teroris", "makar", "penggelapan", "penipuan", "penyelundupan"],
    "patterns": [
      "ini dari kepolisian",
      "rekening anda terlibat pencucian uang",
      "anda ditetapkan sebagai tersangka",
      "transfer uang jaminan agar kasus ditutup",
      "video call dengan seragam polisi",
      "ini penyidik dari bareskrim",
      "jangan ceritakan ke siapapun",
      "anda terlibat kasus narkoba",
      "surat panggilan dari kejaksaan",
      "rekening anda dipakai untuk penipuan",
      "anda dilaporkan oleh seseorang",
      "bayar jaminan untuk hindari penahanan",
      "ini dari polda metro jaya",
      "kami akan kirim surat perintah penangkapan",
      "anda wajib kooperatif atau kami jemput paksa"
    ],
    "analysis_result": "Ini adalah **Penipuan Impersonasi Aparat Hukum (Vishing)**. Pelaku menelepon atau video call menggunakan seragam/atribut polisi/jaksa palsu—kini bahkan menggunakan teknologi AI voice cloning agar suaranya terdengar sangat meyakinkan. Korban diancam terlibat kasus hukum serius (pencucian uang, narkoba, terorisme), lalu dipaksa mentransfer 'uang jaminan'. Instruksi 'jangan ceritakan ke siapapun' adalah tanda merah terbesar.",
    "micro_lesson": "Aparat hukum resmi TIDAK PERNAH meminta uang lewat telepon/WA. Semua proses hukum resmi melalui surat panggilan fisik dan gelar perkara di kantor. Instruksi 'jangan bilang siapapun' = 100% penipuan."
  },
  {
    "id": "fraud_10",
    "category": "Penipuan Pemulihan Dana (Recovery Scam)",
    "threat_level": "High",
    "action": "Abaikan semua tawaran pemulihan dana dari pihak tidak dikenal. Laporan resmi hanya ke IASC (Indonesia Anti Scam Centre) atau OJK 157—TANPA BIAYA.",
    "keywords": ["dana", "kembali", "pulihkan", "recovery", "blokir", "rekening diblokir", "korban penipuan", "bantu cairkan", "tim resmi", "administrasi", "refund", "dana sitaan", "bantuan hukum", "pengacara", "klaim ganti rugi", "dana bekas penipuan"],
    "patterns": [
      "kami bisa membantu mengembalikan dana anda",
      "sebagai korban penipuan anda berhak",
      "kami adalah tim pemulihan resmi",
      "bayar biaya administrasi dulu",
      "rekening anda akan dibuka setelah transfer",
      "kami dari ojk recovery center",
      "kami dari bareskrim bagian pemulihan dana",
      "dana sitaan kasus penipuan bisa dicairkan",
      "bayar biaya pengacara untuk proses klaim",
      "kami sudah melacak uang anda",
      "transfer biaya notaris untuk cairkan dana",
      "proses refund butuh biaya verifikasi"
    ],
    "analysis_result": "Ini adalah **Recovery Scam (Penipuan Pemulihan Dana)**—modus paling kejam karena menargetkan orang yang SUDAH menjadi korban penipuan sebelumnya. Pelaku mengaku dari OJK, Bareskrim, atau 'tim pemulihan resmi' yang bisa mengembalikan uang korban. Syaratnya: bayar biaya administrasi, pengacara, atau notaris. Uang yang ditransfer TIDAK AKAN PERNAH menghasilkan apa-apa—korban ditipu untuk kedua kalinya.",
    "micro_lesson": "Tidak ada layanan pemulihan dana resmi yang meminta biaya di muka. Semua proses pemulihan di IASC/OJK GRATIS. Laporkan di ojk.go.id atau hubungi 157."
  },
  {
    "id": "fraud_11",
    "category": "Pig Butchering / Romance Scam Investasi",
    "threat_level": "Critical",
    "action": "Waspada dengan kenalan online yang terlalu perhatian dan tiba-tiba mengajak investasi atau meminjam uang. Putuskan hubungan dan jangan transfer sepeserpun.",
    "keywords": ["kenalan", "teman baru", "sayang", "perhatian", "investasi bersama", "platform trading", "profit bersama", "transfer dulu", "darurat", "pinjam", "cinta", "jodoh", "serius", "hubungan", "masa depan", "nikah", "kencan", "dating", "match", "tinder", "bumble", "tantan"],
    "patterns": [
      "halo aku menemukan kontakmu",
      "kita pernah bertemu sebelumnya",
      "aku sedang trading kripto menguntungkan",
      "mau investasi bersama aku",
      "aku perlu bantuan dana darurat",
      "nanti aku ganti setelah cair",
      "sudah dapat profit besar minggu ini",
      "aku punya sistem trading yang tidak pernah rugi",
      "aku sayang kamu tolong bantu aku",
      "aku di luar negeri butuh bantuan transfer",
      "investasi di platform ini dijamin aman",
      "aku sudah profit ratusan juta",
      "gabung sebelum kuota penuh",
      "aku tidak punya siapa-siapa selain kamu"
    ],
    "analysis_result": "Ini adalah **Modus Pig Butchering (Romance Scam + Investasi)**—penipuan paling berbahaya secara psikologis. Pelaku membangun hubungan emosional intens selama berminggu-minggu atau berbulan-bulan melalui dating app atau media sosial. Setelah korban jatuh cinta ('digemukkan' secara emosional), pelaku mengajak investasi di platform trading palsu atau meminjam uang untuk 'keadaan darurat'. Setelah uang terkirim, pelaku menghilang total.",
    "micro_lesson": "Kenalan online yang sangat perhatian lalu tiba-tiba membahas uang, investasi, atau minta bantuan darurat = ALARM BESAR. Verifikasi identitas asli (video call, foto bareng teman) sebelum percaya. Jangan pernah transfer ke orang yang belum pernah kamu temui langsung."
  },
  {
    "id": "fraud_05",
    "category": "Lowongan Kerja & Misi Palsu (Task Scam)",
    "threat_level": "High",
    "action": "Jangan transfer uang deposit atau komitmen apapun. Kerja asli TIDAK PERNAH meminta kamu membayar di muka.",
    "keywords": ["lowongan", "tugas", "misi", "komisi", "like", "subscribe", "deposit", "paruh waktu", "kerja", "freelance", "part time", "gaji harian", "penghasilan tambahan", "kerja online", "kerja dari rumah", "tugas harian", "tiktok", "youtube", "shopee affiliate", "misi harian", "upgrade akun"],
    "patterns": [
      "lowongan kerja dari rumah",
      "kami mencari pekerja lepas",
      "Anda hanya perlu like youtube atau follow",
      "untuk mendapatkan komisi misi lanjutan",
      "bayar deposit garansi",
      "gaji rp 500 ribu per hari",
      "tugas hanya like dan subscribe",
      "deposit rp 200 ribu untuk akses misi",
      "kerja 2 jam sehari gaji jutaan",
      "upgrade akun premium untuk misi besar",
      "komisi langsung cair ke rekening",
      "rekrutmen karyawan online",
      "tugas review produk dapat komisi",
      "transfer deposit keamanan pekerjaan",
      "misi selanjutnya butuh top up dulu"
    ],
    "analysis_result": "Hati-Hati! Pesan ini masuk ke skema **Penipuan Tugas / Task Scam / Skema Ponzi**. Di awal kamu mungkin mendapat bayaran kecil (20-50 ribu) untuk meyakinkan. Lalu kamu disuruh 'upgrade' atau transfer deposit untuk mengakses misi dengan komisi lebih besar. Setelah transfer, uangmu tidak akan pernah kembali. Modus ini juga beroperasi di grup Telegram/WA dengan struktur seperti MLM.",
    "micro_lesson": "Kerja asli itu membayarmu, BUKAN kamu yang membayar mereka. Jika diminta deposit, upgrade, atau top up untuk dapat kerja = PASTI penipuan."
  },
  {
    "id": "fraud_12",
    "category": "SMS Pajak/Listrik/Tagihan Palsu",
    "threat_level": "High",
    "action": "Jangan klik tautan dari SMS tagihan yang mencurigakan. Cek tagihan pajak/listrik/air hanya melalui aplikasi resmi instansi terkait.",
    "keywords": ["pajak", "tagihan", "listrik", "pln", "pdam", "terhutang", "belum dibayar", "denda", "sanksi", "mati lampu", "pemutusan", "token", "kwh", "pascabayar", "prabayar", "bpjs", "pbb", "spt", "pph", "e-billing", "kode billing"],
    "patterns": [
      "tagihan listrik anda belum dibayar",
      "pajak kendaraan anda akan diblokir",
      "segera bayar tagihan sebelum diputus",
      "anda memiliki tunggakan pajak",
      "bayar sekarang untuk menghindari denda",
      "tagihan air bulan ini belum lunas",
      "token listrik segera expired",
      "bayar melalui link berikut",
      "spt tahunan anda bermasalah",
      "bayar pbb sebelum aset disita",
      "tagihan bpjs kesehatan terhutang",
      "pemutusan listrik dalam 24 jam",
      "bayar pajak kendaraan online di sini",
      "e-billing pajak silahkan bayar via link",
      "tagihan pdam bulan ini menunggak"
    ],
    "analysis_result": "Ini adalah modus **SMS Phishing Tagihan Palsu**. Pelaku mengirim SMS yang seolah-olah dari PLN, PDAM, BPJS, Dirjen Pajak, atau instansi pemerintah dengan tujuan menakut-nakuti. Tautan palsu mengarah ke situs tiruan yang mencuri data pembayaran, nomor kartu kredit/debit, atau OTP. Modus ini sangat efektif karena memanfaatkan ketakutan akan denda atau pemutusan layanan.",
    "micro_lesson": "Instansi resmi (PLN, PDAM, Pajak, BPJS) TIDAK PERNAH mengirim SMS dengan tautan pembayaran. Cek dan bayar hanya melalui PLN Mobile, e-Pajak, JKN Mobile, atau aplikasi resmi lainnya."
  },
  {
    "id": "fraud_13",
    "category": "SMS/WA Hadiah Provider & Poin Palsu",
    "threat_level": "High",
    "action": "Abaikan SMS/WA hadiah dari provider. Operator resmi hanya mengumumkan pemenang melalui aplikasi resmi—BUKAN tautan SMS.",
    "keywords": ["telkomsel", "indosat", "xl", "tri", "axis", "poin", "reward", "hadiah", "undian", "pemenang", "voucher", "smartfren", "by.u", "mytelkomsel", "myim3", "myxl", "kuota", "pulsa", "cashback"],
    "patterns": [
      "selamat anda mendapatkan hadiah",
      "poin telkomsel anda terpilih",
      "klaim hadiah di",
      "anda memenangkan voucher belanja",
      "nomor anda beruntung",
      "klik untuk ambil hadiah",
      "reward indosat poin",
      "poin tri anda bisa ditukar",
      "klaim kuota gratis di link ini",
      "selamat dari smartfren anda dapat hadiah",
      "voucher shopee dari telkomsel poin",
      "pulsa gratis klaim sekarang",
      "reward xl prioritas untuk anda"
    ],
    "analysis_result": "Ini adalah modus **SMS/WA Phishing Hadiah Provider**. Pelaku mengirim pesan yang mengaku dari Telkomsel, Indosat, XL, Tri, atau Smartfren dengan klaim poin terpilih atau memenangkan hadiah. Tautan mengarah ke situs phishing yang meminta data pribadi, nomor rekening, atau menginstal malware. Modus ini sangat meyakinkan karena menggunakan nama brand provider yang kamu pakai.",
    "micro_lesson": "Cek poin dan reward provider HANYA melalui aplikasi resmi (MyTelkomsel, myIM3, MyXL, Bima+). Operator resmi tidak pernah mengirim tautan klaim hadiah via SMS."
  },
  {
    "id": "fraud_14",
    "category": "WhatsApp Minta OTP / Takeover Akun",
    "threat_level": "Critical",
    "action": "JANGAN PERNAH memberikan kode OTP kepada siapapun. OTP adalah kunci akunmu—yang meminta OTP = yang mengambil alih akunmu.",
    "keywords": ["otp", "kode verifikasi", "salah kirim otp", "masukkin kode", "kirim otp", "butuh otp", "konfirmasi kode", "kode 6 digit", "pin verifikasi", "sms masuk", "kode whatsapp", "kode telegram"],
    "patterns": [
      "tolong kirimkan kode otp yang masuk",
      "aku salah kirim otp ke nomormu",
      "masukkan kode verifikasi ini",
      "aku butuh kode yang masuk ke hpmu",
      "bantu konfirmasi kode",
      "tolong kasih tau kode yang sms masuk",
      "aku lagi daftar ulang butuh otp",
      "kode 6 digit yang masuk ke sms kamu",
      "aku lagi ganti hp butuh verifikasi",
      "tolong screenshot kode yang masuk",
      "aku salah input nomor jadi otp-nya ke kamu",
      "pin verifikasi yang sms barusan apa"
    ],
    "analysis_result": "Ini adalah modus **WhatsApp Takeover Akun (Minta OTP)**. Pelaku sudah mengetahui nomor HP kamu dan sedang mencoba login ke akun WhatsApp/Telegram/sosmed milikmu. Mereka pura-pura mengirim OTP 'ke nomor yang salah' dan memintamu memberikan kode tersebut. Jika kamu berikan, akunmu akan direbut dan digunakan untuk menipu semua kontakmu—bahkan meminta uang dengan mengatasnamakan kamu.",
    "micro_lesson": "OTP (One Time Password) adalah KUNCI AKUN PRIBADIMU. Tidak ada alasan logis orang lain meminta OTPmu. Jika ada yang minta kode OTP = mereka sedang mencoba MEREBAK akunmu. Langsung blokir."
  },
  {
    "id": "fraud_15",
    "category": "WhatsApp CEO/Boss Scam (BEC)",
    "threat_level": "Critical",
    "action": "Verifikasi langsung ke atasanmu melalui saluran resmi (telepon kantor, email internal). Jangan pernah transfer hanya berdasarkan pesan WhatsApp.",
    "keywords": ["transfer", "urgent", "segera", "rahasia", "klien", "vendor", "rekening", "atasan", "bos", "direktur", "manager", "keuangan", "accounting", "pembayaran", "invoice", "termin"],
    "patterns": [
      "ini bos saya ganti nomor",
      "tolong segera transfer ke rekening ini",
      "ada pembayaran urgent ke vendor",
      "jangan bilang siapapun soal ini",
      "saya sedang rapat tidak bisa telepon",
      "proses sekarang nanti saya ganti",
      "ini untuk klien penting",
      "tolong belikan voucher game",
      "saya butuh bantuan transfer hari ini",
      "ini rekening baru vendor",
      "bayar invoice ini sekarang juga",
      "tolong proses pembayaran ke nomor rekening",
      "saya di luar kota tolong handle ini",
      "rahasia jangan sampai hr tahu"
    ],
    "analysis_result": "Ini adalah modus **CEO/Boss Scam (BEC - Business Email/WhatsApp Compromise)**. Pelaku menyamar sebagai atasan, direktur, atau manager keuangan perusahaanmu, lalu meminta transfer mendadak ke rekening baru dengan alasan mendesak. Mereka sengaja menciptakan urgensi ('sekarang juga'), kerahasiaan ('jangan bilang siapapun'), dan otoritas ('ini perintah bos') agar kamu tidak sempat verifikasi. Kerugian perusahaan dari modus ini bisa mencapai ratusan juta.",
    "micro_lesson": "Setiap permintaan transfer dari 'atasan' via WhatsApp/email WAJIB dikonfirmasi langsung melalui telepon ke nomor yang sudah tersimpan. Penipu mengandalkan rasa takut dan hormatmu untuk tidak bertanya."
  },
  {
    "id": "fraud_16",
    "category": "Bantuan Sosial / Bansos / Subsidi Palsu",
    "threat_level": "High",
    "action": "Abaikan tawaran bantuan sosial dari pesan tidak dikenal. Bansos resmi TIDAK PERNAH dipungut biaya atau diminta melalui SMS/WhatsApp.",
    "keywords": ["bansos", "bantuan sosial", "blt", "bpnt", "pkh", "kemensos", "pemerintah", "subsidi", "bantuan pemerintah", "cair", "klaim bantuan", "bst", "bpum", "umkm", "prakerja", "kip", "kis", "pnpm", "dtkl", "dtks"],
    "patterns": [
      "anda terdaftar sebagai penerima bansos",
      "klaim bantuan sosial sekarang",
      "bantuan pemerintah sudah cair",
      "isi formulir untuk dapat blt",
      "transfer biaya administrasi bansos",
      "bantuan subsidi segera hangus",
      "verifikasi data penerima bantuan",
      "anda dapat bpum umkm sebesar",
      "klaim bantuan prakerja di link ini",
      "dana bst sudah masuk segera cairkan",
      "subsidi listrik pemerintah klaim di sini",
      "kartu indonesia pintar perlu aktivasi",
      "verifikasi penerima kis kesehatan"
    ],
    "analysis_result": "Ini adalah modus **Penipuan Bansos/Bantuan Sosial Palsu**. Pelaku mengaku dari instansi pemerintah dan menginformasikan bahwa kamu berhak menerima bantuan (BLT, BPNT, PKH, BPUM, BST). Untuk mencairkannya, kamu diminta mengisi formulir di tautan palsu atau mentransfer 'biaya administrasi'. Bansos resmi TIDAK PERNAH dipungut biaya dan tidak pernah diminta melalui pesan WA/SMS.",
    "micro_lesson": "Bansos resmi dari pemerintah TIDAK PERNAH meminta biaya administrasi. Cek status bansos hanya di dtks.kemensos.go.id atau datangi langsung kelurahan/desa setempat."
  },
  {
    "id": "fraud_17",
    "category": "Email Phishing Akun Digital (Netflix, Google, dll)",
    "threat_level": "Critical",
    "action": "Jangan klik tautan dalam email yang meminta verifikasi akun. Buka langsung situs resmi dari browser atau aplikasi untuk mengecek status akunmu.",
    "keywords": ["akun", "ditangguhkan", "expired", "verifikasi", "login", "password", "keamanan", "suspended", "unusual activity", "netflix", "google", "facebook", "instagram", "tiktok", "spotify", "apple", "microsoft", "amazon", "paypal", "steam", "playstation", "xbox"],
    "patterns": [
      "akun anda akan ditangguhkan",
      "kami mendeteksi login dari perangkat baru",
      "verifikasi akun anda sekarang",
      "password anda akan expired",
      "akun anda telah dibekukan",
      "klik di sini untuk mengamankan akun",
      "unusual activity detected",
      "your account has been limited",
      "seseorang mencoba login dari lokasi berbeda",
      "akun netflix anda akan dihentikan",
      "google: someone has your password",
      "konfirmasi pembayaran apple id",
      "verifikasi akun microsoft anda",
      "akun instagram anda dilaporkan"
    ],
    "analysis_result": "Ini adalah modus **Email Phishing Akun Layanan Digital**. Email ini dibuat sangat mirip dengan email resmi dari Netflix, Google, Apple, Microsoft, Facebook, Instagram, atau layanan digital lainnya. Tujuannya menipu kamu agar mengklik tautan dan memasukkan kredensial login di situs palsu. Setelah mendapatkan username dan password, pelaku bisa mengakses dan mengambil alih akunmu yang sebenarnya.",
    "micro_lesson": "Perusahaan besar TIDAK PERNAH meminta password melalui email. Jika ragu, langsung ketik URL situs resmi di browser—JANGAN klik tautan dari email. Aktifkan 2FA di semua akun penting."
  },
  {
    "id": "fraud_18",
    "category": "Email Invoice / Tagihan / Faktur Palsu",
    "threat_level": "High",
    "action": "Jangan langsung membayar invoice dari email yang tidak dikenal. Verifikasi ke pihak terkait langsung melalui kontak resmi mereka.",
    "keywords": ["invoice", "faktur", "tagihan", "pembayaran", "jatuh tempo", "purchase order", "po", "kwitansi", "billing", "termin", "down payment", "dp", "pelunasan"],
    "patterns": [
      "silakan cek invoice terlampir",
      "pembayaran jatuh tempo segera",
      "faktur pajak belum dibayar",
      "tagihan layanan anda",
      "silakan lakukan pembayaran ke rekening",
      "invoice po nomor",
      "reminder pembayaran overdue",
      "lampiran faktur pembayaran",
      "segera lunasi invoice berikut",
      "pembayaran termin 2 sudah jatuh tempo",
      "down payment proyek belum diterima",
      "tagihan hosting/domain sudah expired"
    ],
    "analysis_result": "Ini adalah modus **Email Invoice/Tagihan Palsu (Fake Invoice Scam)**. Pelaku mengirim email dengan lampiran PDF atau link yang berisi invoice palsu untuk layanan yang tidak pernah kamu pesan. Tujuannya agar kamu panik dan langsung membayar ke rekening penipu, atau membuka lampiran PDF yang mengandung malware. Modus ini sangat efektif menargetkan UMKM dan bagian keuangan perusahaan.",
    "micro_lesson": "Jangan pernah membayar tagihan dari email tanpa verifikasi. Periksa apakah kamu benar-benar berlangganan layanan tersebut. Hubungi penyedia layanan melalui kontak resmi yang sudah ada—bukan dari email tagihan."
  },
  {
    "id": "fraud_19",
    "category": "Email Reset Password / Account Recovery Palsu",
    "threat_level": "Critical",
    "action": "Jangan klik tautan reset password yang tidak kamu minta. Jika tidak merasa meminta reset, abaikan email tersebut dan langsung aktifkan 2FA.",
    "keywords": ["reset password", "ubah kata sandi", "recovery", "pulihkan akun", "lupa password", "change password", "account recovery", "two factor", "2fa", "verifikasi identitas"],
    "patterns": [
      "klik di sini untuk reset password",
      "seseorang meminta reset kata sandi",
      "kami menerima permintaan pemulihan akun",
      "jika ini bukan anda abaikan email ini",
      "reset your password now",
      "your password reset link",
      "confirm your identity",
      "someone tried to reset your password",
      "verifikasi identitas untuk keamanan akun",
      "klik tautan berikut untuk ubah password",
      "permintaan reset kata sandi diterima",
      "pulihkan akun anda yang terkunci"
    ],
    "analysis_result": "Ini adalah modus **Email Reset Password Palsu**. Pelaku mengirim email seolah-olah dari layanan yang kamu gunakan, mengklaim ada permintaan reset password. Tautan dalam email mengarah ke situs phishing yang mencatat password baru yang kamu masukkan. Ironisnya, kamu justru memberikan akses akunmu sendiri kepada penipu.",
    "micro_lesson": "Jika kamu tidak meminta reset password, JANGAN KLIK tautannya. Langsung buka situs resmi dan cek aktivitas akunmu. Aktifkan 2FA dengan aplikasi authenticator (bukan SMS) untuk keamanan maksimal."
  },
  {
    "id": "fraud_20",
    "category": "Domain Typosquatting & Brand Spoofing",
    "threat_level": "Critical",
    "action": "Selalu periksa URL dengan teliti sebelum memasukkan data login. Perhatikan ejaan domain—penipu mengganti huruf mirip (o→0, l→1, rn→m).",
    "keywords": ["login", "signin", "masuk", "verifikasi", "secure", "account", "update", "official", "resmi"],
    "patterns": [
      "tok0pedia.com",
      "sh0pee.co.id",
      "bca-verifikasi.com",
      "gojek-promo.com",
      "grab-indonesia.com",
      "secure-bca.net",
      "login-bri.com",
      "google-security.com",
      "facebook-login.net",
      "instagram-verify.com",
      "tokopedia-login.co",
      "mandiri-online.xyz",
      "bni-m-banking.com",
      "bukalapak-promo.com",
      "dana-ewallet.com",
      "ovo-cashback.com",
      "gopay-promo.net"
    ],
    "analysis_result": "Ini adalah modus **Domain Typosquatting & Brand Spoofing**. Penipu membuat domain yang sangat mirip dengan situs resmi—mengganti huruf 'o' dengan angka '0', 'l' dengan '1', menambahkan kata seperti 'secure-', 'login-', 'verify-', atau menggunakan domain aneh (.xyz, .top, .buzz, .club). Situs tiruan ini meniru 100% tampilan situs asli untuk mencuri kredensial login kamu.",
    "micro_lesson": "Sebelum login, SELALU periksa URL di address bar. Domain resmi Tokopedia = tokopedia.com (bukan tok0pedia.com). Bookmark situs penting. Domain .co.id, .go.id lebih terpercaya daripada .xyz, .top, .buzz."
  },
  {
    "id": "fraud_21",
    "category": "Crypto Airdrop & Token Scam (Drainer)",
    "threat_level": "Critical",
    "action": "Jangan hubungkan wallet ke situs airdrop yang tidak terverifikasi. Airdrop resmi TIDAK PERNAH meminta seed phrase atau approve unlimited spending.",
    "keywords": ["airdrop", "token", "crypto", "wallet", "connect wallet", "claim", "free", "nft", "swap", "approve", "seed phrase", "metamask", "phantom", "trust wallet", "defi", "dex", "uniswap", "pancakeswap", "solana", "ethereum", "bitcoin", "web3"],
    "patterns": [
      "claim your free airdrop",
      "connect wallet untuk klaim",
      "limited airdrop token",
      "approve to receive",
      "swap token sebelum expired",
      "free nft claim now",
      "seed phrase recovery",
      "verifikasi wallet anda",
      "airdrop token gratis limited",
      "connect metamask untuk klaim",
      "approve unlimited spending",
      "claim free solana airdrop",
      "nft giveaway connect wallet",
      "seed phrase untuk verifikasi",
      "swap sebelum liquidity lock"
    ],
    "analysis_result": "Ini adalah modus **Crypto Drainer / Airdrop Scam**. Pelaku membuat situs palsu yang meniru airdrop token populer atau NFT giveaway. Saat kamu menghubungkan wallet, situs meminta approval transaksi yang sebenarnya memberikan izin untuk menarik SELURUH aset crypto dari wallet-mu. Modus lain: meminta seed phrase untuk 'verifikasi'—padahal siapapun yang punya seed phrase punya akses penuh ke wallet-mu.",
    "micro_lesson": "Jangan pernah hubungkan wallet ke situs yang tidak dikenal. Airdrop resmi tidak meminta 'unlimited approval' atau seed phrase. Gunakan Revoke.cash untuk cek dan batalkan approval mencurigakan. Seed phrase = nyawa wallet-mu."
  },
  {
    "id": "fraud_22",
    "category": "WhatsApp Lowongan Kerja Luar Negeri (TKI/PMI)",
    "threat_level": "Critical",
    "action": "Jangan percaya tawaran kerja luar negeri via WhatsApp. Pastikan agen penyalur terdaftar di BP2MI dan miliki SIP3MI resmi.",
    "keywords": ["kerja luar negeri", "tki", "pmi", "malaysia", "singapura", "taiwan", "hongkong", "jepang", "korea", "arab saudi", "qatar", "dubai", "gaji dollar", "agen penyalur", "proses cepat", "paspor", "disnaker", "bp2mi", "sip3mi", "depo", "penempatan"],
    "patterns": [
      "lowongan kerja ke malaysia",
      "gaji 3000 ringgit sebulan",
      "proses cepat tanpa tes",
      "butuh paspor dan biaya agen",
      "kerja di singapura gaji dollar",
      "agen resmi penyalur tki",
      "siap berangkat dalam 1 minggu",
      "transfer biaya penempatan",
      "kerja di jepang gaji 200 ribu yen",
      "lowongan pmi taiwan gaji besar",
      "agen resmi penyalur ke korea",
      "butuh biaya depo untuk proses",
      "kerja di dubai tanpa pengalaman",
      "kontrak 2 tahun akomodasi ditanggung"
    ],
    "analysis_result": "Ini adalah modus **Penipuan Tawaran Kerja Luar Negeri**. Pelaku menawarkan pekerjaan di luar negeri dengan gaji tinggi melalui WhatsApp, meminta korban menyetor biaya 'agen', 'depo', atau 'penempatan'. Setelah uang ditransfer, pelaku menghilang atau korban justru menjadi korban perdagangan orang (human trafficking). Modus ini sangat berbahaya karena menargetkan masyarakat ekonomi lemah.",
    "micro_lesson": "Tawaran kerja luar negeri yang meminta biaya di muka = RED FLAG besar. Pastikan agen penyalur terdaftar di bp2mi.go.id dan miliki SIP3MI resmi. Proses penempatan TKI/PMI resmi TIDAK dimulai dari WhatsApp."
  },
  {
    "id": "fraud_23",
    "category": "SMS/WA Pura-pura Kenal (Minta Pulsa/Transfer)",
    "threat_level": "High",
    "action": "Verifikasi identitas melalui video call atau hubungi kontak lamamu. Jangan transfer uang ke nomor yang tidak bisa diverifikasi.",
    "keywords": ["ingat aku", "teman lama", "pulsa", "transfer", "pinjam", "darurat", "kecelakaan", "rumah sakit", "tolong", "nomor baru", "mantan", "teman kuliah", "teman sekolah", "saudara", "sepupu", "paman", "tante"],
    "patterns": [
      "hai ingat aku nggak",
      "ini nomor baruku",
      "tolong isiin pulsa dulu",
      "aku kecelakaan butuh uang",
      "pinjam dulu nanti aku ganti",
      "aku di rumah sakit",
      "ini aku teman lama",
      "tolong transfer ke nomor ini",
      "ini nomor baru pamanmu",
      "aku kehabisan pulsa tolong belikan",
      "tolong bayarkan ojol dulu",
      "aku di luar kota dompet ketinggalan",
      "ini sepupumu tolong butuh bantuan",
      "aku kehilangan hp ini hp pinjaman"
    ],
    "analysis_result": "Ini adalah modus **Impersonasi Teman/Keluarga (Pura-pura Kenal)**. Pelaku menghubungi kamu seolah-olah teman lama, keluarga, atau saudara, lalu meminta bantuan keuangan mendesak. Mereka menggunakan nomor baru dan mengandalkan rasa sungkan atau kasihan agar kamu langsung transfer tanpa verifikasi. Modus ini sangat efektif karena memanfaatkan empati dan rasa tidak enak.",
    "micro_lesson": "Jika seseorang mengaku kenal tapi menggunakan nomor baru, WAJIB verifikasi melalui video call atau hubungi kontak lamamu yang tersimpan. Penipu paling ahli memainkan emosi—jangan biarkan rasa sungkan mengalahkan logika."
  },
  {
    "id": "fraud_24",
    "category": "Situs E-commerce Palsu / Toko Online Fiktif",
    "threat_level": "High",
    "action": "Belanja hanya di marketplace resmi dengan sistem rekening bersama (escrow). Jangan transfer langsung ke rekening penjual dari link di sosmed/WhatsApp.",
    "keywords": ["diskon", "flash sale", "promo", "harga grosir", "stok terbatas", "gratis ongkir", "COD", "whatsapp order", "transfer langsung", "clearance sale", "warehouse sale", "garage sale", "closing sale"],
    "patterns": [
      "diskon 90 persen hari ini",
      "flash sale stok terbatas",
      "order via whatsapp",
      "harga grosir termurah",
      "transfer ke rekening ini untuk proses",
      "gratis ongkir seindonesia",
      "sepatu branded harga 100 ribu",
      "iphone murah garansi toko",
      "clearance sale semua barang habis",
      "warehouse sale branded ori harga 50rb",
      "closing toko semua diskon besar",
      "garage sale barang import",
      "harga distributor tanpa perantara",
      "order dulu barang dikirim besok"
    ],
    "analysis_result": "Ini adalah modus **Toko Online Fiktif / E-commerce Palsu**. Pelaku membuat website atau akun sosmed yang menjual barang branded dengan harga sangat murah (diskon 80-90%). Setelah kamu transfer, barang tidak dikirim, yang datang barang kw/tidak sesuai, atau toko langsung tutup. Tanpa sistem rekening bersama (escrow), uangmu tidak bisa dikembalikan.",
    "micro_lesson": "Jika harga terlalu murah untuk barang branded (iPhone 2 juta, sepatu Nike 100 ribu), hampir pasti itu penipuan. Belanja di marketplace dengan rekening bersama (Tokopedia, Shopee, Lazada) agar uang aman sampai barang diterima."
  },
  {
    "id": "fraud_25",
    "category": "OTP Bajak Akun (SIM Swap / SS7)",
    "threat_level": "Critical",
    "action": "Jika tiba-tiba menerima OTP tanpa permintaanmu, segera hubungi provider dan bank. Jangan berikan kode OTP ke siapapun.",
    "keywords": ["otp", "kode", "verifikasi", "nomor anda", "aktivasi", "registrasi", "sim", "kartu", "sms masuk", "kode masuk", "one time password"],
    "patterns": [
      "kode otp anda adalah",
      "jangan bagikan kode ini",
      "verifikasi nomor telepon",
      "aktivasi akun baru",
      "kode masuk anda",
      "someone requested your code",
      "your verification code is",
      "kode otp untuk login",
      "jangan bagikan kode ini ke siapapun",
      "your whatsapp code is"
    ],
    "analysis_result": "Menerima OTP tanpa diminta adalah tanda seseorang sedang mencoba **membajak akunmu**. Modus ini bisa berupa: (1) SIM Swap—pelaku mengganti kartu SIM kamu di gerai provider, (2) serangan SS7 yang mencegat SMS, atau (3) pelaku sudah tahu nomor HPmu dan mencoba login. Jika kamu memberikan kode OTP yang 'salah kirim' ke nomor lain, kamu justru membantu pelaku mengambil alih akunmu.",
    "micro_lesson": "OTP yang masuk tanpa kamu minta = seseorang sedang mencoba login ke akunmu. JANGAN berikan kode itu ke siapapun. Langsung ubah password, hubungi provider untuk cek SIM swap, dan aktifkan 2FA authenticator."
  },
  {
    "id": "fraud_26",
    "category": "Pinjaman Online (Pinjol) Ilegal Palsu",
    "threat_level": "Critical",
    "action": "Jangan pernah mengajukan pinjaman melalui tautan SMS/WhatsApp. Pinjol legal terdaftar di OJK dan TIDAK PERNAH meminta biaya di muka.",
    "keywords": ["pinjaman", "pinjol", "kredit", "cair", "dana cepat", "tanpa jaminan", "tanpa bi checking", "bunga rendah", "proses cepat", "cicilan", "tenor", "plafon", "pengajuan", "acc cepat", "dana instan"],
    "patterns": [
      "pinjaman cair dalam 5 menit",
      "dana cepat tanpa jaminan",
      "ajukan pinjaman tanpa bi checking",
      "bunga rendah 0 persen",
      "proses acc cepat 1 jam",
      "plafon hingga 50 juta",
      "transfer biaya asuransi dulu",
      "bayar biaya verifikasi untuk cairkan",
      "pinjaman online terdaftar ojk",
      "cicilan ringan tanpa survey",
      "dana instan langsung ke rekening",
      "biaya admin dulu sebelum pinjaman cair"
    ],
    "analysis_result": "Ini adalah modus **Pinjaman Online (Pinjol) Ilegal**. Pelaku menawarkan pinjaman mudah dengan bunga rendah melalui SMS/WhatsApp. Setelah kamu mengajukan, mereka meminta transfer 'biaya asuransi', 'biaya verifikasi', atau 'biaya admin' di muka. Setelah ditransfer, pinjaman tidak pernah cair dan pelaku menghilang. Pinjol ilegal juga bisa mengakses kontak dan foto di HP-mu untuk mengancam saat penagihan.",
    "micro_lesson": "Pinjol legal TIDAK PERNAH meminta biaya di muka. Cek daftar pinjol legal di ojk.go.id. Proses pinjaman resmi melalui aplikasi di Play Store/App Store, bukan dari tautan SMS/WhatsApp."
  },
  {
    "id": "fraud_27",
    "category": "Donasi / Sedekah / Amal Palsu",
    "threat_level": "High",
    "action": "Jangan transfer donasi ke rekening pribadi dari pesan tidak dikenal. Salurkan donasi melalui platform resmi seperti Kitabisa, Dompet Dhuafa, atau lembaga terverifikasi.",
    "keywords": ["donasi", "sedekah", "amal", "zakat", "infaq", "bantuan", "galang dana", "penggalangan", "derma", "yatim", "duafa", "bencana", "musibah", "kemanusiaan"],
    "patterns": [
      "bantu saudara kita yang terkena musibah",
      "donasi untuk anak yatim",
      "sedekah jumat ke rekening ini",
      "galang dana untuk biaya operasi",
      "bantuan korban bencana alam",
      "zakat dan infaq ke nomor rekening",
      "donasi kemanusiaan segera dibutuhkan",
      "transfer donasi ke rekening pribadi",
      "bantu biaya sekolah anak kurang mampu",
      "amal jariyah untuk pembangunan masjid"
    ],
    "analysis_result": "Ini adalah modus **Donasi/Sedekah Palsu**. Pelaku memanfaatkan empati dan rasa kemanusiaan untuk mengumpulkan uang melalui rekening pribadi. Mereka menggunakan foto-foto menyedihkan dari internet, mengaku dari yayasan yang tidak ada, atau membuat cerita musibah palsu. Uang yang terkumpul masuk ke kantong penipu, bukan ke yang membutuhkan.",
    "micro_lesson": "Salurkan donasi melalui platform terverifikasi (Kitabisa, Dompet Dhuafa, BAZNAS, Rumah Zakat). Jangan transfer ke rekening pribadi dari pesan WA yang tidak bisa diverifikasi keasliannya."
  },
  {
    "id": "fraud_28",
    "category": "Asuransi & BPJS Palsu",
    "threat_level": "High",
    "action": "Verifikasi informasi asuransi/BPJS melalui aplikasi resmi atau call center. Jangan klik tautan dari SMS/WA yang mengaku dari BPJS atau asuransi.",
    "keywords": ["asuransi", "bpjs", "klaim", "polis", "premi", "santunan", "jaminan", "kesehatan", "kematian", "kecelakaan", "jiwa", "unit link", "auto debit"],
    "patterns": [
      "polis asuransi anda akan hangus",
      "klaim asuransi segera cair",
      "bpjs kesehatan anda tidak aktif",
      "bayar premi sebelum polis dibatalkan",
      "santunan asuransi jiwa bisa diklaim",
      "verifikasi bpjs melalui link ini",
      "auto debit gagal segera perbarui",
      "klaim asuransi kecelakaan butuh verifikasi",
      "update data bpjs sebelum kartu diblokir",
      "polis unit link anda sudah jatuh tempo"
    ],
    "analysis_result": "Ini adalah modus **Phishing Asuransi & BPJS**. Pelaku mengirim pesan yang mengaku dari BPJS Kesehatan, perusahaan asuransi, atau agen asuransi. Mereka mengancam polis akan hangus, BPJS tidak aktif, atau menawarkan klaim palsu. Tautan mengarah ke situs phishing yang mencuri data pribadi dan finansial. Modus lain: agen asuransi nakal yang menjual produk tidak sesuai.",
    "micro_lesson": "Cek status BPJS di aplikasi JKN Mobile atau bpjs-kesehatan.go.id. Untuk asuransi, hubungi call center resmi perusahaan—jangan dari nomor/tautan di SMS/WA."
  },
  {
    "id": "fraud_29",
    "category": "Top-Up Game / Voucher Palsu",
    "threat_level": "High",
    "action": "Top-up game dan beli voucher hanya melalui platform resmi (Codashop, UniPin, Google Play, App Store). Jangan dari tautan WhatsApp/Telegram.",
    "keywords": ["top up", "diamond", "voucher", "game", "mobile legends", "free fire", "pubg", "genshin", "steam", "google play", "itunes", "gift card", "uc", "ml", "ff", "codashop", "unipin"],
    "patterns": [
      "top up diamond murah",
      "voucher google play diskon 50 persen",
      "jual diamond ml ff harga grosir",
      "top up free fire via wa",
      "gift card steam murah",
      "beli uc pubg harga reseller",
      "top up genshin genesis crystal murah",
      "voucher itunes promo",
      "transfer dulu top up diproses",
      "codashop reseller harga agen"
    ],
    "analysis_result": "Ini adalah modus **Top-Up Game & Voucher Palsu**. Pelaku menawarkan diamond, UC, atau voucher game dengan harga sangat murah melalui WhatsApp/Telegram/media sosial. Setelah kamu transfer, item tidak dikirim atau akun game kamu justru diretas. Modus lain: situs top-up palsu yang mencuri data akun Google/game kamu.",
    "micro_lesson": "Beli diamond, UC, dan voucher game HANYA dari platform resmi (Codashop, UniPin, Google Play, App Store). Harga yang terlalu murah dari penjual WA = pasti penipuan atau barang ilegal."
  },
  {
    "id": "fraud_30",
    "category": "Travel & Umroh/Haji Palsu",
    "threat_level": "Critical",
    "action": "Pastikan biro travel/umroh memiliki izin resmi dari Kemenag. Cek daftar PPIU resmi di kemenag.go.id sebelum menyetor uang.",
    "keywords": ["umroh", "haji", "travel", "paket wisata", "liburan", "tiket", "pesawat", "hotel", "promo travel", "biro perjalanan", "ppiu", "kemenag", "onh", "bpih"],
    "patterns": [
      "paket umroh murah 20 juta",
      "promo travel ke eropa",
      "tiket pesawat diskon besar",
      "paket haji plus tanpa tunggu",
      "biro umroh berangkat bulan depan",
      "hotel bintang 5 harga bintang 3",
      "transfer dp untuk booking seat",
      "paket wisata halal harga spesial",
      "umroh plus turki promo terbatas",
      "biro travel terpercaya berangkat pasti"
    ],
    "analysis_result": "Ini adalah modus **Biro Travel & Umroh/Haji Palsu**. Pelaku menawarkan paket umroh, haji, atau wisata dengan harga sangat murah dan berangkat cepat. Setelah transfer DP atau pelunasan, biro menghilang atau berangkat tidak pernah terjadi. Modus ini sangat merugikan karena uang yang dikumpulkan biasanya puluhan hingga ratusan juta per korban.",
    "micro_lesson": "Pastikan biro travel/umroh memiliki izin PPIU dari Kemenag (cek di kemenag.go.id). Harga umroh di bawah 25 juta patut dicurigai. Jangan pernah transfer ke rekening pribadi—pastikan ke rekening perusahaan."
  },
  {
    "id": "fraud_31",
    "category": "Giveaway Sosmed / Influencer Palsu",
    "threat_level": "High",
    "action": "Giveaway resmi dari influencer/brand TIDAK PERNAH meminta transfer atau data pribadi. Jika diminta bayar = pasti penipuan.",
    "keywords": ["giveaway", "gratis", "menang", "undian", "influencer", "youtuber", "tiktok", "selebgram", "followers", "give away", "doorprize", "lucky draw", "grand prize"],
    "patterns": [
      "selamat anda menang giveaway",
      "transfer biaya pengiriman hadiah",
      "giveaway dari youtuber terkenal",
      "anda terpilih dari followers",
      "klaim hadiah giveaway di link",
      "bayar pajak hadiah dulu",
      "giveaway iphone gratis",
      "menang undian dari tiktok",
      "selamat dari selebgram dapat hadiah",
      "klik link untuk klaim giveaway"
    ],
    "analysis_result": "Ini adalah modus **Giveaway Sosmed / Influencer Palsu**. Pelaku mengaku dari influencer, YouTuber, atau brand terkenal dan menginformasikan kamu memenangkan giveaway. Untuk mengklaim, kamu diminta membayar 'biaya pengiriman', 'pajak hadiah', atau mengisi data pribadi di tautan palsu. Giveaway resmi TIDAK PERNAH meminta uang dari pemenang.",
    "micro_lesson": "Giveaway asli diumumkan di akun resmi influencer/brand (cek centang biru). Pemenang tidak diminta transfer apapun. Jika diminta bayar untuk klaim hadiah = 100% penipuan."
  },
  {
    "id": "fraud_32",
    "category": "Grup WA Investasi / Sinyal Trading",
    "threat_level": "Critical",
    "action": "Keluar dari grup WhatsApp/Telegram yang menawarkan sinyal trading atau investasi. Grup semacam ini hampir pasti skema Ponzi atau pump-and-dump.",
    "keywords": ["grup", "sinyal", "trading", "signal", "vip", "join grup", "komunitas", "trader", "analisis", "profit", "cuan", "rekomendasi saham", "copy trade", "pump"],
    "patterns": [
      "join grup vip signal trading",
      "sinyal trading akurat 99 persen",
      "komunitas trader profit konsisten",
      "rekomendasi saham hari ini",
      "copy trade dari master trader",
      "gabung grup investasi eksklusif",
      "signal crypto pasti profit",
      "join channel vip gratis",
      "analisis market harian akurat",
      "trading bareng profit besar"
    ],
    "analysis_result": "Ini adalah modus **Grup Investasi/Sinyal Trading Palsu**. Pelaku mengundang kamu ke grup WhatsApp/Telegram yang berisi 'sinyal trading' atau 'rekomendasi investasi'. Di awal mungkin profit kecil untuk membangun kepercayaan, lalu kamu disuruh deposit besar. Grup ini biasanya berisi akun-akun fake yang memposting testimoni palsu. Ujung-ujungnya: platform trading yang kamu gunakan adalah milik penipu, dan uangmu tidak bisa ditarik.",
    "micro_lesson": "Tidak ada sinyal trading yang 'akurat 99%' atau 'pasti profit'. Grup investasi yang meminta deposit ke platform tertentu hampir pasti skema. Investasi resmi melalui broker terdaftar di OJK/BEI."
  },
  {
    "id": "fraud_33",
    "category": "SMS/WA Ganti Kartu SIM / Registrasi Ulang",
    "threat_level": "Critical",
    "action": "Jangan pernah mengirimkan nomor KK atau NIK ke nomor tidak dikenal. Registrasi ulang kartu SIM hanya dilakukan di gerai provider resmi.",
    "keywords": ["registrasi", "kartu", "sim", "nik", "kk", "kartu keluarga", "blokir", "aktifkan", "ganti kartu", "upgrade", "4g", "5g", "esim"],
    "patterns": [
      "kartu anda akan diblokir segera registrasi",
      "kirim nik dan kk untuk aktivasi",
      "registrasi ulang kartu sim anda",
      "kartu 3g akan dimatikan upgrade sekarang",
      "verifikasi nik untuk hindari pemblokiran",
      "kartu anda tidak terdaftar segera daftar",
      "ganti kartu 4g gratis kirim nik",
      "registrasi esim melalui wa ini",
      "kartu akan dinonaktifkan dalam 24 jam",
      "kirim foto ktp untuk verifikasi"
    ],
    "analysis_result": "Ini adalah modus **Phishing Data Identitas via Registrasi SIM Card**. Pelaku mengirim SMS/WA yang mengaku dari provider, meminta NIK dan nomor KK untuk 'registrasi ulang' atau 'hindari pemblokiran'. Data identitas (NIK + KK) yang dikumpulkan bisa digunakan untuk: mendaftar pinjol ilegal, membuat rekening bank palsu, atau mendaftar layanan digital atas namamu.",
    "micro_lesson": "Registrasi ulang kartu SIM HANYA dilakukan di gerai provider resmi (MyGraPARI, galeri Indosat, dll) atau melalui SMS ke 4444. JANGAN pernah kirim NIK/KK ke nomor WA/SMS tidak dikenal."
  },
  {
    "id": "fraud_34",
    "category": "Phishing Kurir Internasional (DHL, FedEx, UPS)",
    "threat_level": "High",
    "action": "Jangan klik tautan dari SMS/WA/email yang mengaku dari DHL, FedEx, atau UPS. Lacak paket hanya melalui situs resmi kurir.",
    "keywords": ["dhl", "fedex", "ups", "ems", "paket internasional", "customs", "bea cukai", "pajak impor", "clearance", "tracking", "shipment"],
    "patterns": [
      "paket dhl anda tertahan di bea cukai",
      "bayar pajak impor untuk rilis paket",
      "fedex tracking update klik link",
      "paket ups memerlukan verifikasi",
      "customs clearance butuh pembayaran",
      "shipment anda ditahan di bandara",
      "bayar biaya bea cukai sekarang",
      "paket ems dari luar negeri perlu klaim"
    ],
    "analysis_result": "Ini adalah modus **Phishing Kurir Internasional**. Pelaku mengirim pesan yang mengaku dari DHL, FedEx, UPS, atau EMS, mengklaim paket internasionalmu tertahan di bea cukai. Untuk 'merilis' paket, kamu diminta membayar pajak impor atau biaya clearance melalui tautan palsu. Modus ini sangat efektif karena banyak orang yang memang menunggu paket dari luar negeri.",
    "micro_lesson": "Lacak paket internasional HANYA melalui situs resmi (dhl.com, fedex.com, ups.com). Kurir resmi tidak meminta pembayaran melalui tautan SMS/WA. Pajak impor dibayar melalui sistem pabean, bukan transfer ke rekening."
  },
  {
    "id": "fraud_35",
    "category": "Sewa Properti / Kos / Rumah Fiktif",
    "threat_level": "High",
    "action": "Jangan transfer DP sewa properti tanpa survei langsung. Pastikan properti benar-benar ada dan pemiliknya terverifikasi.",
    "keywords": ["sewa", "kos", "kontrakan", "rumah", "apartemen", "kost", "indekost", "dp", "uang muka", "booking", "hunian", "sewa bulanan", "sewa tahunan"],
    "patterns": [
      "kamar kos tersisa 1 unit",
      "transfer dp untuk booking kamar",
      "sewa apartemen murah di pusat kota",
      "rumah kontrakan harga spesial",
      "bayar uang muka sebelum survei",
      "kost eksklusif fasilitas lengkap",
      "sewa bulanan tanpa agen",
      "properti ini sangat diminati segera booking",
      "transfer dp ke rekening pemilik",
      "indekost putra/putri harga murah"
    ],
    "analysis_result": "Ini adalah modus **Sewa Properti/Kos Fiktif**. Pelaku memasang iklan sewa kos, kontrakan, atau apartemen dengan harga sangat murah di OLX, Facebook Marketplace, atau situs properti. Setelah kamu transfer DP untuk 'booking', pelaku menghilang dan properti ternyata tidak ada atau bukan miliknya. Modus ini sangat merugikan karena DP yang diminta biasanya 1-3 juta.",
    "micro_lesson": "Jangan pernah transfer DP sewa properti SEBELUM survei langsung. Pastikan properti benar-benar ada, pemiliknya jelas, dan minta foto/video real-time. Gunakan platform properti terpercaya dengan verifikasi listing."
  },
  {
    "id": "fraud_36",
    "category": "Sextortion / Pemerasan Video Intim",
    "threat_level": "Critical",
    "action": "Jangan panik dan JANGAN TRANSFER uang! Pelaku biasanya mengancam tanpa bukti. Screenshot semua ancaman, lalu laporkan ke polisi (110) atau cybercrime.polri.go.id.",
    "keywords": ["sextortion", "pemerasan", "video call", "bugil", "telanjang", "sebar", "viral", "malu", "ancam", "rekam", "screenshoot", "intim", "mesum", "porno", "skandal"],
    "patterns": [
      "aku punya video call mu",
      "aku sudah rekam saat kamu bugil",
      "bayar atau video mu aku sebar",
      "transfer atau aku kirim ke keluargamu",
      "aku punya foto telanjang mu",
      "video mu akan aku viral kan",
      "bayar dalam 24 jam atau semua lihat",
      "aku hack kamera hp mu",
      "bayar ke rekening ini atau malu",
      "video call kita tadi malam aku rekam",
      "aku kirim ke semua kontak mu",
      "bayar rp atau hidup mu hancur"
    ],
    "analysis_result": "Ini adalah modus **Sextortion (Pemerasan Video/Foto Intim)**. Pelaku mengancam menyebarkan video atau foto intim korban—padahal seringkali video/foto tersebut tidak ada atau deepfake. Modus ini sangat berbahaya secara psikologis karena memanfaatkan rasa malu dan takut. Pelaku meminta transfer uang berulang kali, dan setelah dibayar, ancaman tidak berhenti—justru diminta lebih banyak.",
    "micro_lesson": "JANGAN PERNAH transfer uang ke pemeras—permintaan mereka TIDAK AKAN pernah berhenti. Screenshot semua bukti ancaman, blokir pelaku, dan laporkan ke polisi (110) atau cybercrime.polri.go.id. Kamu adalah KORBAN, bukan pelaku."
  },
  {
    "id": "fraud_37",
    "category": "Tech Support Scam (Virus Palsu)",
    "threat_level": "High",
    "action": "Tutup pop-up atau browser segera. Jangan hubungi nomor yang tertera. HP/komputer Anda TIDAK terinfeksi virus dari pop-up semacam itu.",
    "keywords": ["virus", "terinfeksi", "malware", "hack", "terkena virus", "windows defender", "keamanan", "system error", "call support", "hubungi teknisi", "pop up", "browser terkunci", "warning", "alert", "critical error"],
    "patterns": [
      "perangkat anda terinfeksi virus",
      "segera hubungi teknisi",
      "browser anda terkunci",
      "windows terdeteksi malware",
      "hubungi support sekarang",
      "peringatan keamanan kritis",
      "system anda dalam bahaya",
      "jangan tutup jendela ini",
      "call toll free untuk perbaikan",
      "data anda sedang dicuri",
      "perangkat diserang virus berbahaya",
      "hubungi nomor berikut untuk bantuan"
    ],
    "analysis_result": "Ini adalah modus **Tech Support Scam**. Pelaku menampilkan pop-up palsu yang mengklaim HP/komputer kamu terinfeksi virus atau malware berbahaya. Pop-up ini biasanya mengunci browser dan meminta kamu menghubungi nomor 'teknisi resmi'. Jika menelepon, kamu akan diminta membayar ratusan ribu hingga jutaan untuk 'perbaikan' yang sebenarnya tidak diperlukan, atau malah memberikan akses remote ke perangkatmu.",
    "micro_lesson": "Pop-up 'virus detected' dari browser adalah SCAM. HP/komputer tidak bisa didiagnosis virus dari pop-up website. Tutup paksa browser (Force Close) dan jangan pernah hubungi nomor yang tertera di pop-up."
  },
  {
    "id": "fraud_38",
    "category": "Penipuan Marketplace (Resi/Bukti Transfer Palsu)",
    "threat_level": "High",
    "action": "Selalu gunakan sistem rekening bersama (escrow) di marketplace. Jangan langsung transfer ke rekening penjual di luar platform. Verifikasi resi di situs kurir resmi.",
    "keywords": ["resi", "bukti transfer", "sudah transfer", "sudah kirim", "no resi", "bukti pembayaran", "konfirmasi transfer", "ss transfer", "bukti tf", "rekening pribadi", "luar marketplace"],
    "patterns": [
      "sudah transfer silahkan cek",
      "ini bukti transfernya",
      "no resi pengiriman",
      "sudah kirim barang tadi pagi",
      "transfer ke rekening ini aja",
      "harga lebih murah di luar marketplace",
      "order via wa aja biar murah",
      "ini screenshot bukti tf",
      "resi pengiriman sudah ada",
      "sudah saya kirim cek resi di sini",
      "bayar langsung ke rekening toko",
      "keluar marketplace biar gratis ongkir"
    ],
    "analysis_result": "Ini adalah modus **Penipuan Marketplace dengan Resi/Bukti Transfer Palsu**. Pelaku yang berpura-pura sebagai penjual meminta kamu keluar dari sistem marketplace dan transfer langsung ke rekening pribadi. Mereka mengirim bukti transfer/resi palsu untuk meyakinkan. Modus lain: penjual nakal yang mengirim resi palsu agar status 'sudah dikirim' padahal barang tidak pernah ada.",
    "micro_lesson": "SELALU belanja di dalam marketplace dengan rekening bersama. Jangan pernah transfer ke rekening pribadi di luar platform. Cek resi pengiriman langsung di situs kurir (jne.co.id, jnt.co.id), bukan dari link yang dikirim penjual."
  },
  {
    "id": "fraud_39",
    "category": "Penipuan Rental Mobil/Motor",
    "threat_level": "High",
    "action": "Jangan transfer DP rental kendaraan tanpa survei langsung. Pastikan rental punya izin usaha dan kendaraan benar-benar ada. Foto STNK dan kendaraan sebelum bayar.",
    "keywords": ["rental", "sewa mobil", "sewa motor", "rent car", "sewa harian", "sewa mingguan", "lepas kunci", "dengan sopir", "rental murah", "dp rental", "booking kendaraan"],
    "patterns": [
      "sewa mobil murah lepas kunci",
      "rental motor harian harga spesial",
      "transfer dp untuk booking kendaraan",
      "sewa mobil dengan sopir murah",
      "rental mobil promo weekend",
      "bayar dp sebelum kendaraan disiapkan",
      "sewa harian 100 ribu",
      "booking sekarang unit terbatas",
      "rent car harga termurah",
      "transfer ke rekening pemilik rental"
    ],
    "analysis_result": "Ini adalah modus **Penipuan Rental Kendaraan**. Pelaku memasang iklan sewa mobil/motor dengan harga sangat murah di media sosial atau OLX. Setelah kamu transfer DP untuk 'booking', pelaku menghilang dan kendaraan ternyata tidak ada. Modus lain: rental fiktif yang mengumpulkan DP dari banyak korban lalu kabur. Kerugian biasanya 500rb-3jt per korban.",
    "micro_lesson": "Sebelum transfer DP rental kendaraan, pastikan: (1) tempat rental benar-benar ada (kunjungi langsung), (2) minta foto STNK dan kendaraan real-time, (3) cek review Google Maps. Jangan pernah DP ke rekening pribadi tanpa verifikasi."
  },
  {
    "id": "fraud_40",
    "category": "Penculikan Anak Digital (Tebusan Palsu)",
    "threat_level": "Critical",
    "action": "Jangan panik! Langsung hubungi anak/keluarga melalui nomor yang sudah ada untuk verifikasi. Jangan transfer sebelum memastikan kondisi anak. Laporkan ke polisi (110).",
    "keywords": ["anak", "diculik", "tebusan", "sandera", "selamatkan", "nyawa", "bahaya", "kecelakaan", "anak anda", "sekolah", "jemput", "pulang"],
    "patterns": [
      "anak anda ada di tangan kami",
      "transfer tebusan atau anak anda celaka",
      "anak anda kecelakaan butuh operasi",
      "jangan telepon polisi atau anak anda",
      "anak anda kami sandera",
      "transfer sekarang atau anak anda",
      "anak anda dalam bahaya",
      "bayar tebusan dalam 1 jam",
      "jangan hubungi siapapun soal ini",
      "anak anda ditahan di lokasi",
      "selamatkan nyawa anak anda",
      "anak anda di rumah sakit butuh uang operasi"
    ],
    "analysis_result": "Ini adalah modus **Penculikan Anak Digital (Virtual Kidnapping)**. Pelaku menghubungi orang tua via WhatsApp/telepon, mengklaim anak mereka diculik atau kecelakaan parah, lalu meminta transfer tebusan mendesak. Padahal anak dalam keadaan aman—pelaku hanya mengandalkan kepanikan orang tua agar langsung transfer tanpa verifikasi. Modus ini sangat kejam karena menyerang insting perlindungan orang tua.",
    "micro_lesson": "Jika menerima kabar anak diculik/kecelakaan: (1) TENANG, jangan panik, (2) hubungi anak langsung di nomornya, (3) hubungi sekolah/keluarga terdekat, (4) JANGAN transfer sebelum verifikasi, (5) laporkan ke 110. Penipu mengandalkan panikmu untuk mencegah berpikir jernih."
  },
  {
    "id": "fraud_41",
    "category": "Penipuan Langganan / Subscription Palsu",
    "threat_level": "High",
    "action": "Jangan klik tautan dalam pesan yang mengklaim langganan akan diperpanjang. Cek status langganan langsung di aplikasi resmi (Netflix, Spotify, dll).",
    "keywords": ["langganan", "subscription", "perpanjang", "diperpanjang", "auto renewal", "perpanjangan otomatis", "netflix", "spotify", "youtube premium", "apple", "google", "amazon prime", "disney", "iflix", "vidio", "wetv"],
    "patterns": [
      "langganan netflix anda akan diperpanjang",
      "pembayaran spotify gagal segera perbarui",
      "subscription youtube premium expired",
      "perpanjangan otomatis apple id",
      "langganan anda akan dibatalkan",
      "update pembayaran untuk layanan",
      "tagihan langganan bulan ini gagal",
      "klik untuk batalkan perpanjangan",
      "akun streaming anda akan ditangguhkan",
      "bayar tagihan langganan sekarang",
      "pembayaran auto debit gagal",
      "langganan disney+ akan hangus"
    ],
    "analysis_result": "Ini adalah modus **Penipuan Langganan/Subscription Palsu**. Pelaku mengirim SMS/WA/email yang mengaku dari Netflix, Spotify, YouTube Premium, Apple, atau layanan streaming lain, mengklaim langganan akan diperpanjang atau pembayaran gagal. Tautan mengarah ke situs phishing yang mencuri data kartu kredit/debit. Korban sering tertipu karena memang berlangganan layanan tersebut.",
    "micro_lesson": "Cek status langganan HANYA di aplikasi resmi atau situs resmi layanan. Jangan klik tautan dari SMS/WA/email yang mengklaim masalah pembayaran. Layanan streaming tidak mengirim tagihan melalui WhatsApp."
  },
  {
    "id": "fraud_42",
    "category": "Penipuan Judi Online / Slot / Togel",
    "threat_level": "Critical",
    "action": "Jangan pernah deposit ke platform judi online. Judi online ilegal di Indonesia dan platformnya dirancang untuk menguras uangmu—tidak ada yang 'pasti menang'.",
    "keywords": ["judi", "slot", "togel", "casino", "poker", "deposit", "withdraw", "maxwin", "jackpot", "gacor", "rtp", "scatter", "bandar", "agen judi", "situs judi", "hoki", "main slot", "pasti menang"],
    "patterns": [
      "main slot pasti menang",
      "deposit 50 ribu bisa maxwin",
      "situs judi online terpercaya",
      "rtp tinggi hari ini",
      "slot gacor anti rungkad",
      "agen judi bonus new member",
      "withdraw berapapun pasti dibayar",
      "deposit pulsa tanpa potongan",
      "togel online diskon besar",
      "bandar casino live terpercaya",
      "kode referral bonus deposit",
      "main poker online uang asli"
    ],
    "analysis_result": "Ini adalah modus **Penipuan Judi Online / Slot / Togel**. Pelaku mengajak kamu bermain di platform judi online yang mengklaim 'pasti menang' atau 'slot gacor'. Di awal mungkin kamu menang kecil untuk memancing, lalu saat deposit besar, kamu kalah terus. Platform judi online ilegal di Indonesia dan TIDAK ADA yang bisa withdraw—uang yang masuk tidak akan pernah kembali. Modus ini juga melanggar UU ITE.",
    "micro_lesson": "Judi online ILEGAL di Indonesia (UU ITE Pasal 27 ayat 2). Platform judi dirancang untuk membuatmu kalah—tidak ada sistem 'gacor' atau 'pasti menang'. Jika ada yang mengajak main slot/togel = mereka agen yang dapat komisi dari kekalahanmu."
  },
  {
    "id": "fraud_43",
    "category": "Penipuan Survey / Review Berbayar (Task Scam Lanjutan)",
    "threat_level": "High",
    "action": "Jangan deposit atau transfer uang untuk 'misi' survey/review. Pekerjaan asli tidak meminta kamu membayar untuk mendapat tugas.",
    "keywords": ["survey", "review", "rating", "bintang", "ulasan", "isi survey", "review produk", "google review", "shopee review", "tiktok review", "misi harian", "tugas review", "komisi review"],
    "patterns": [
      "isi survey dapat uang",
      "review produk dapat komisi",
      "beri rating bintang 5 dapat bayaran",
      "tugas review google maps",
      "misi review shopee tokopedia",
      "deposit untuk akses survey premium",
      "isi survey 5 menit dapat 50 ribu",
      "review hotel dapat komisi",
      "top up dulu untuk misi selanjutnya",
      "tugas rating aplikasi di play store",
      "survey berbayar online",
      "upgrade member untuk survey eksklusif"
    ],
    "analysis_result": "Ini adalah modus **Penipuan Survey/Review Berbayar** yang merupakan variasi dari Task Scam. Pelaku menawarkan pekerjaan mengisi survey atau memberi review dengan bayaran. Di awal kamu dibayar kecil (10-20rb) untuk membangun kepercayaan. Lalu diminta 'upgrade member' atau deposit untuk mengakses survey dengan komisi lebih besar. Setelah deposit besar, uang tidak bisa ditarik.",
    "micro_lesson": "Pekerjaan survey/review yang meminta deposit atau upgrade = PASTI penipuan. Platform survey legit (Google Opinion Rewards, dll) TIDAK PERNAH minta bayaran dari peserta. Kerja asli membayar kamu, bukan sebaliknya."
  },
  {
    "id": "fraud_44",
    "category": "Romance Scam Tentara/Dokter Asing",
    "threat_level": "Critical",
    "action": "Jangan percaya kenalan asing yang mengaku tentara, dokter, atau insinyur di luar negeri. Jangan pernah mengirim uang untuk 'izin cuti', 'biaya dokumen', atau 'tiket pesawat'.",
    "keywords": ["soldier", "military", "doctor", "engineer", "overseas", "deployment", "leave", "cuti", "mission", "peacekeeping", "united nations", "nato", "surgeon", "orthopedic", "widow", "duda", "single parent", "janda", "duda"],
    "patterns": [
      "aku tentara amerika sedang bertugas",
      "aku dokter di yaman/suriah/afghanistan",
      "aku butuh uang untuk izin cuti",
      "tolong bayar biaya dokumen",
      "aku ingin pulang ke indonesia",
      "aku single parent istri meninggal",
      "aku insinyur minyak di rig",
      "aku di misi perdamaian pbb",
      "kirim uang untuk tiket pesawat",
      "aku punya warisan butuh bantuan cairkan",
      "aku jatuh cinta padamu dari foto mu",
      "aku ingin ke indonesia menemuimu"
    ],
    "analysis_result": "Ini adalah modus **Romance Scam dengan Profesi Terpercaya (Tentara/Dokter Asing)**. Pelaku mengaku sebagai tentara AS, dokter di zona konflik, atau insinyur di rig minyak—profesi yang terkesan serius dan terpercaya. Mereka membangun hubungan romantis selama berminggu-minggu, lalu mulai meminta uang untuk berbagai alasan: izin cuti, biaya dokumen, tiket pesawat, atau warisan yang perlu dicairkan. Identitas dan foto yang digunakan selalu dicuri dari orang lain.",
    "micro_lesson": "Tentara, dokter, atau insinyur asing TIDAK AKAN mencari pasangan di Facebook/Instagram dan minta uang. Semua alasan untuk minta uang (cuti, dokumen, tiket) adalah BOHONG. Lakukan reverse image search di Google untuk cek apakah foto profilnya dicuri."
  },
  {
    "id": "fraud_45",
    "category": "Jasa Hapus BI Checking / SLIK OJK",
    "threat_level": "High",
    "action": "Jangan percaya jasa hapus BI checking. Tidak ada pihak yang bisa menghapus riwayat kredit secara instan. Laporkan ke OJK jika ditawari jasa semacam ini.",
    "keywords": ["bi checking", "slik ojk", "hapus blacklist", "kredit macet", "hapus riwayat", "skor kredit", "kol", "lancar", "macet", "hapus ctatan hitam", "perbaiki credit score", "penghapusan data"],
    "patterns": [
      "jasa hapus bi checking",
      "hapus blacklist ojk",
      "perbaiki skor kredit instan",
      "hapus riwayat kredit macet",
      "bi checking negatif bisa dihapus",
      "bayar untuk hapus data slik",
      "jasa penghapusan ctatan kredit",
      "jaminan bi checking bersih",
      "hapus kol 2 3 4 5",
      "perbaiki credit score dalam 1 minggu",
      "solusi kredit macet langsung cair",
      "bayar administrasi untuk hapus data"
    ],
    "analysis_result": "Ini adalah modus **Jasa Hapus BI Checking / SLIK OJK Palsu**. Pelaku menawarkan jasa 'menghapus' riwayat kredit macet atau blacklist di SLIK OJK agar kamu bisa mengajukan pinjaman lagi. Mereka meminta bayaran di muka (biasanya 500rb-5jt), namun riwayat kredit TIDAK AKAN PERNAH bisa dihapus secara instan oleh pihak manapun. Data SLIK OJK hanya bisa diperbaiki dengan melunasi utang dan menunggu proses alami.",
    "micro_lesson": "Tidak ada pihak yang bisa menghapus riwayat kredit macet secara instan. BI checking/SLIK OJK hanya bisa diperbaiki dengan: (1) melunasi utang, (2) menunggu 24 bulan setelah lunas. Jasa 'hapus BI checking' = PASTI penipuan."
  },
    {
    "id": "fraud_46",
    "category": "Modus Salah Transfer (Pinjol Ilegal)",
    "threat_level": "High",
    "action": "JANGAN langsung transfer balik uang yang masuk tiba-tiba. Hubungi bank kamu untuk verifikasi asal dana. Bisa jadi ini jebakan pinjol ilegal yang mendaftarkan pinjaman atas namamu.",
    "keywords": ["salah transfer", "uang masuk", "transfer balik", "kembalikan", "tolong kembalikan", "dana masuk", "uang tidak dikenal", "transfer ke rekening", "salah kirim", "pengirim tidak dikenal"],
    "patterns": [
      "maaf saya salah transfer ke rekening anda",
      "tolong kembalikan uang saya yang masuk tadi",
      "saya tidak sengaja transfer ke nomor anda",
      "cek rekening kamu ada uang masuk dari saya",
      "mohon transfer balik dana yang masuk",
      "itu uang gaji karyawan saya salah kirim",
      "tolong segera kembalikan saya butuh uang itu",
      "ada dana masuk ke rekening anda tolong kembalikan",
      "saya sudah lapor ke bank tolong transfer balik",
      "itu uang darurat saya tolong kembalikan sekarang"
    ],
    "analysis_result": "Ini adalah modus **Salah Transfer Palsu** yang sering berkaitan dengan skema pinjol ilegal. Pelaku sengaja mengirim uang ke rekeningmu, lalu meminta kamu mengembalikannya ke rekening berbeda (bukan rekening asal). Tujuannya: (1) mencuci uang hasil kejahatan melalui rekeningmu, (2) menggunakan rekening aktifmu sebagai rekening penampung, atau (3) ternyata pinjol ilegal sudah mendaftarkan pinjaman atas namamu tanpa sepengetahuanmu menggunakan data yang bocor. Jika kamu transfer balik, kamu bisa terlibat kasus pencucian uang.",
    "micro_lesson": "Jika ada uang masuk dari nomor tidak dikenal: (1) JANGAN transfer balik tanpa konfirmasi bank, (2) hubungi call center bankmu untuk verifikasi asal dana, (3) laporkan transaksi mencurigakan. Mengembalikan uang ke rekening berbeda = potensi terlibat pencucian uang."
  },
  {
    "id": "fraud_47",
    "category": "Rekening Penampung / Money Mule",
    "threat_level": "Critical",
    "action": "TOLAK tawaran apapun yang meminta kamu menggunakan rekening pribadi untuk 'menampung' atau 'meneruskan' dana orang lain. Ini ilegal dan bisa membuatmu dipenjara.",
    "keywords": ["rekening", "penampung", "tampung uang", "teruskan dana", "komisi", "rekening pribadi", "jual rekening", "sewa rekening", "rekening bantuan", "transfer teruskan", "agen pembayaran", "mule"],
    "patterns": [
      "minta tolong tampung uang di rekening kamu dulu",
      "nanti kamu transfer ke rekening lain dapat komisi",
      "jual rekening bank kamu bayaran tinggi",
      "sewa rekening kamu untuk keperluan bisnis",
      "bantu terima dana dulu nanti aku ganti plus fee",
      "kamu jadi agen pembayaran dapat komisi per transaksi",
      "rekening kamu dipakai sementara untuk proyek",
      "tolong tampung transfer ini nanti kamu terusin",
      "butuh rekening aktif untuk proses bisnis",
      "jadi kurir dana dapat bayaran harian"
    ],
    "analysis_result": "Ini adalah modus **Money Mule / Rekening Penampung**. Pelaku merekrut orang untuk menggunakan rekening pribadinya menampung dan meneruskan dana hasil kejahatan (penipuan, judi online, narkoba). Korban biasanya diiming-imingi komisi atau fee. Meski kamu tidak tahu asal uangnya, secara hukum kamu bisa dijerat UU TPPU (Tindak Pidana Pencucian Uang) dengan ancaman penjara hingga 20 tahun. Bank juga akan memblokir dan menutup rekeningmu permanen.",
    "micro_lesson": "Menjual, menyewakan, atau meminjamkan rekening bank untuk dipakai orang lain = TINDAK PIDANA PENCUCIAN UANG (UU No.8/2010). Ancaman hukumnya nyata—kamu bisa dipenjara meski tidak tahu uangnya dari mana. Tolak apapun alasannya."
  },
  {
    "id": "fraud_48",
    "category": "Joki Pinjol / Galbay Palsu",
    "threat_level": "High",
    "action": "Jangan percaya jasa joki pinjol atau konsultan galbay. Mereka akan mencuri data pribadimu dan memeras lebih banyak uang. Hubungi langsung platform pinjol legal untuk restrukturisasi.",
    "keywords": ["joki pinjol", "galbay", "gagal bayar", "kabur dari pinjol", "hapus utang pinjol", "jasa lunasi pinjol", "konsultan pinjol", "urus pinjol", "blokir penagih", "stop dc pinjol", "blacklist pinjol", "hapus data pinjol"],
    "patterns": [
      "jasa joki pinjol terpercaya",
      "bantu kabur dari tagihan pinjol",
      "hapus utang pinjol legal maupun ilegal",
      "stop penagihan debt collector pinjol",
      "joki galbay aman terbukti",
      "konsultan pinjol bermasalah",
      "hapus data di pinjol ilegal",
      "urus blacklist pinjol ojk",
      "bayar biaya konsultasi urus pinjol",
      "pinjol tidak bisa nagih lagi setelah pakai jasa kami",
      "kirim ktp dan data pinjol kamu ke kami",
      "akses aplikasi pinjol kamu untuk kami urus"
    ],
    "analysis_result": "Ini adalah modus **Joki Pinjol / Galbay Palsu**. Pelaku menawarkan jasa 'menyelesaikan' masalah pinjol bermasalah dengan meminta biaya konsultasi, data KTP, bahkan akses ke aplikasi pinjolmu. Setelah mendapat data dan uang, mereka menghilang—dan data pribadimu disalahgunakan untuk mengajukan pinjaman baru atas namamu di pinjol lain. Utang lama tidak selesai, utang baru bertambah.",
    "micro_lesson": "Tidak ada jalan pintas legal untuk kabur dari utang pinjol. Jika kesulitan bayar, hubungi langsung platform pinjol untuk restrukturisasi, atau minta bantuan AFPI (afpi.or.id) dan OJK 157. Jangan berikan KTP atau akses akun ke pihak ketiga manapun."
  },
  {
    "id": "fraud_49",
    "category": "Skimming Digital / Card Fraud",
    "threat_level": "Critical",
    "action": "Periksa tagihan kartu kredit/debit secara rutin. Aktifkan notifikasi setiap transaksi. Jika ada transaksi tidak dikenal, segera blokir kartu dan lapor ke bank.",
    "keywords": ["kartu kredit", "debit", "tagihan membengkak", "transaksi tidak dikenal", "skimming", "card fraud", "limit habis", "transaksi asing", "belanja online tidak dikenal", "charge tidak dikenal", "merchant asing", "transaksi luar negeri"],
    "patterns": [
      "ada transaksi tidak dikenal di kartu kreditmu",
      "limit kartu tiba-tiba habis",
      "tagihan bulan ini membengkak ada transaksi asing",
      "belanja di merchant yang tidak pernah dikunjungi",
      "ada charge dari luar negeri padahal tidak bepergian",
      "data kartu kredit dicuri saat transaksi online",
      "transaksi muncul berkali-kali di tagihan",
      "kartu dipakai belanja tanpa sepengetahuan pemilik",
      "ada OTP masuk padahal tidak belanja",
      "notifikasi transaksi dari merchant tidak dikenal"
    ],
    "analysis_result": "Ini adalah tanda **Skimming Digital / Card Fraud**. Data kartu kredit/debetmu mungkin telah dicuri melalui: (1) perangkat skimmer tersembunyi di mesin EDC/ATM, (2) malware di website belanja online, (3) kebocoran data dari merchant, atau (4) phishing yang mendapat nomor kartu + CVV. Pelaku menggunakan data ini untuk berbelanja online atau membuat kartu duplikat.",
    "micro_lesson": "Aktifkan notifikasi SMS/WhatsApp untuk setiap transaksi kartu. Cek tagihan bulanan dengan teliti. Untuk belanja online, gunakan kartu virtual sekali pakai jika tersedia. Segera blokir kartu jika ada transaksi mencurigakan—hubungi call center bank 24 jam."
  },
  {
    "id": "fraud_50",
    "category": "Email / WA Phishing Pajak (DJP Palsu)",
    "threat_level": "High",
    "action": "Email resmi DJP hanya dari domain @pajak.go.id. Akses laporan pajak hanya melalui pajak.go.id atau coretax.pajak.go.id. Jangan klik tautan dari email/WA yang mengaku dari DJP.",
    "keywords": ["pajak", "djp", "spt", "coretax", "efiling", "ebilling", "wajib pajak", "npwp", "kode billing", "denda pajak", "kurang bayar", "pemeriksaan pajak", "surat ketetapan pajak", "skp", "dirjen pajak", "keuangan negara"],
    "patterns": [
      "surat peringatan pajak dari djp",
      "anda memiliki tunggakan pajak yang belum dibayar",
      "segera bayar pajak atau rekening diblokir",
      "klik link untuk akses spt anda",
      "notifikasi coretax akun anda bermasalah",
      "periksa pajak anda segera",
      "verifikasi npwp melalui link ini",
      "denda pajak anda sudah jatuh tempo",
      "surat ketetapan pajak dikirim ke email ini",
      "login e-filing melalui link berikut",
      "akun djp online anda akan ditangguhkan",
      "pembayaran kode billing pajak segera",
      "anda mendapat restitusi pajak klik untuk klaim",
      "pemeriksaan pajak anda dijadwalkan segera"
    ],
    "analysis_result": "Ini adalah modus **Email/WA Phishing Berkedok Dirjen Pajak (DJP)**. Pelaku mengirim email atau WA yang mengaku dari DJP dengan subjek menakutkan seperti 'tunggakan pajak' atau 'denda'. Email menggunakan logo DJP tiruan dan meminta klik tautan ke situs phishing. Dirjen Pajak sendiri sudah berulang kali mengingatkan: email resmi DJP HANYA dari @pajak.go.id—bukan Gmail, Yahoo, atau domain lain.",
    "micro_lesson": "Email resmi DJP SELALU dari @pajak.go.id. Akses layanan pajak HANYA di pajak.go.id atau coretax.pajak.go.id—ketik manual di browser, jangan dari tautan email/WA. Jika ragu, hubungi Kring Pajak 1500200."
  },
  {
    "id": "fraud_51",
    "category": "Penipuan AI Voice Cloning (Suara Palsu Keluarga)",
    "threat_level": "Critical",
    "action": "Jika menerima telepon dari 'keluarga' yang minta uang darurat, tutup dan hubungi langsung nomor yang sudah tersimpan. Buat kata sandi keluarga untuk situasi darurat.",
    "keywords": ["suara mirip", "telepon anak", "telepon suami", "telepon istri", "telepon orang tua", "suara palsu", "ai voice", "kloning suara", "darurat", "kecelakaan", "butuh uang", "tolong transfer", "jangan cerita ke siapapun"],
    "patterns": [
      "ini suara anak saya tapi nomor beda",
      "mama ini aku butuh uang sekarang",
      "papa aku kecelakaan tolong kirim uang",
      "ini suaramu tapi kenapa minta uang",
      "suara yang mirip keluarga minta bantuan",
      "telepon dari nomor asing tapi suaranya kenal",
      "anak kamu bilang darurat butuh transfer",
      "suami kamu minta tolong via telepon",
      "jangan bilang siapapun ini darurat",
      "transfer dulu nanti aku cerita",
      "tolong jangan panik aku baik-baik saja tapi butuh uang",
      "aku di kantor polisi butuh uang jaminan"
    ],
    "analysis_result": "Ini adalah modus **AI Voice Cloning Scam** yang sangat berbahaya dan baru marak di 2025-2026. Pelaku menggunakan teknologi AI untuk mengkloning suara anggota keluargamu (diambil dari video/audio di media sosial), lalu menelepon dengan nomor asing tapi suaranya persis seperti anak, suami, istri, atau orang tuamu. Mereka menciptakan skenario darurat agar kamu langsung transfer tanpa verifikasi. Teknologi ini sangat meyakinkan—bahkan cara berbicara dan logat bisa ditiru.",
    "micro_lesson": "Buat 'kata sandi keluarga' rahasia yang hanya diketahui anggota keluarga inti—gunakan sebagai verifikasi jika ada yang mengaku keluarga dan minta uang. Jika suara mirip tapi nomor beda: TUTUP dan hubungi langsung nomor asli keluarga. Suara saja bukan bukti identitas di era AI."
  },
  {
    "id": "fraud_52",
    "category": "Penipuan Link Undangan / URL Pendek Berbahaya (2026)",
    "threat_level": "High",
    "action": "Jangan klik tautan pendek dari nomor tidak dikenal meskipun tampilannya seperti undangan resmi. Undangan asli sekarang bisa berbentuk URL—tapi selalu cek dulu preview-nya sebelum klik.",
    "keywords": ["link undangan", "url pendek", "klik link", "tautan undangan", "undangan digital", "buka link", "lihat di sini", "klik di sini", "bit.ly", "s.id", "tinyurl", "cutt.ly", "link berbahaya", "malware link", "tautan mencurigakan"],
    "patterns": [
      "silakan buka undangan di link ini",
      "klik tautan untuk lihat detail acara",
      "undangan digital kamu ada di link berikut",
      "buka link ini untuk konfirmasi kehadiran",
      "link undangan pernikahan kami",
      "lihat foto dan lokasi acara di sini",
      "undangan sudah dikirim silakan klik",
      "tautan undangan akan expired 24 jam",
      "konfirmasi via link sebelum acara",
      "buka link untuk download undangan resepsi",
      "ini link undangan dari saya",
      "acara di bulan depan klik link untuk info"
    ],
    "analysis_result": "Ini adalah **Evolusi Modus APK ke URL Berbahaya (2026)**. Setelah masyarakat waspada terhadap file .APK, penipu kini beralih ke tautan URL pendek yang mengarah ke situs yang secara otomatis mengunduh malware tersembunyi tanpa notifikasi instalasi. Malware ini berjalan di latar belakang, membaca SMS (OTP), merekam ketikan (keylogger), dan membocorkan data perbankan. Modus ini sangat berbahaya karena tampak seperti undangan biasa.",
    "micro_lesson": "Sebelum klik tautan pendek dari nomor tidak dikenal: (1) gunakan preview link seperti 'Check Short URL' untuk melihat tujuan aslinya, (2) aktifkan Google Safe Browsing, (3) aktifkan Auto-Blocker di pengaturan HP Android. Tautan pendek + nomor tidak dikenal = POTENSI BAHAYA."
  },
  {
    "id": "fraud_53",
    "category": "Penipuan Crowdfunding / Patungan Online Palsu",
    "threat_level": "High",
    "action": "Verifikasi kampanye crowdfunding sebelum donasi. Cek rekam jejak penggalang dana, update kampanye, dan gunakan platform resmi (Kitabisa) yang punya tim verifikasi.",
    "keywords": ["patungan", "crowdfunding", "iuran", "kolektif", "urunan", "galang dana", "kitabisa", "kumpulkan dana", "dana bersama", "patungan online", "iuran grup", "dana komunitas", "sumbangan", "bantuan bersama"],
    "patterns": [
      "yuk patungan untuk teman kita yang sakit",
      "ikut iuran grup untuk hadiah perpisahan",
      "crowdfunding untuk biaya operasi temanku",
      "transfer ke rekening ini untuk patungan",
      "kami kumpulkan dana untuk bencana",
      "ikut urunan beli kado bos kita",
      "dana patungan terkumpul tolong transfer ke",
      "bantu patungan untuk beasiswa adik kita",
      "join patungan online lewat wa ini",
      "sudah ada yang transfer belum patungannya",
      "deadline patungan besok tolong segera transfer",
      "patungan untuk modal usaha bersama"
    ],
    "analysis_result": "Ini adalah modus **Patungan/Crowdfunding Palsu**. Pelaku membuat grup WhatsApp atau pesan berantai yang mengaku mengumpulkan dana untuk teman sakit, bencana, atau hadiah bersama. Mereka mengelola uang patungan tapi tidak pernah digunakan sesuai tujuan. Modus ini sangat efektif di lingkungan kerja, sekolah, dan komunitas karena memanfaatkan rasa solidaritas dan kepercayaan kelompok.",
    "micro_lesson": "Untuk patungan grup, pastikan ada laporan transparan penerimaan dan penggunaan dana. Gunakan platform resmi dengan sistem akuntabilitas (Kitabisa, GandengTangan). Untuk patungan informal, pilih bendahara yang bisa dipertanggungjawabkan dan minta bukti penggunaan dana."
  },
  {
    "id": "fraud_54",
    "category": "Penipuan Klaim Asuransi Jiwa / Warisan (Advance Fee)",
    "threat_level": "Critical",
    "action": "Abaikan semua email/WA tentang warisan atau klaim asuransi jiwa dari orang yang tidak dikenal. Tidak ada warisan yang dikirim melalui email ke orang asing.",
    "keywords": ["warisan", "waris", "deposito", "klaim warisan", "pewaris", "meninggal", "harta", "aset", "bank luar negeri", "dollar", "jutaan dolar", "notar", "pengacara warisan", "advance fee", "biaya notaris", "biaya transfer warisan"],
    "patterns": [
      "anda adalah pewaris sah dari almarhum",
      "ada warisan jutaan dolar atas nama anda",
      "saya pengacara yang mengurus warisan klien",
      "klien saya meninggal tanpa ahli waris",
      "anda dipilih menerima warisan sebesar",
      "transfer biaya notaris untuk proses warisan",
      "dana warisan sudah siap dicairkan",
      "bayar pajak warisan untuk release dana",
      "klaim asuransi jiwa atas nama anda",
      "ada deposito di bank luar negeri atas nama anda",
      "biaya administrasi untuk transfer warisan",
      "anda berhak atas dana warisan senilai"
    ],
    "analysis_result": "Ini adalah modus **Advance Fee Fraud / Penipuan Warisan**—salah satu penipuan tertua di dunia yang kini masuk via email dan WA. Pelaku mengaku pengacara, bankir, atau pejabat yang mengelola warisan mendiang orang asing. Kamu dipilih sebagai 'penerima'. Untuk mencairkan warisan, kamu diminta membayar 'biaya notaris', 'pajak warisan', atau 'biaya transfer' yang terus bertambah. Warisan tidak pernah ada—setiap pembayaran akan diikuti permintaan biaya baru.",
    "micro_lesson": "Tidak ada warisan dari orang asing yang datang via email. Pengacara/bankir resmi tidak menghubungi calon ahli waris melalui WA atau email massal. Setiap penawaran 'uang besar' yang butuh biaya di muka = PASTI penipuan Advance Fee."
  },
  {
    "id": "fraud_55",
    "category": "Penipuan Akun Medsos Diretas / Bajak Facebook-Instagram",
    "threat_level": "High",
    "action": "Jika akunmu diretas, segera lapor ke platform (fb.com/hacked, instagram.com/hacked). Aktifkan 2FA. Beritahu teman-temanmu agar tidak percaya pesan dari akunmu yang diretas.",
    "keywords": ["akun diretas", "hack facebook", "instagram diambil alih", "akun dijual", "facebook palsu", "instagram palsu", "akun teman diretas", "pesan dari akun teman", "minta pulsa dari fb", "minta uang dari instagram", "akun kloning", "duplikat akun"],
    "patterns": [
      "halo ini aku tapi akun lamaku kena hack",
      "tolong bantu aku akunnya di hack",
      "ini akun baruku yang lama kena bajak",
      "jangan percaya pesan dari akun lamaku",
      "ada yang buat akun palsu atas namaku",
      "minta tolong transfer karena hp hilang",
      "akun facebookku dibajak minta bantuan",
      "ada yang clone akun instagramku",
      "ini aku dari akun baru lama kena hack",
      "tolong report akun palsu atas namaku",
      "kirimin pulsa dulu hp ku ilang kata teman",
      "seseorang pakai foto ku buat akun baru"
    ],
    "analysis_result": "Ini adalah modus **Pembajakan/Kloning Akun Media Sosial**. Ada dua skenario: (1) Akun Facebook/Instagram temanmu benar-benar diretas, dan pelaku menggunakannya untuk meminta uang/pulsa ke semua kontaknya—memanfaatkan kepercayaan bahwa pesan dari akun teman pasti asli. (2) Pelaku membuat akun duplikat dengan foto dan nama yang sama, lalu menambahkan teman-teman korban untuk melakukan penipuan. Kerugian dari modus ini bisa mencapai jutaan karena korban percaya sedang membantu teman.",
    "micro_lesson": "Jika mendapat pesan minta uang/pulsa dari akun teman di medsos: (1) hubungi teman lewat nomor HP yang sudah tersimpan untuk konfirmasi, (2) jangan transfer sebelum verifikasi suara/video call, (3) Aktifkan 2FA di semua medsos untuk mencegah peretasan akunmu sendiri."
  },
  ...NEW_SCAM_ENTRIES
];

// Modular regex-based detection using REGEX_RULES
const checkWithRegex = (text: string) => {
  const flags: string[] = [];
  const suspiciousKeywordsList: string[] = [];
  let rawScore = 0;
  const categoryCounts: Record<string, number> = {};

  for (const rule of REGEX_RULES) {
    // FIX 3: Reset lastIndex sebelum setiap penggunaan regex global
    // Regex dengan flag 'g' menyimpan lastIndex antar pemanggilan — bisa hasil inkonsisten
    rule.regex.lastIndex = 0;
    const matches = text.match(rule.regex);
    if (matches) {
      flags.push(rule.label);
      suspiciousKeywordsList.push(...matches);
      
      const cat = rule.weight_category;
      categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
      
      // FIX: Logarithmic Score Decay per Kategori
      // Rule pertama dalam kategori menyumbang 100% skor, rule kedua 50%, ketiga 25%, dst.
      // Mencegah akumulasi poin ekstrem dari pesan panjang yang memicu banyak rule di kategori yang sama.
      const decayFactor = 1 / Math.pow(2, categoryCounts[cat] - 1);
      const multiplier = WEIGHT_MULTIPLIERS[cat] || 1.0;
      
      rawScore += rule.score * multiplier * decayFactor;
    }
  }

  // Normalize: critical rules can push score above 10, but cap display at 10
  const score = Math.min(rawScore, 15);

  return { flags, suspiciousKeywordsList, score, rawScore };
};

export function analyzeTextLocal(input: string, isUrl: boolean): AnalysisResult {
  if (!input || !input.trim()) {
    return {
      verdict: 'AMAN',
      dangerScore: 1,
      redFlags: [],
      suspiciousKeywords: [],
      simpleExplanation: "Pesan kosong tidak bisa dianalisis. Silakan masukkan teks atau URL untuk diperiksa.",
      actionItem: "Ketik atau tempel pesan yang ingin kamu periksa ke kolom analisis.",
      microLesson: "Selalu waspada terhadap pesan dari nomor atau akun yang tidak dikenal."
    };
  }

  // 1. Preprocess text
  const cleaned = cleanText(input);

  // 2. URL analysis (extract and analyze any URLs in the text)
  const urls = extractUrls(input);
  const urlResults = urls.map(u => analyzeURL(u));
  const urlScore = urlResults.reduce((sum, r) => sum + r.score, 0);
  const urlFlags: string[] = [];
  const urlKeywords: string[] = [];

  for (const ur of urlResults) {
    if (ur.isSuspicious) {
      urlKeywords.push(ur.url);
      for (const reason of ur.reasons) {
        urlFlags.push(reason);
      }
    }
  }

  // 3. Regex-based detection on cleaned text
  const { flags: regexFlags, suspiciousKeywordsList, score: regexScore } = checkWithRegex(cleaned);

  // 4. Fuzzy Search — FIX 8: tambah minMatchCharLength & distance untuk kontrol lebih ketat
  // FIX: Dynamic Thresholding (teks pendek butuh kecocokan lebih tinggi)
  const dynamicThreshold = cleaned.length < 30 ? 0.2 : 0.4;
  
  const fuseOptions = {
    keys: ['patterns', 'keywords'],
    includeScore: true,
    threshold: dynamicThreshold,
    minMatchCharLength: 4, // Abaikan match pada kata sangat pendek (<4 karakter)
    distance: 100           // Batasi jarak pencarian untuk efisiensi dan akurasi
  };

  const fuse = new Fuse(SCAM_DB, fuseOptions);
  const searchResults = fuse.search(cleaned);

  // 5. Decision logic with weighted scoring
  let decision: "AMAN" | "MENCURIGAKAN" | "BERBAHAYA" = "AMAN";
  let explanation = "Kami tidak menemukan sesuatu yang mencolok secara berbahaya dalam pesan ini.";
  let action = "Jika ini pesan dari nomor tidak dikenal, cukup hiraukan atau balas sesuai konteks secara aman.";
  let lesson = "Jangan bagikan OTP (One Time Password) kepadamu dengan alasan/kepada siapapun.";
  let finalScore = regexScore + urlScore;
  let finalKeywords = [...suspiciousKeywordsList, ...urlKeywords];
  let finalFlags = [...regexFlags, ...urlFlags];

  // FIX 5: Multi-match — ambil top-3 results dari Fuse.js, gabungkan flags & keywords
  // Sebelumnya hanya mengambil bestMatch[0] sehingga pesan multi-modus hanya terdeteksi 1 modus
  const TOP_MATCHES = 3;
  const topMatches = searchResults
    .filter(r => r.score !== undefined && (1 - r.score) > 0.35)
    .slice(0, TOP_MATCHES);

  // Kumpulkan flags & keywords dari semua top matches
  // FIX 2: Gunakan `cleaned.toLowerCase()` bukan `input.toLowerCase()` agar konsisten dengan preprocessing
  const lowerCleaned = cleaned.toLowerCase();
  for (const match of topMatches) {
    match.item.keywords.forEach(kw => {
      if (lowerCleaned.includes(kw.toLowerCase())) {
        if (!finalKeywords.includes(kw)) finalKeywords.push(kw);
      }
    });
  }

  const bestMatch = topMatches[0] ?? searchResults[0];

  if (bestMatch && bestMatch.score !== undefined) {
    const similarityScore = 1 - bestMatch.score; // In Fuse.js, 0 = perfect match

    // Weight the DB match by its threat category
    const dbWeight = WEIGHT_MULTIPLIERS[getWeightCategory(bestMatch.item)] || 1.0;

    if (similarityScore > 0.55 || (similarityScore > 0.4 && finalScore >= 5)) {
      // High confidence match: strong DB similarity OR moderate similarity + strong regex
      decision = "BERBAHAYA";
      explanation = bestMatch.item.analysis_result;
      action = bestMatch.item.action;
      lesson = bestMatch.item.micro_lesson;
      finalScore += 5 * dbWeight;

      if (!finalFlags.length) {
        finalFlags.push("Sangat mirip dengan database modus penipuan berulang kami.");
      }
    } else if (similarityScore > 0.4 || finalScore >= 6) {
      // Medium confidence: moderate DB match OR strong regex alone
      decision = "BERBAHAYA";
      explanation = bestMatch.item.analysis_result || "Meski kata penyampaiannya berbeda, ini mendemonstrasikan kelakuan phising standar.";
      action = bestMatch.item.action || "Hapus atau laporkan pesan sebagai Spam.";
      lesson = bestMatch.item.micro_lesson || "Pahami bahwa trik penipu selalu berkembang setiap detiknya.";
      finalScore += 4 * dbWeight;
    } else if (similarityScore > 0.3 || finalScore >= 3) {
      // Low confidence: some signals present
      decision = "MENCURIGAKAN";
      explanation = "Pesan ini punya pola umum layaknya spam atau mengarah perlahan-perlahan ke dalam tipuan.";
      action = "Jangan membagikan data diri secara cuma-cuma dan terus bersikap kritis.";
      lesson = "Pahami bahwa trik penipu selalu berkembang setiap detiknya.";
      finalScore += 2;
    }
  } else if (finalScore >= 6) {
    // No DB match but strong regex + URL signals
    decision = "BERBAHAYA";
    explanation = "Meski kata penyampaiannya berbeda, ini mendemonstrasikan kelakuan phising standar.";
    action = "Hapus atau laporkan pesan sebagai Spam.";
    finalFlags.push("Tautan atau kalimat dalam pesan menuntun kamu ke ancaman yang umum.");
  } else if (finalScore >= 3) {
    decision = "MENCURIGAKAN";
    explanation = "Ada elemen seperti tautan singkatan atau ajakan buru-buru, tapi agak sulit dikategorikan pasti sebagai ancaman.";
    action = "Cross-check ulang pihak pengirim aslinya. Buka tabungan mandiri/shopee dll dari aplikasinya langsung, BUKAN dari tautannya.";
  }

  // FIX 7: Normalisasi finalScore lebih proporsional
  // Sebelumnya: Math.min(finalScore, 10) → skor 10 dan 37 terlihat sama di UI
  // Sekarang: skala relatif terhadap 20 agar severity lebih terwakili
  let displayScore = Math.round(Math.min((finalScore / 20) * 10, 10));
  if (decision === "AMAN" && displayScore === 0) displayScore = 1;

  return {
    verdict: decision,
    dangerScore: displayScore,
    redFlags: Array.from(new Set(finalFlags)),
    suspiciousKeywords: Array.from(new Set(finalKeywords)),
    simpleExplanation: explanation,
    actionItem: action,
    microLesson: lesson
  };
}

export function processQuizAnswerLocal(input: string, isSafe: boolean, _exampleNumber: number): string {
  if (!input || !input.trim()) {
    return "Pesan kosong tidak bisa dianalisis.";
  }

  const cleaned = cleanText(input);
  const { score } = checkWithRegex(cleaned);

  const dynamicThreshold = cleaned.length < 30 ? 0.2 : 0.4;
  const fuse = new Fuse(SCAM_DB, { keys: ['patterns', 'keywords'], includeScore: true, threshold: dynamicThreshold, minMatchCharLength: 4, distance: 100 });
  const result = fuse.search(cleaned);

  // Cek top-3 matches (konsisten dengan analyzeTextLocal)
  const topMatches = result.filter(r => r.score !== undefined && (1 - r.score) > 0.35).slice(0, 3);
  const hasStrongMatch = topMatches.some(r => (1 - r.score!) > 0.4);

  let isActuallySafe = true;
  if (score >= 3 || hasStrongMatch) {
    isActuallySafe = false;
  }

  const isUserCorrect = isSafe === isActuallySafe;

  if (isUserCorrect) {
    if (!isSafe) {
      return "Tepat Sekali! Kamu berhasil mengamati bahwa pesan / tautan ini memiliki tanda bahaya layaknya penipuan. Jangan terpancing ya.";
    } else {
      return "Tebakan yang bagus. Terkadang, sesuatu yang biasa-biasa saja memang asli dan aman. Tetap semangat mengedukasi diri.";
    }
  } else {
    if (isSafe && !isActuallySafe) {
      return "Aduh, ini sebenarnya adalah modus berbahaya lho! Terdapat frasa / modus yang mencoba mencuri data atau uangmu.";
    } else {
      return "Kewaspadaanmu sangat tinggi! Meski terlihat aman, tak ada salahnya berjaga-jaga. Namun pesan ini murni cukup aman.";
    }
  }
}