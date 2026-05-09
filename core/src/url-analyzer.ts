// ============================================================
// URL / DOMAIN ANALYZER — Analisis URL, domain, TLD, shortener, brand spoofing
// ============================================================

import { URLAnalysis, HomographResult } from './types';
import { UNICODE_HOMOGLYPH_MAP } from './preprocessing';

export const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'buzz', 'club', 'click', 'icu',
  'tk', 'ml', 'ga', 'cf', 'gq',
  'work', 'loan', 'racing', 'win', 'bid', 'trade', 'accountant',
  'cfd', 'gdn', 'men', 'cam', 'adult', 'party', 'bet', 'casino',
  'monster', 'cyou', 'hair', 'beauty', 'lol', 'boats', 'quest',
]);

export const MODERATE_RISK_TLDS = new Set([
  'dev', 'app', 'zip', 'mov', 'page',
  'ru', 'cn', 'cc', 'su', 'pw', 'ws', 'es', 'li',
  'biz', 'info', 'pro', 'online', 'site', 'website', 'space', 'live',
  'shop', 'best', 'digital', 'support',
]);

export const SHORTENER_DOMAINS = new Set([
  // ================================================================
  // LOKAL INDONESIA
  // ================================================================
  's.id',
  'dwz.id',
  'lynk.id',
  'dik.si',
  'bityl.co',
  'gplinks.co',
  'droplink.co',
  'za.gl',
  'snacklink.id',
  'safelinku.com',
  'dz4link.com',
  'tempel.in',

  // ================================================================
  // PLATFORM PESAN & SOSIAL (redirect chain)
  // ================================================================
  'wa.me',
  't.me',
  't.co',
  'lnkd.in',
  'fb.me',

  // ================================================================
  // INTERNASIONAL POPULER
  // ================================================================
  'bit.ly',
  'tinyurl.com',
  'cutt.ly',
  'rb.gy',
  'is.gd',
  'v.ht',
  'shorturl.at',
  'tiny.cc',
  'buff.ly',
  'bl.ink',
  'bit.do',
  'ow.ly',
  'u.to',
  'gg.gg',
  'da.gd',
  'osdb.link',
  'spoo.me',

  // ================================================================
  // MONETISASI BERBAYAR
  // ================================================================
  'shrinkme.io',
  'shrink.pe',
  'clk.sh',
  'exe.io',
  'fc.lc',
  'shorte.st',
  'ouo.io',
  'adf.ly',
  'linkvertise.com',
  'loot-link.com',
  'tmjv.id',
  'adpaylink.com',
  'paid4link.com',

  // ================================================================
  // LINK-IN-BIO
  // ================================================================
  'linktr.ee',
  'campsite.bio',
  'taplink.cc',
  'solo.to',
  'beacons.ai',
  'link.space',
  'linkin.bio',
  'bio.link',
  'linkpop.com',
  'milkshake.app',

  // ================================================================
  // E-COMMERCE SHORTENERS
  // ================================================================
  'id.shp.ee',

  // ================================================================
  // SERING DIPAKAI DI KAMPANYE PHISHING INTERNASIONAL
  // ================================================================
  'rebrand.ly',
  'snip.ly',
  'hyperurl.co',
  'fox.ly',
  'tiny.pl',
  'shorturl.asia',
  'go2l.ink',
  'urlr.me',
  'shrtco.de',

  // ================================================================
  // BERBASIS RUSIA / EROPA TIMUR
  // ================================================================
  'clck.ru',
  'goo.su',
  'vk.cc',

  // ================================================================
  // LAIN-LAIN YANG SERING MUNCUL DI LAPORAN SCAM
  // ================================================================
  'urlcut.com',
  'zee.gl',
  'qr.ae',
  'go.ly',
  'shrt.li',
  'tinycc.com',
  'short.io',
  'bl.ink',
  'zws.im',
  't.ly',
  'bitly.ws',
  'loom.ly',
]);

export const FREE_SUBDOMAINS = [
  'my.id', 'biz.id',
  'workers.dev', 'pages.dev',
  'github.io', 'gitlab.io',
  'netlify.app',
  'vercel.app',
  'herokuapp.com',
  'web.app', 'firebaseapp.com',
  'readthedocs.io',
  'weebly.com', 'wixsite.com',
  'canva.site', 'notion.site', 'wordpress.com', 'blogspot.com'
];

export const BRAND_DOMAINS: Record<string, string[]> = {
  // --- PERBANKAN ---
  'bca': ['bca.co.id', 'klikbca.com', 'blubca.co.id'],
  'bri': ['bri.co.id', 'brimo.id'],
  'mandiri': ['bankmandiri.co.id', 'livin.bankmandiri.co.id', 'livinbymandiribusiness.co.id'],
  'bni': ['bni.co.id', 'bnionline.com', 'wondr.bni.co.id', 'wondrbybni.com'],
  'bsi': ['bankbsi.co.id'],
  'btn': ['btn.co.id'],
  'seabank': ['seabank.co.id'],
  'jago': ['jago.com'],
  'neobank': ['bankneocommerce.co.id'],
  'superbank': ['superbank.id'],
  'aladin': ['aladinbank.id'],

  // --- E-WALLET & FINTECH ---
  'dana': ['dana.id'],
  'ovo': ['ovo.id'],
  'gopay': ['gopay.co.id'],
  'shopeepay': ['shopeepay.co.id'],
  'linkaja': ['linkaja.id'],
  'flip': ['flip.id'],
  'xendit': ['xendit.co'],
  'kredivo': ['kredivo.id'],
  'akulaku': ['akulaku.com'],
  'astrapay': ['astrapay.com'],

  // --- PINJOL LEGAL OJK ---
  'tunaiku': ['tunaiku.com'],
  'easycash': ['easycash.id'],
  'adapundi': ['adapundi.com'],
  'julo': ['julo.co.id'],

  // --- KRIPTO & INVESTASI ---
  'indodax': ['indodax.com'],
  'tokocrypto': ['tokocrypto.com'],
  'pintu': ['pintu.co.id'],
  'bibit': ['bibit.id'],
  'bareksa': ['bareksa.com'],
  'ajaib': ['ajaib.co.id'],

  // --- E-COMMERCE & TRAVEL ---
  'shopee': ['shopee.co.id', 'shopee.com'],
  'tokopedia': ['tokopedia.com'],
  'tiktokshop': ['shop.tiktok.com', 'id.tiktok.com'],
  'lazada': ['lazada.co.id'],
  'blibli': ['blibli.com'],
  'bukalapak': ['bukalapak.com'],
  'traveloka': ['traveloka.com'],
  'tiket': ['tiket.com'],
  'pegipegi': ['pegipegi.com'],

  // --- RIDE-HAILING & LOGISTIK ---
  'gojek': ['gojek.com'],
  'grab': ['grab.com', 'grab.id'],
  'jne': ['jne.co.id'],
  'jnt': ['jet.co.id'],
  'sicepat': ['sicepat.com'],
  'pos': ['posindonesia.co.id'],
  'anteraja': ['anteraja.id'],
  'lionparcel': ['lionparcel.com'],
  'ninjaxpress': ['ninjaxpress.co'],
  'paxel': ['paxel.co'],

  // --- TELEKOMUNIKASI ---
  'telkomsel': ['telkomsel.com', 'mytelkomsel.com'],
  'indosat': ['indosat.com', 'indosatooredoo.com', 'myim3.com'],
  'xl': ['xl.co.id', 'myxl.xl.co.id'],

  // --- UTILITAS ---
  'pln': ['pln.co.id', 'plnmobile.co.id'],

  // --- PEMERINTAH ---
  'bpjs': ['bpjs-kesehatan.go.id', 'bpjsketenagakerjaan.go.id'],
  'ojk': ['ojk.go.id'],
  'pajak': ['pajak.go.id', 'coretax.pajak.go.id'],
  'djp': ['pajak.go.id'],
  'kemenag': ['kemenag.go.id'],
  'kemensos': ['kemensos.go.id', 'dtks.kemensos.go.id'],
  'prakerja': ['prakerja.go.id'],
  'kpu': ['kpu.go.id'],
  'dukcapil': ['dukcapil.go.id'],
  'samsat': ['samsat.id', 'esamsat.id'],
  'kemenkes': ['kemenkes.go.id'],
  'kemendikbud': ['kemendikbud.go.id'],
  'polri': ['polri.go.id'],
  'kominfo': ['kominfo.go.id'],
  'baznas': ['baznas.go.id'],
  'rumahzakat': ['rumahzakat.org'],
  'disnaker': ['disnaker.go.id'],
  'pedulilindungi': ['pedulilindungi.id'],
  'satusehat': ['satusehat.kemkes.go.id'],

  // --- MEDIA SOSIAL & KOMUNIKASI ---
  'google': ['google.com', 'google.co.id', 'gmail.com', 'youtube.com'],
  'facebook': ['facebook.com', 'fb.com', 'meta.com'],
  'instagram': ['instagram.com'],
  'tiktok': ['tiktok.com'],
  'telegram': ['telegram.org'],
  'whatsapp': ['whatsapp.com', 'web.whatsapp.com'],
  'zoom': ['zoom.us'],
  'x': ['x.com', 'twitter.com'],
  'twitter': ['twitter.com', 'x.com'],

  // --- TEKNOLOGI GLOBAL ---
  'netflix': ['netflix.com'],
  'spotify': ['spotify.com'],
  'apple': ['apple.com', 'icloud.com'],
  'microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'hotmail.com'],
  'amazon': ['amazon.com', 'amazon.co.id'],
  'wikipedia': ['wikipedia.org', 'wikimedia.org'],
  'github': ['github.com'],

  // International brands untuk mencegah bypass Homograph attack
  'paypal': ['paypal.com', 'paypal.me'],
  'wise': ['wise.com', 'transferwise.com'],
  'revolut': ['revolut.com'],
  'skrill': ['skrill.com'],
  'venmo': ['venmo.com'],
  'cashapp': ['cash.app', 'square.com'],
};

export const WHITELIST_DOMAINS = new Set([
  // Sosial & Komunikasi
  'google.com', 'google.co.id', 'gmail.com', 'youtube.com', 'googleapis.com',
  'facebook.com', 'fb.com', 'meta.com', 'instagram.com',
  'whatsapp.com', 'web.whatsapp.com',
  'tiktok.com', 'telegram.org',
  'x.com', 'twitter.com',
  'zoom.us', 'meet.google.com', 'teams.microsoft.com',

  // E-commerce & Travel
  'tokopedia.com', 'shopee.co.id', 'shopee.com', 'shop.tiktok.com', 'id.tiktok.com',
  'lazada.co.id', 'blibli.com', 'bukalapak.com',
  'traveloka.com', 'tiket.com', 'pegipegi.com',

  // Perbankan
  'bca.co.id', 'klikbca.com', 'blubca.co.id',
  'bri.co.id', 'brimo.id',
  'bankmandiri.co.id', 'livin.bankmandiri.co.id', 'livinbymandiribusiness.co.id',
  'bni.co.id', 'bnionline.com', 'wondr.bni.co.id', 'wondrbybni.com',
  'bankbsi.co.id',
  'btn.co.id', 'seabank.co.id',
  'jago.com', 'bankneocommerce.co.id', 'superbank.id', 'aladinbank.id',

  // E-wallet & Fintech
  'dana.id', 'ovo.id', 'gopay.co.id', 'shopeepay.co.id', 'linkaja.id',
  'flip.id', 'xendit.co',
  'kredivo.id', 'akulaku.com', 'astrapay.com',

  // Pinjol legal OJK
  'tunaiku.com', 'easycash.id', 'adapundi.com', 'julo.co.id',

  // Kripto & Investasi
  'indodax.com', 'tokocrypto.com', 'pintu.co.id',
  'bibit.id', 'bareksa.com', 'ajaib.co.id',

  // Ride-hailing & Logistik
  'gojek.com', 'grab.com', 'grab.id',
  'jne.co.id', 'jet.co.id', 'sicepat.com', 'posindonesia.co.id',
  'anteraja.id', 'lionparcel.com', 'ninjaxpress.co', 'paxel.co',

  // Telekomunikasi
  'telkomsel.com', 'mytelkomsel.com',
  'indosat.com', 'indosatooredoo.com', 'myim3.com',
  'xl.co.id', 'myxl.xl.co.id',

  // Utilitas
  'pln.co.id', 'plnmobile.co.id',

  // Pemerintah
  'ojk.go.id',
  'pajak.go.id', 'coretax.pajak.go.id',
  'bpjs-kesehatan.go.id', 'bpjsketenagakerjaan.go.id',
  'kemenag.go.id', 'kemensos.go.id', 'dtks.kemensos.go.id',
  'kominfo.go.id', 'kemenkes.go.id', 'kemendikbud.go.id',
  'polri.go.id', 'baznas.go.id',
  'prakerja.go.id', 'satusehat.kemkes.go.id',
  'kpu.go.id', 'dukcapil.go.id',
  'samsat.id', 'esamsat.id',
  'disnaker.go.id',
  'pedulilindungi.id',

  // Donasi & Sosial
  'kitabisa.com', 'rumahzakat.org',

  // Developer & Tech
  'github.com', 'gitlab.com', 'stackoverflow.com',

  // Teknologi Global
  'microsoft.com', 'outlook.com', 'live.com', 'hotmail.com',
  'apple.com', 'icloud.com',
  'amazon.com', 'netflix.com', 'spotify.com',
  'wikipedia.org', 'wikimedia.org',
]);

// Known valid TLDs to filter bare domain matches and reduce false positives
const KNOWN_TLDS = new Set([
  // Generic
  'com', 'co', 'org', 'net', 'edu', 'gov', 'mil', 'int',
  // Indonesia
  'id', 'co.id', 'ac.id', 'go.id', 'or.id', 'my.id', 'biz.id', 'web.id', 'sch.id', 'ponpes.id',
  // Common ccTLDs
  'uk', 'us', 'de', 'fr', 'jp', 'cn', 'kr', 'au', 'ca', 'br', 'in', 'ru', 'es', 'it', 'nl',
  'se', 'no', 'fi', 'dk', 'pl', 'cz', 'at', 'ch', 'be', 'pt', 'ie', 'nz', 'sg', 'my', 'ph',
  'th', 'vn', 'tw', 'hk', 'mo', 'cc', 'su', 'pw', 'ws', 'li', 'me', 'tv', 'io', 'ai', 'app',
  // Common gTLDs
  'info', 'biz', 'pro', 'name', 'mobi', 'travel', 'asia', 'tel',
  'dev', 'app', 'page', 'zip', 'mov', 'xyz', 'top', 'online', 'site', 'website', 'space',
  'live', 'shop', 'store', 'tech', 'digital', 'cloud', 'blog', 'club', 'work', 'click',
  'link', 'fun', 'icu', 'buzz', 'best', 'lol', 'monster', 'cyou', 'hair', 'beauty', 'boats',
  'quest', 'cfd', 'gdn', 'men', 'cam', 'adult', 'party', 'bet', 'casino', 'loan', 'racing',
  'win', 'bid', 'trade', 'accountant', 'support',
  // Platform shorteners TLDs
  'ly', 'gl', 'at', 'ee', 'do', 'to', 'im', 'ws', 'sh',
]);

export function extractUrls(text: string): string[] {
  let normalized = text
    .replace(/hxxps?:\/\//gi, 'https://')
    .replace(/\[\.\]/g, '.')
    .replace(/\[@\]/g, '@')
    .replace(/\[\/\]/g, '/')
    .replace(/[\[\]]/g, '')
    .replace(/h\s+t\s+t\s+p\s+s?\s*:\s*\/\s*\//gi, 'https://');

  const urlRegex = /https?:\/\/[^\s<>"'`,;)}\]]+/gi;
  const matches = normalized.match(urlRegex) || [];
  const bareDomainRegex = /(?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?[^\s]*/gi;
  const bareMatches = (normalized.match(bareDomainRegex) || []).filter(m => {
    // Filter against known TLDs to reduce false positives (e.g. "aku.sedang", "ini.contoh")
    const parts = m.toLowerCase().replace(/^www\./, '').split(/[/?#\s]/)[0].split('.');
    if (parts.length < 2) return false;
    const tld = parts[parts.length - 1];
    const compoundTld = parts.length >= 3 ? `${parts[parts.length - 2]}.${tld}` : null;
    return KNOWN_TLDS.has(tld) || (compoundTld !== null && KNOWN_TLDS.has(compoundTld));
  });
  return [...new Set([...matches, ...bareMatches])];
}

export function extractDomain(url: string): string {
  try {
    const fullUrl = url.startsWith('http') ? url : `http://${url}`;
    const parsed = new URL(fullUrl);
    return parsed.hostname.replace(/^www\./, '');
  } catch {
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/\s:?#]+)/i);
    return match ? match[1].toLowerCase() : '';
  }
}

export function extractRawDomain(url: string): string {
  const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/\s:?#]+)/i);
  return match ? match[1].toLowerCase() : '';
}

// ============================================================
// IDN HOMOGRAPH ATTACK DETECTOR
// ============================================================
export function detectHomographAttack(domain: string): HomographResult {
  const hasUnicode = /[^\x00-\x7F]/.test(domain);
  const isPunycode = domain.includes('xn--');

  let visualDomain = domain;
  if (isPunycode) {
    try {
      const parsed = new URL(`http://${domain}`);
      visualDomain = parsed.hostname.replace(/^www\./, '');
    } catch {
      visualDomain = domain;
    }
  }

  let normalizedDomain = visualDomain.toLowerCase();
  for (const [glyph, replacement] of Object.entries(UNICODE_HOMOGLYPH_MAP)) {
    normalizedDomain = normalizedDomain.split(glyph).join(replacement.toLowerCase());
  }
  normalizedDomain = normalizedDomain.normalize('NFKD').replace(/[̀-ͯ]/g, '');

  let spoofedBrand: string | null = null;
  if (hasUnicode || isPunycode) {
    for (const [brand, legitimateDomains] of Object.entries(BRAND_DOMAINS)) {
      for (const legit of legitimateDomains) {
        const normalizedLegit = legit.toLowerCase();
        if (normalizedDomain === normalizedLegit && visualDomain !== legit) {
          spoofedBrand = brand;
          break;
        }
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
    normalizedDomain !== visualDomain.toLowerCase()
  );

  return { isHomograph, hasUnicode, isPunycode, normalizedDomain, spoofedBrand, visualDomain };
}

// Module-level constants untuk Open Redirect Detection
const REDIRECT_PARAMS = ['url', 'redirect', 'next', 'q', 'u', 'link', 'goto', 'dest', 'target', 'return', 'redir'];
const KNOWN_REDIRECTORS = new Set(['google.com', 'facebook.com', 'youtube.com', 'instagram.com', 't.co']);

export function analyzeURL(url: string): URLAnalysis {
  const originalUrl = url;
  try {
    url = new URL(url.startsWith('http') ? url : `https://${url}`).href;
  } catch { /* biarkan url asli jika invalid */ }

  const domain = extractDomain(url);
  const rawDomain = extractRawDomain(url);
  const reasons: string[] = [];
  let score = 0;
  let matchedBrand: string | null = null;
  let legitimateDomains: string[] = [];

  // Check shortener
  if (SHORTENER_DOMAINS.has(domain)) {
    reasons.push(`Menggunakan shortener (${domain}) — tujuan asli tersembunyi`);
    score += 3;
  }

  // Check Free Subdomains / Serverless
  const matchedFreeSubdomain = FREE_SUBDOMAINS.find(sub => domain === sub || domain.endsWith('.' + sub));
  if (matchedFreeSubdomain) {
    reasons.push(`Menggunakan domain gratisan/serverless (.${matchedFreeSubdomain}) — sering dipakai hosting phishing`);
    score += 4;
  }

  // Check suspicious TLD menggunakan two-tier scoring
  const tld = domain.split('.').pop() || '';
  if (HIGH_RISK_TLDS.has(tld)) {
    reasons.push(`TLD berisiko tinggi (.${tld}) — hampir selalu digunakan untuk situs phishing`);
    score += 4;
  } else if (MODERATE_RISK_TLDS.has(tld)) {
    reasons.push(`TLD berisiko moderat (.${tld}) — sering disalahgunakan, verifikasi domain dengan teliti`);
    score += 2;
  }

  // Check IP address as domain
  if (/^\d{1,3}(\.\d{1,3}){3}/.test(domain) || /^\d{8,10}$/.test(domain) || /^0x[0-9a-f]{8}$/i.test(domain)) {
    reasons.push('Menggunakan IP address (Desimal/Hex/Dotted) langsung — situs resmi tidak melakukan ini');
    score += 5;
  }

  // Check typosquatting against known brands
  const normalizedDomainForBrand = domain.toLowerCase()
    .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
    .replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't')
    .replace(/-/g, '');

  for (const [brand, brandDomains] of Object.entries(BRAND_DOMAINS)) {
    const brandPattern = new RegExp(`(^|[-.])${brand}([-.]|$)`, 'i');
    const isMatch = brandPattern.test(domain) || brandPattern.test(normalizedDomainForBrand);

    if (isMatch && !brandDomains.some(d => domain === d || domain.endsWith('.' + d))) {
      const hasSuspiciousModifier = /[-]?(login|verify|secure|update|online|account|signin|auth|confirm|check|support)/i.test(domain);
      const hasNumberSubstitution = domain.replace(brandPattern, '').match(/[0-9]/);
      const hasHyphenBrand = domain.includes(`-${brand}`) || domain.includes(`${brand}-`);

      if (hasSuspiciousModifier || hasNumberSubstitution || hasHyphenBrand) {
        matchedBrand = brand;
        legitimateDomains = brandDomains;
        reasons.push(`Domain meniru brand "${brand}" dengan pola typosquatting`);
        score += 6;
      }
    }
  }

  // Check path segments for brand spoofing
  try {
    const parsed = new URL(url.startsWith('http') ? url : `http://${url}`);
    const pathSegments = parsed.pathname.split('/').filter(Boolean);

    for (const segment of pathSegments) {
      const lowerSegment = segment.toLowerCase();
      for (const [brand, brandDomains] of Object.entries(BRAND_DOMAINS)) {
        const brandInPathPattern = new RegExp(`(^|[-_./])${brand}([-_./]|$)`, 'i');
        if (brandInPathPattern.test(lowerSegment) &&
          !brandDomains.some(d => domain === d || domain.endsWith('.' + d))) {
          if (!matchedBrand) {
            matchedBrand = brand;
            legitimateDomains = brandDomains;
            reasons.push(`Path URL menyembunyikan nama brand "${brand}" (${segment}) — teknik penyamaran tujuan`);
            score += 4;
          }
        }
      }
    }
  } catch { }

  // Check for suspicious patterns in domain
  if (/secure-|login-|verify-|update-|account-|signin-/.test(domain)) {
    reasons.push('Domain mengandung kata kunci phishing (secure/login/verify)');
    score += 4;
  }

  // Check for excessive hyphens
  const hyphenCount = (rawDomain.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    reasons.push(`Domain terlalu banyak tanda hubung (${hyphenCount}) — ciri domain phishing`);
    score += 3;
  }

  // Check for very long domain
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
  if (/^(data|javascript|vbscript):/i.test(originalUrl)) {
    reasons.push('Menggunakan skema URI berbahaya (data/javascript)');
    score += 8;
  }

  // URL Auth Deception
  if (url.includes('@')) {
    try {
      const parsed = new URL(url.startsWith('http') ? url : `http://${url}`);
      if (parsed.username || parsed.password) {
        reasons.push('URL menggunakan format autentikasi (user@host) untuk menyamarkan domain asli — teknik phishing berbahaya');
        score += 8;
      }
    } catch { }
  }

  // Open Redirect Detection
  try {
    const parsedForRedirect = new URL(url.startsWith('http') ? url : `http://${url}`);
    if (KNOWN_REDIRECTORS.has(parsedForRedirect.hostname) ||
      [...KNOWN_REDIRECTORS].some(d => parsedForRedirect.hostname.endsWith('.' + d))) {
      for (const param of REDIRECT_PARAMS) {
        const redirectTarget = parsedForRedirect.searchParams.get(param);
        if (redirectTarget && (/^https?:\/\//i.test(redirectTarget) || redirectTarget.startsWith('aHR0c') || redirectTarget.startsWith('aHR0cHM6'))) {
          reasons.push(`⚠️ Open Redirect: Domain resmi dipakai sebagai pengalih ke "${redirectTarget.substring(0, 50)}..."`);
          score += 5;
          break;
        }
      }
    }
  } catch { }

  // IDN HOMOGRAPH ATTACK DETECTION
  const homographResult = detectHomographAttack(rawDomain);
  if (homographResult.isHomograph) {
    if (homographResult.spoofedBrand) {
      reasons.push(
        `⚠️ SERANGAN HOMOGRAPH TERDETEKSI: Domain "${homographResult.visualDomain}" menggunakan ` +
        `karakter Unicode (Cyrillic/Greek) untuk meniru "${homographResult.spoofedBrand}" yang asli. ` +
        `Setelah dinormalisasi: "${homographResult.normalizedDomain}"`
      );
      score += 9;
    } else if (homographResult.hasUnicode) {
      reasons.push(
        `Domain mengandung karakter Unicode mencurigakan — kemungkinan serangan IDN Homograph. ` +
        `Verifikasi domain asli: "${homographResult.normalizedDomain}"`
      );
      score += 6;
    } else if (homographResult.isPunycode) {
      reasons.push(
        `Domain menggunakan format IDN/Punycode (${domain}) — selalu cek tujuan aslinya`
      );
      score += 4;
    }
  }

  // Whitelist check
  let isWhitelisted = WHITELIST_DOMAINS.has(domain) ||
    [...WHITELIST_DOMAINS].some(wl => {
      if (domain === wl) return true;
      if (domain.endsWith('.' + wl)) {
        const subdomain = domain.replace('.' + wl, '');
        const suspiciousSubPatterns = /^(login|secure|verify|update|account|auth|confirm|check|support|cs|help|service|mobile|app|my|info|web|online|portal|care|member|vip|official|id)/i;
        if (suspiciousSubPatterns.test(subdomain) && domain.split('.').length > 3) {
          reasons.push(`Subdomain mencurigakan pada domain resmi: ${subdomain}.${wl}`);
          score += 3;
          return false;
        }
        return domain.split('.').length <= 4;
      }
      return false;
    });

  // GAP FIX: SaaS Exception for Google Sites and Storage
  if (url.includes('sites.google.com') || url.includes('storage.googleapis.com')) {
    isWhitelisted = false;
    score += 4;
    reasons.push("Menggunakan layanan hosting Google (Sites/Storage) yang sering disalahgunakan untuk phishing.");
  }

  // Generate whitelist reason
  let whitelistReason: string | null = null;
  if (isWhitelisted) {
    if (domain.endsWith('.go.id')) {
      whitelistReason = `Domain resmi pemerintah Indonesia (${domain})`;
    } else if (matchedBrand) {
      whitelistReason = `Domain resmi ${matchedBrand} yang terverifikasi`;
    } else {
      whitelistReason = `Domain terpercaya yang terdaftar di whitelist`;
    }
  }

  if (!matchedBrand && homographResult.spoofedBrand) {
    matchedBrand = homographResult.spoofedBrand;
    legitimateDomains = BRAND_DOMAINS[matchedBrand] || [];
  }

  return {
    url: originalUrl,
    domain,
    isSuspicious: score >= 3 && !isWhitelisted,
    reasons,
    score: isWhitelisted ? 0 : score,
    matchedBrand,
    legitimateDomains,
    isWhitelisted,
    whitelistReason
  };
}
