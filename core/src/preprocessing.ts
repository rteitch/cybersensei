// ============================================================
// PREPROCESSING — Normalisasi teks: emoji, homoglyph, leet-speak
// ============================================================

const EMOJI_REGEX = /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{FE00}-\u{FE0F}\u{1F900}-\u{1F9FF}\u{1FA00}-\u{1FA6F}\u{1FA70}-\u{1FAFF}\u{200D}\u{20E3}\u{E0020}-\u{E007F}]/gu;

// ============================================================
// UNICODE HOMOGLYPH MAP untuk URL/Domain & Preprocessing
// Referensi: Python script homograph_attack.py + Unicode Confusables
// Mencakup: Cyrillic, Greek, Armenian, Latin Extended, Fullwidth ASCII
// ============================================================
export const UNICODE_HOMOGLYPH_MAP: Record<string, string> = {
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

// Gunakan SEMUA entries — NFKD normalization tidak mengkonversi Greek/Latin Extended/Fullwidth ke ASCII
const HOMOGLYPH_MAP: Record<string, string> = { ...UNICODE_HOMOGLYPH_MAP };

export function cleanText(raw: string): string {
  if (!raw) return '';
  let text = raw;

  // Normalize Unicode (NFKD) to decompose combined characters
  text = text.normalize('NFKD');
  
  // GAP FIX: Zalgo Text / Combining Diacritical Marks stripping
  text = text.replace(/[\u0300-\u036f]/g, '');

  // Remove emojis and zero-width characters
  text = text.replace(EMOJI_REGEX, ' ');
  // Hapus karakter zero-width dan Bidi Overrides (U+202A-U+202E, U+2066-U+2069) yang sering dipakai penipu
  text = text.replace(/[\u200B-\u200D\uFEFF\u00AD\u202A-\u202E\u2066-\u2069​-‍﻿­]/g, '');

  // Replace homoglyphs (Cyrillic lookalikes → Latin)
  for (const [glyph, replacement] of Object.entries(HOMOGLYPH_MAP)) {
    text = text.split(glyph).join(replacement);
  }

  // ============================================================
  // LEET-SPEAK NORMALIZER — Normalisasi substitusi karakter ASCII
  // Penipu sering pakai: S3LAMAT, N0mor, und!an, trplih, kmpanye
  // Context-aware: hanya normalisasi digit/simbol di ANTARA huruf
  // sehingga angka asli ("50 Juta", "1000") tidak ikut diubah.
  //
  // Contoh: "S3LAMAT" → "SELAMAT", "und!an" → "undian"
  //         "N0mor"   → "NOMOR",   "50 Juta" → "50 Juta" (aman)
  // ============================================================
  // Digit di antara huruf → normalisasi ke huruf yang sering disubstitusi
  text = text.replace(/(?<=[a-zA-Z])3(?=[a-zA-Z])/g, 'e'); // S3LAMAT → SELAMAT
  text = text.replace(/(?<=[a-zA-Z])0(?=[a-zA-Z])/g, 'o'); // N0mor   → NOMOR
  text = text.replace(/(?<=[a-zA-Z])1(?=[a-zA-Z])/g, 'l'); // 1ink    → link
  text = text.replace(/(?<=[a-zA-Z])4(?=[a-zA-Z])/g, 'a'); // h4diah  → hadiah
  text = text.replace(/(?<=[a-zA-Z])5(?=[a-zA-Z])/g, 's'); // 5hopee  → shopee
  text = text.replace(/(?<=[a-zA-Z])7(?=[a-zA-Z])/g, 't'); // 7ransfer → transfer
  text = text.replace(/(?<=[a-zA-Z])8(?=[a-zA-Z])/g, 'b'); // 8ank    → bank
  text = text.replace(/(?<=[a-zA-Z])6(?=[a-zA-Z])/g, 'g'); // 6rab    → grab
  // Simbol leet di antara/setelah huruf
  text = text.replace(/(?<=[a-zA-Z])!(?=[a-zA-Z])/g, 'i'); // und!an  → undian
  text = text.replace(/(?<=[a-zA-Z])\$(?=[a-zA-Z])/g, 's'); // $hopee  → shopee
  text = text.replace(/(?<=[a-zA-Z])@(?=[a-zA-Z])/g, 'a'); // m@u     → mau
  // GAP 26 FIX: Simbol di awal kata (tidak ada lookbehind, gunakan boundary)
  text = text.replace(/(?<=\s|^)7(?=[a-zA-Z]{2,})/g, 't'); // 7ransfer → transfer
  text = text.replace(/(?<=\s|^)4(?=[a-zA-Z]{2,})/g, 'a'); // 4kun     → akun
  text = text.replace(/(?<=\s|^)0(?=[a-zA-Z]{2,})/g, 'o'); // 0rder    → order
  text = text.replace(/(?<=\s|^)1(?=[a-zA-Z]{2,})/g, 'l'); // 1ink     → link
  text = text.replace(/(?<=\s|^)3(?=[a-zA-Z]{2,})/g, 'e'); // 3mail    → email
  text = text.replace(/(?<=\s|^)5(?=[a-zA-Z]{2,})/g, 's'); // 5hop     → shop
  text = text.replace(/(?<=\s|^)8(?=[a-zA-Z]{2,})/g, 'b'); // 8ayar    → bayar
  text = text.replace(/(?<=\s|^)6(?=[a-zA-Z]{2,})/g, 'g'); // 6rab     → grab
  text = text.replace(/(?<=\s|^)\$(?=[a-zA-Z]{2,})/g, 's'); // $elamat → selamat (prefix case)

  // GAP 38 FIX: Normalisasi spasi sebelum tanda baca agar regex pencocokan jarak tidak gagal
  text = text.replace(/\s+([,.;:!?)])/g, '$1');
  text = text.replace(/([\[\\])\s+/g, '$1');

  // Collapse multiple spaces/tabs into single space
  text = text.replace(/[ \t]+/g, ' ');

  // FIX 1 + GAP 23 FIX: Obfuscation collapse — spaced-out text
  // "S E L A M A T" → "SELAMAT" (3+ single-char tokens dianggap obfuscation)
  // Pendekatan: identifikasi run huruf tunggal, collapse sekaligus (bukan pair-wise)
  {
    const tokens = text.split(/(\s+)/);
    const result: string[] = [];
    let runChars: string[] = [];  // hanya huruf tunggal (tanpa spasi)
    let runSpaces: string[] = []; // spasi di antara huruf tunggal

    const flushRun = () => {
      if (runChars.length >= 3) {
        // Collapse: gabungkan semua huruf tunggal tanpa spasi
        result.push(runChars.join(''));
        result.push(' ');
      } else {
        // Run terlalu pendek — pertahankan asli (mis. "a k u" 3 char masih collapse,
        // tapi "A B" 2 char tidak — buang batas: 3+ collapse, 2- pertahankan)
        for (let j = 0; j < runChars.length; j++) {
          result.push(runChars[j]);
          if (j < runSpaces.length) result.push(runSpaces[j]);
        }
      }
      runChars = [];
      runSpaces = [];
    };

    for (const token of tokens) {
      if (/^\s+$/.test(token)) {
        // Whitespace — simpan ke runSpaces jika sedang dalam run
        if (runChars.length > 0) {
          runSpaces.push(token);
        } else {
          result.push(token);
        }
        continue;
      }
      // Non-whitespace token
      if (token.length === 1 && /\w/.test(token)) {
        // Single char — masuk ke run
        runChars.push(token);
      } else {
        // Multi-char token — flush run yang tertunda
        flushRun();
        result.push(token);
      }
    }
    // Flush sisa di akhir
    flushRun();

    text = result.join('').replace(/\s{2,}/g, ' ');
  }

  return text.trim();
}
