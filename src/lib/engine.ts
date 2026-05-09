// ============================================================
// ENGINE — Core analysis logic: regex checking, fuzzy search, scoring, decisions
// ============================================================

import Fuse from 'fuse.js';
import { AnalysisResult } from '../types';
import { ScamDatabaseItem, getWeightCategory } from './types';
import { cleanText } from './preprocessing';
import { extractUrls, analyzeURL } from './url-analyzer';
import {
  REGEX_RULES,
  WEIGHT_MULTIPLIERS,
  CRITICAL_RULE_IDS,
  URL_IRRELEVANT_RULES,
  DANGEROUS_COMBOS,
  NEGATION_PATTERN,
  NEGATION_WINDOW
} from './regex-rules';
import { SCAM_DB } from './scam-db';

// ============================================================
// Fuse.js cache
// ============================================================
const fuseCache = new Map<string, Fuse<ScamDatabaseItem>>();
function getFuse(threshold: number): Fuse<ScamDatabaseItem> {
  const key = String(threshold);
  if (!fuseCache.has(key)) {
    fuseCache.set(key, new Fuse(SCAM_DB, {
      keys: [
        { name: 'patterns', weight: 0.7 },
        { name: 'keywords', weight: 0.3 }
      ],
      includeScore: true,
      threshold,
      minMatchCharLength: 4,
      distance: 100
    }));
  }
  return fuseCache.get(key)!;
}

// ============================================================
// Regex-based detection
// ============================================================
const checkWithRegex = (text: string, isUrlInput: boolean = false, urlMatchedBrands: Set<string> = new Set()) => {
  const flags: string[] = [];
  const suspiciousKeywordsList: string[] = [];
  const matchedRuleIds: string[] = [];
  const negatedRuleIds: string[] = [];
  let rawScore = 0;
  const categoryCounts: Record<string, number> = {};

  for (const rule of REGEX_RULES) {
    // FIX 5: Skip typosquatting regex if URL analyzer already detected the same brand
    if (rule.id === 'typosquatting' && urlMatchedBrands.size > 0) {
      rule.regex.lastIndex = 0;
      const testMatch = rule.regex.exec(text);
      if (testMatch) {
        const matchedText = testMatch[0].toLowerCase();
        const alreadyCaught = [...urlMatchedBrands].some(brand => matchedText.includes(brand));
        if (alreadyCaught) continue;
      }
    }

    const urlWeightFactor = (isUrlInput && URL_IRRELEVANT_RULES.has(rule.id)) ? 0.3 : 1.0;
    rule.regex.lastIndex = 0;
    const matches = text.match(rule.regex);
    if (matches) {
      const firstMatch = rule.regexForPosition?.exec(text);
      let isNegated = false;
      if (firstMatch) {
        const matchEnd = firstMatch.index + firstMatch[0].length;
        const beforeWindow = text.substring(Math.max(0, firstMatch.index - NEGATION_WINDOW), firstMatch.index);
        const afterWindow  = text.substring(matchEnd, matchEnd + NEGATION_WINDOW);
        isNegated = NEGATION_PATTERN.test(beforeWindow) || NEGATION_PATTERN.test(afterWindow);
        
        // GAP FIX: Reverse Psychology Negation
        if (isNegated) {
           const NEGATION_REVERSAL_WORDS = /(sampai ketinggalan|lewatkan|abaikan|tunda lagi|bukan penipuan)/i;
           if (NEGATION_REVERSAL_WORDS.test(beforeWindow) || NEGATION_REVERSAL_WORDS.test(afterWindow)) {
              isNegated = false;
           }
        }
      }

      flags.push(rule.label);
      suspiciousKeywordsList.push(...matches);
      matchedRuleIds.push(rule.id);
      if (isNegated) negatedRuleIds.push(rule.id);

      const cat = rule.weight_category;
      categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;

      const MIN_DECAY = 0.3;
      const decayFactor = Math.max(MIN_DECAY, 1 / Math.pow(2, categoryCounts[cat] - 1));
      const multiplier = WEIGHT_MULTIPLIERS[cat] || 1.0;
      const negationFactor = isNegated ? 0.25 : 1.0;

      rawScore += rule.score * multiplier * decayFactor * negationFactor * urlWeightFactor;
    }
  }

  const score = Math.min(rawScore, 15);
  return { flags, suspiciousKeywordsList, matchedRuleIds, negatedRuleIds, score, rawScore };
};

// ============================================================
// Jaccard Similarity — Mengukur kemiripan dua himpunan token
// J(A, B) = |A ∩ B| / |A ∪ B|, range 0–1
// ============================================================
function jaccardSimilarity(a: string, b: string): number {
  const tokenize = (s: string) =>
    new Set(s.toLowerCase().split(/[\s.,!?;:"'()\[\]{}]+/).filter(t => t.length >= 3));
  const tokA = tokenize(a);
  const tokB = tokenize(b);
  if (tokA.size === 0 || tokB.size === 0) return 0;
  const intersection = [...tokA].filter(t => tokB.has(t)).length;
  const union = new Set([...tokA, ...tokB]).size;
  return union === 0 ? 0 : intersection / union;
}

// Pre-compute Jaccard corpora tokens (one-time at module load)
const PRECOMPUTED_CORPORA = SCAM_DB.map(item => {
  const corpus = [...item.patterns, ...item.keywords].join(' ').toLowerCase();
  const tokens = new Set(corpus.split(/[\s.,!?;:"'()\[\]{}]+/).filter(t => t.length >= 3));
  return { item, tokens };
});

// DJB2 hash for cache key — fast, low collision, by Daniel J. Bernstein
function djb2Hash(str: string): string {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash) + str.charCodeAt(i);
  }
  // Combine with length as safety net against theoretical collision
  return `${hash.toString(36)}_${str.length}`;
}

// Module-level cache untuk mencegah perhitungan ulang pada input yang sama
const analysisCache = new Map<string, AnalysisResult>();
const MAX_CACHE_SIZE = 100;

// ============================================================
// Main analysis function
// ============================================================
export function analyzeTextLocal(input: string, isUrlInput: boolean = false): AnalysisResult {
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

  // Cek cache
  const cacheKey = `${isUrlInput}:${input.substring(0, 10)}_${djb2Hash(input)}`;
  if (analysisCache.has(cacheKey)) {
    return analysisCache.get(cacheKey)!;
  }

  // Truncate extremely long inputs to prevent ReDoS
  const MAX_INPUT_LENGTH = 5000;
  const safeInput = input.length > MAX_INPUT_LENGTH
    ? input.substring(0, MAX_INPUT_LENGTH) + '...[truncated]'
    : input;

  // 1. Preprocess text
  const cleaned = cleanText(safeInput);

  // 2. URL analysis (extract and analyze any URLs in the text)
  // FIX: Extract from BOTH raw and cleaned text — homoglyph URLs (e.g. bіt.ly with Cyrillic і)
  // won't be found in raw but will normalize to valid URLs after cleanText
  const rawUrls = extractUrls(safeInput);
  const cleanedUrls = extractUrls(cleaned);
  const urls = [...new Set([...rawUrls, ...cleanedUrls])];
  const urlResults = urls.map(u => analyzeURL(u));
  const urlScore = urlResults.reduce((sum, r) => sum + r.score, 0);
  const urlFlags: string[] = [];
  const urlKeywords: string[] = [];

  for (const ur of urlResults) {
    if (ur.isWhitelisted) {
      if (ur.whitelistReason) {
        urlFlags.push(`✅ ${ur.whitelistReason}`);
      }
      if (ur.matchedBrand && ur.legitimateDomains.length > 0) {
        urlFlags.push(`✅ Domain resmi ${ur.matchedBrand}: ${ur.legitimateDomains.join(', ')}`);
      }
    } else if (ur.isSuspicious) {
      urlKeywords.push(ur.url);
      for (const reason of ur.reasons) {
        urlFlags.push(reason);
      }
      if (ur.matchedBrand && ur.legitimateDomains.length > 0) {
        urlFlags.push(`Domain resmi ${ur.matchedBrand} yang asli: ${ur.legitimateDomains.join(', ')}`);
      }
    }
  }

  // 3. Regex-based detection on cleaned text
  // Collect brands already detected by URL analyzer to avoid double-counting typosquatting
  const urlMatchedBrands = new Set(
    urlResults.filter(ur => ur.matchedBrand).map(ur => ur.matchedBrand!)
  );
  const { flags: regexFlags, suspiciousKeywordsList, matchedRuleIds, negatedRuleIds, score: regexScore } = checkWithRegex(cleaned, isUrlInput, urlMatchedBrands);

  // 4. Fuzzy Search
  const dynamicThreshold = cleaned.length < 30 ? 0.15 : 0.3;
  const fuse = getFuse(dynamicThreshold);
  const searchResults = fuse.search(cleaned);

  // 5. Decision logic with weighted scoring
  let decision: "AMAN" | "MENCURIGAKAN" | "BERBAHAYA" = "AMAN";
  let explanation = "Kami tidak menemukan sesuatu yang mencolok secara berbahaya dalam pesan ini.";
  let action = "Jika ini pesan dari nomor tidak dikenal, cukup hiraukan atau balas sesuai konteks secara aman.";
  let lesson = "Selalu verifikasi identitas pengirim sebelum mengikuti instruksi dari pesan tak dikenal.";
  let finalScore = regexScore + urlScore;
  let finalKeywords = [...suspiciousKeywordsList, ...urlKeywords];
  let finalFlags = [...regexFlags, ...urlFlags];

  // Rule Interaction Scoring — bonus untuk kombinasi sinyal berbahaya
  for (const combo of DANGEROUS_COMBOS) {
    const allActiveAndNotNegated = combo.rules.every(
      ruleId => matchedRuleIds.includes(ruleId) && !negatedRuleIds.includes(ruleId)
    );
    if (allActiveAndNotNegated) {
      finalScore += combo.bonus;
      finalFlags.push(`⚠️ Kombinasi sinyal bahaya: ${combo.label}`);
    }
  }

  // CRITICAL OVERRIDE — berbasis rule ID
  let hasCriticalRule = matchedRuleIds.some(
    id => CRITICAL_RULE_IDS.has(id) && !negatedRuleIds.includes(id)
  );

  // Multi-match — ambil top-3 results dari Fuse.js
  const TOP_MATCHES = 3;
  const topMatches = searchResults
    .filter(r => r.score !== undefined && (1 - r.score) > 0.45)
    .slice(0, TOP_MATCHES);

  // Kumpulkan flags & keywords dari semua top matches
  const lowerCleaned = cleaned.toLowerCase();
  for (const match of topMatches) {
    match.item.keywords.forEach(kw => {
      if (lowerCleaned.includes(kw.toLowerCase())) {
        if (!finalKeywords.includes(kw)) finalKeywords.push(kw);
      }
    });
  }

  const bestMatch = topMatches[0] ?? searchResults[0];

  // Infer critical dari DB match dengan threat_level Critical
  if (!hasCriticalRule && bestMatch && bestMatch.score !== undefined) {
    const sim = 1 - bestMatch.score;
    if (sim > 0.55 && bestMatch.item.weight_category === 'critical') {
      hasCriticalRule = true;
      finalFlags.push(`⚠️ Modus kritis terdeteksi via database: "${bestMatch.item.category}" (confidence: ${Math.round(sim * 100)}%)`);
    }
  }

  // Jaccard Similarity Fallback
  if (!hasCriticalRule && topMatches.length === 0 && cleaned.length >= 10) {
    let bestJaccard = 0;
    let bestJaccardItem: ScamDatabaseItem | null = null;
    const inputTokens = new Set(cleaned.toLowerCase().split(/[\s.,!?;:"'()\[\]{}]+/).filter(t => t.length >= 3));
    for (const { item, tokens: corpusTokens } of PRECOMPUTED_CORPORA) {
      if (inputTokens.size === 0 || corpusTokens.size === 0) continue;
      const intersection = [...inputTokens].filter(t => corpusTokens.has(t)).length;
      const union = new Set([...inputTokens, ...corpusTokens]).size;
      const sim = union === 0 ? 0 : intersection / union;
      if (sim > bestJaccard) { bestJaccard = sim; bestJaccardItem = item; }
    }
    if (bestJaccardItem && bestJaccard >= 0.15) {
      const earlyNegation = NEGATION_PATTERN.test(cleaned.substring(0, 60));
      const fullTextNegation = !earlyNegation && NEGATION_PATTERN.test(cleaned);
      const negationStrength = earlyNegation ? 0.25 : (fullTextNegation ? 0.5 : 1.0);
      const jaccardContrib = Math.min(bestJaccard * 8, 4) * negationStrength;
      finalScore += jaccardContrib;
      if (negationStrength < 1.0) {
        finalFlags.push(`ℹ️ Kemiripan pola terdeteksi tapi pesan bernada peringatan/edukasi`);
      } else {
        finalFlags.push(`ℹ️ Kemiripan pola token: ${Math.round(bestJaccard * 100)}% — kategori "${bestJaccardItem.category}"`);
      }
    }
  }

  // Critical Override — jalankan SEBELUM blok DB match
  if (hasCriticalRule) {
    decision = "BERBAHAYA";
    if (bestMatch && bestMatch.score !== undefined && (1 - bestMatch.score) > 0.45) {
      explanation = bestMatch.item.analysis_result;
      action = bestMatch.item.action;
      lesson = bestMatch.item.micro_lesson;
      const dbWeight = WEIGHT_MULTIPLIERS[getWeightCategory(bestMatch.item)] || 1.0;
      finalScore += 5 * dbWeight;
    } else {
      finalScore += 7;
      explanation = "Pesan ini mengandung sinyal risiko tinggi yang teridentifikasi sebagai pola penipuan berbahaya — seperti permintaan OTP, ancaman aparat palsu, atau pemerasan.";
      action = "JANGAN berikan OTP, PIN, atau transfer uang. Blokir nomor pengirim dan laporkan ke pihak berwenang.";
      lesson = "Jangan pernah memberikan OTP atau data sensitif kepada siapapun — termasuk yang mengaku dari bank, polisi, atau pemerintah.";
    }
  } else if (bestMatch && bestMatch.score !== undefined) {
    const similarityScore = 1 - bestMatch.score;
    const dbWeight = WEIGHT_MULTIPLIERS[getWeightCategory(bestMatch.item)] || 1.0;

    if (similarityScore > 0.6 && finalScore >= 4) {
      decision = "BERBAHAYA";
      explanation = bestMatch.item.analysis_result;
      action = bestMatch.item.action;
      lesson = bestMatch.item.micro_lesson;
      finalScore += 5 * dbWeight;
      if (!finalFlags.length) {
        finalFlags.push("Sangat mirip dengan database modus penipuan berulang kami.");
      }
    } else if (similarityScore > 0.5 && finalScore >= 3) {
      decision = "BERBAHAYA";
      explanation = bestMatch.item.analysis_result || "Meski kata penyampaiannya berbeda, ini mendemonstrasikan kelakuan phising standar.";
      action = bestMatch.item.action || "Hapus atau laporkan pesan sebagai Spam.";
      lesson = bestMatch.item.micro_lesson || "Pahami bahwa trik penipu selalu berkembang setiap detiknya.";
      finalScore += 4 * dbWeight;
    } else if (similarityScore > 0.45 || finalScore >= 5) {
      decision = "MENCURIGAKAN";
      explanation = bestMatch.item.analysis_result
        ? `Pesan ini memiliki kemiripan dengan modus "${bestMatch.item.category}". ${bestMatch.item.analysis_result}`
        : "Pesan ini mengandung pola yang umum digunakan dalam penipuan digital. Waspadalah.";
      action = bestMatch.item.action || "Verifikasi pengirim melalui saluran resmi sebelum bertindak.";
      lesson = bestMatch.item.micro_lesson || "Pahami bahwa trik penipu selalu berkembang setiap detiknya.";
      finalScore += 3;
    } else if (similarityScore > 0.35 || finalScore >= 3) {
      decision = "MENCURIGAKAN";
      explanation = "Pesan ini punya pola umum layaknya spam atau mengarah perlahan-perlahan ke dalam tipuan.";
      action = "Jangan membagikan data diri secara cuma-cuma dan terus bersikap kritis.";
      lesson = "Pahami bahwa trik penipu selalu berkembang setiap detiknya.";
      finalScore += 2;
    }
  } else if (finalScore >= 10) {
    decision = "BERBAHAYA";
    explanation = "Pesan ini mengandung kombinasi sinyal risiko sangat tinggi yang identik dengan pola penipuan digital aktif, meski belum cocok persis dengan modus di database kami.";
    action = "JANGAN klik tautan apapun, JANGAN transfer uang, dan segera blokir nomor pengirim.";
    lesson = "Penipu terus memperbarui modus mereka. Sinyal berbahaya yang sangat kuat dari analisis otomatis harus dianggap serius.";
    finalFlags.push("Kombinasi sinyal risiko sangat tinggi terdeteksi dari analisis URL dan pola teks.");
  } else if (finalScore >= 8) {
    decision = "MENCURIGAKAN";
    explanation = "Pesan ini mengandung beberapa pola yang umum digunakan dalam penipuan, namun tidak cocok dengan modus spesifik di database kami. Tetap waspada.";
    action = "Verifikasi pengirim melalui saluran resmi sebelum bertindak. Jangan klik tautan atau berikan data pribadi.";
    finalFlags.push("Terdapat beberapa indikator risiko, meski belum cocok dengan modus penipuan yang diketahui.");
  } else if (finalScore >= 4) {
    decision = "MENCURIGAKAN";
    explanation = "Ada elemen seperti tautan singkatan atau ajakan buru-buru, tapi agak sulit dikategorikan pasti sebagai ancaman.";
    action = "Cross-check ulang pihak pengirim aslinya. Buka tabungan mandiri/shopee dll dari aplikasinya langsung, BUKAN dari tautannya.";
  }

  // Normalisasi finalScore dikunci ke decision
  let displayScore: number;
  if (decision === "BERBAHAYA") {
    displayScore = Math.min(Math.max(Math.round(5 + (finalScore / 20) * 5), 7), 10);
  } else if (decision === "MENCURIGAKAN") {
    displayScore = Math.min(Math.max(Math.round(2 + (finalScore / 20) * 4), 4), 6);
  } else {
    displayScore = Math.min(Math.max(Math.round((finalScore / 20) * 3) + 1, 1), 3);
  }

  // ============================================================
  // LAYER 0: WHITELIST SHIELD — final override sebelum return
  // ============================================================
  const anyWhitelisted = urlResults.some(ur => ur.isWhitelisted);
  const anyHomograph   = urlResults.some(
    ur => ur.isSuspicious && ur.reasons.some(r => r.includes("HOMOGRAPH"))
  );
  const allUrlsClean = urlResults.length > 0 && urlResults.every(ur => !ur.isSuspicious);
  const hasOnlyWhitelistedUrls = urlResults.length > 0 && urlResults.every(ur => ur.isWhitelisted);

  if (anyWhitelisted && !anyHomograph && allUrlsClean && hasOnlyWhitelistedUrls && !hasCriticalRule && regexScore < 4) {
    const whitelistedEntry = urlResults.find(ur => ur.isWhitelisted);
    decision      = "AMAN";
    displayScore  = 1;
    explanation   = whitelistedEntry?.whitelistReason
      ? `Pesan ini berasal dari layanan terpercaya: ${whitelistedEntry.whitelistReason}.`
      : "Pesan ini mengandung tautan dari layanan resmi yang terpercaya.";
    action  = "Pesan ini aman untuk ditindaklanjuti. Namun tetap jangan bagikan OTP kepada siapapun.";
    lesson  = "Layanan resmi (bank, e-wallet, pemerintah) tidak pernah meminta OTP, PIN, atau password melalui pesan. Hanya tindaklanjuti instruksi yang masuk akal sesuai konteks.";
    finalFlags = finalFlags.filter(f => f.startsWith("✅") || f.startsWith("ℹ️"));
  }

  const result: AnalysisResult = {
    verdict: decision,
    dangerScore: displayScore,
    redFlags: Array.from(new Set(finalFlags)),
    suspiciousKeywords: Array.from(new Set(finalKeywords)),
    simpleExplanation: explanation,
    actionItem: action,
    microLesson: lesson
  };

  // Simpan hasil analisis ke cache
  if (analysisCache.size >= MAX_CACHE_SIZE) {
    const firstKey = analysisCache.keys().next().value;
    if (firstKey) analysisCache.delete(firstKey);
  }
  analysisCache.set(cacheKey, result);

  return result;
}

// ============================================================
// Quiz answer processing
// ============================================================
export function processQuizAnswerLocal(input: string, isSafe: boolean, _exampleNumber: number): string {
  if (!input || !input.trim()) {
    return "Pesan kosong tidak bisa dianalisis.";
  }

  const cleaned = cleanText(input);
  const { score, matchedRuleIds: quizMatchedIds, negatedRuleIds: quizNegatedIds } = checkWithRegex(cleaned);

  const dynamicThreshold = cleaned.length < 30 ? 0.15 : 0.3;
  const fuse = getFuse(dynamicThreshold);
  const result = fuse.search(cleaned);

  const topMatches = result.filter(r => r.score !== undefined && (1 - r.score) > 0.45).slice(0, 3);
  const hasStrongMatch = topMatches.some(r => (1 - r.score!) > 0.6);
  const hasCriticalInQuiz = quizMatchedIds.some(
    id => CRITICAL_RULE_IDS.has(id) && !quizNegatedIds.includes(id)
  );

  const urls = extractUrls(input);
  const urlResults = urls.map(u => analyzeURL(u));
  const urlScore = urlResults.reduce((sum, r) => sum + r.score, 0);
  const totalScore = score + urlScore;

  let isActuallySafe = true;
  if (totalScore >= 3 || hasStrongMatch || hasCriticalInQuiz) {
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
