// ============================================================
// TYPES — Semua interface dan type yang digunakan di seluruh engine
// ============================================================

export type Verdict = 'AMAN' | 'MENCURIGAKAN' | 'BERBAHAYA';

export interface AnalysisResult {
  verdict: Verdict;
  dangerScore: number;
  redFlags: string[];
  suspiciousKeywords: string[];
  simpleExplanation: string;
  actionItem: string;
  microLesson: string;
}

export interface ScamDatabaseItem {
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

export function getWeightCategory(item: ScamDatabaseItem): "critical" | "high" | "moderate" {
  if (item.weight_category) return item.weight_category;
  if (item.threat_level === "Critical") return "critical";
  if (item.threat_level === "High") return "high";
  return "moderate";
}

export interface RegexRule {
  id: string;
  label: string;
  regex: RegExp;
  regexForPosition?: RegExp;
  score: number;
  weight_category: "critical" | "high" | "moderate";
}

export interface URLAnalysis {
  url: string;
  domain: string;
  isSuspicious: boolean;
  reasons: string[];
  score: number;
  matchedBrand: string | null;       // Nama brand yang mirip (jika ada)
  legitimateDomains: string[];       // Domain resmi dari brand tersebut
  isWhitelisted: boolean;            // Apakah domain ada di whitelist
  whitelistReason: string | null;    // Alasan domain dianggap aman
}

export interface HomographResult {
  isHomograph: boolean;
  hasUnicode: boolean;
  isPunycode: boolean;
  normalizedDomain: string;  // domain setelah homoglyph di-normalize ke ASCII
  spoofedBrand: string | null; // brand mana yang ditiru, jika ada
  visualDomain: string;       // tampilan visual yang user lihat
}
