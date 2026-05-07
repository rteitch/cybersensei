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

export interface HistoryItem {
  id: string;
  timestamp: number;
  input: string;
  inputType: 'text' | 'url';
  result: AnalysisResult;
}
