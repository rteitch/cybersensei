import { useState, useRef, ReactNode } from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, AlertCircle, Lightbulb, CheckCircle2, Download, Share2, Shield, FileText, Lock, Eye, Zap, Users } from 'lucide-react';
import { AnalysisResult } from '../types';
import { motion, AnimatePresence } from 'motion/react';
import { toPng } from 'html-to-image';

function getHighlightedText(text: string, highlights: string[], verdict: string): ReactNode[] | string {
  if (!highlights || highlights.length === 0) return text;
  
  const sortedHighlights = [...highlights].sort((a, b) => b.length - a.length);
  const regex = new RegExp(`(${sortedHighlights.map(h => h.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`, 'gi');
  const tokens = text.split(regex);
  
  const isDangerous = verdict === 'BERBAHAYA' || verdict === 'MENCURIGAKAN';
  const highlightClass = isDangerous
    ? "text-red-700 font-bold bg-red-100 px-1 rounded mx-0.5"
    : "text-amber-700 font-bold bg-amber-100 px-1 rounded mx-0.5";

  return tokens.map((part, i) => {
    if (sortedHighlights.find(h => h.toLowerCase() === part.toLowerCase())) {
      return <span key={i} className={highlightClass}>{part}</span>;
    }
    return <span key={i}>{part}</span>;
  });
}

import { SCAM_DB, REGEX_RULES } from '../lib/analyzer';

// ─── Empty State (before any analysis) ───────────────────────────────────────
function EmptyState() {
  const scamCount = SCAM_DB.length;
  let patternCount = REGEX_RULES.length;
  SCAM_DB.forEach(scam => {
    patternCount += scam.patterns.length + scam.keywords.length;
  });

  const stats = [
    { icon: Shield,  value: `${scamCount}+`,   label: 'Modus penipuan' },
    { icon: Eye,     value: `${patternCount}+`,  label: 'Pola berbahaya' },
    { icon: Zap,     value: '<1 dtk', label: 'Waktu analisis' },
    { icon: Users,   value: '100%',  label: 'Gratis selamanya' },
  ];

  const tips = [
    { emoji: '🔐', text: 'OTP adalah kunci akun — TIDAK PERNAH bagikan ke siapapun' },
    { emoji: '🔗', text: 'Periksa URL sebelum klik — perhatikan ejaan & domain aneh' },
    { emoji: '📱', text: 'File .APK dari luar Play Store bisa mencuri data bankmu' },
    { emoji: '💸', text: 'Transfer sebelum terima barang/layanan = tanda penipuan' },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden"
    >
      {/* Hero Section */}
      <div className="bg-gradient-to-br from-[var(--color-navy)] to-[#2d5f9e] p-8 text-center text-white relative overflow-hidden">
        {/* Background decorative circles */}
        <div className="absolute -top-6 -right-6 w-28 h-28 rounded-full bg-white/5" />
        <div className="absolute -bottom-8 -left-8 w-36 h-36 rounded-full bg-white/5" />

        <div className="relative">
          <div className="w-28 h-28 mx-auto mb-4 drop-shadow-lg">
            <img src="/logo_cybersensei_maskot.png" alt="CyberSensei Maskot" className="w-full h-full object-contain" />
          </div>
          <h3 className="text-2xl font-extrabold mb-1 tracking-tight">Halo! Saya CyberSensei</h3>
          <p className="text-white/80 text-sm leading-relaxed max-w-xs mx-auto">
            Tempel pesan atau link mencurigakan di sebelah kiri — saya akan bedah ancamannya dalam hitungan detik.
          </p>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 divide-x divide-gray-100 border-b border-gray-100">
        {stats.map(({ icon: Icon, value, label }) => (
          <div key={label} className="flex flex-col items-center py-4 px-2 text-center gap-1">
            <Icon className="w-4 h-4 text-blue-500 mb-0.5" />
            <span className="text-base font-extrabold text-[var(--color-navy)] leading-none">{value}</span>
            <span className="text-[10px] text-gray-400 font-medium leading-tight">{label}</span>
          </div>
        ))}
      </div>

      {/* Quick Tips */}
      <div className="p-5">
        <p className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-3">Tips Keamanan Digital</p>
        <div className="space-y-2.5">
          {tips.map(({ emoji, text }) => (
            <div key={text} className="flex items-start gap-3 p-3 rounded-xl bg-gray-50/80 border border-gray-100">
              <span className="text-lg leading-none flex-shrink-0">{emoji}</span>
              <p className="text-sm text-gray-600 font-medium leading-snug">{text}</p>
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

// ─── Main AnalysisPanel ───────────────────────────────────────────────────────
export function AnalysisPanel({ result, analyzedText = "" }: { result: AnalysisResult | null, analyzedText?: string }) {
  const panelRef = useRef<HTMLDivElement>(null);
  const [isCapturing, setIsCapturing] = useState(false);

  const handleShare = async () => {
    if (!panelRef.current) return;
    setIsCapturing(true);
    try {
      await new Promise(resolve => setTimeout(resolve, 50));
      const dataUrl = await toPng(panelRef.current, {
        cacheBust: true,
        backgroundColor: '#ffffff',
        pixelRatio: 2,
        style: { transform: 'scale(1)', transformOrigin: 'top left' }
      });
      const link = document.createElement('a');
      link.download = `CyberSensei-Analisis-${Date.now()}.png`;
      link.href = dataUrl;
      link.click();
    } catch (err) {
      console.error("Failed to capture screenshot", err);
      alert("Maaf, gagal menyimpan gambar. Coba ulangi lagi.");
    } finally {
      setIsCapturing(false);
    }
  };

  if (!result) return <EmptyState />;

  const isSafe       = result.verdict === 'AMAN';
  const isSuspicious = result.verdict === 'MENCURIGAKAN';
  const isDangerous  = result.verdict === 'BERBAHAYA';

  // Colour + copy per verdict
  const config = isSafe
    ? {
        gradient:   'from-green-600 to-emerald-500',
        ring:       'ring-green-200',
        icon:       <ShieldCheck className="w-8 h-8 text-white" />,
        sub:        'Tidak ditemukan ancaman berbahaya',
        pulse:      false,
      }
    : isSuspicious
    ? {
        gradient:   'from-amber-500 to-yellow-400',
        ring:       'ring-amber-200',
        icon:       <AlertTriangle className="w-8 h-8 text-white" />,
        sub:        'Ada elemen mencurigakan — tetap waspada',
        pulse:      false,
      }
    : {
        gradient:   'from-red-600 to-rose-500',
        ring:       'ring-red-200',
        icon:       <ShieldAlert className="w-8 h-8 text-white" />,
        sub:        'Ancaman terdeteksi — jangan abaikan!',
        pulse:      true,
      };

  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={result.simpleExplanation}
        initial={{ opacity: 0, y: 20, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.45, ease: 'easeOut' }}
        className={`bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden ring-2 ${config.ring}`}
      >
        <div ref={panelRef} className="bg-white pb-2 relative">

          {/* ── Verdict Header ─────────────────────────────────────────────── */}
          <div className={`bg-gradient-to-r ${config.gradient} px-6 pt-7 pb-6 text-white relative overflow-hidden`}>
            {/* Decorative blobs */}
            <div className="absolute -top-4 -right-4 w-24 h-24 rounded-full bg-white/10" />
            <div className="absolute bottom-0 left-1/2 w-32 h-32 -translate-x-1/2 translate-y-1/2 rounded-full bg-white/5" />

            <div className="relative flex items-center gap-4">
              {/* Pulsing icon for BERBAHAYA */}
              <div className={`p-3 rounded-2xl bg-white/20 flex-shrink-0 ${config.pulse ? 'animate-pulse' : ''}`}>
                {config.icon}
              </div>
              <div>
                <p className="text-white/75 text-xs font-semibold uppercase tracking-widest mb-0.5">
                  Hasil Analisis CyberSensei
                </p>
                <h2 className="text-3xl font-extrabold tracking-tight leading-none">
                  {result.verdict}
                </h2>
                <p className="text-white/85 text-sm font-medium mt-1">{config.sub}</p>
              </div>

              {isCapturing && (
                <div className="absolute top-0 right-0 text-white/80 text-xs font-bold bg-black/15 px-2 py-1 rounded-md">
                  cybersensei.app
                </div>
              )}
            </div>
          </div>

          <div className="p-6 space-y-6">

            {/* ── Danger Meter ─────────────────────────────────────────────── */}
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.25 }}>
              <div className="flex justify-between items-end mb-2">
                <h3 className="font-bold text-[var(--color-navy)] text-sm">Skor Bahaya</h3>
                <div className="flex items-baseline gap-0.5">
                  <span className="text-3xl font-extrabold text-[var(--color-navy)] leading-none">
                    {result.dangerScore}
                  </span>
                  <span className="text-gray-400 text-base font-semibold">/10</span>
                </div>
              </div>
              <div className="h-3 w-full bg-gray-100 rounded-full overflow-hidden">
                <motion.div
                  className="h-full rounded-full bg-gradient-to-r from-green-400 via-amber-400 to-red-500"
                  initial={{ width: 0 }}
                  animate={{ width: `${(result.dangerScore / 10) * 100}%` }}
                  transition={{ duration: 1, delay: 0.4, ease: 'easeOut' }}
                />
              </div>
              {/* Labels */}
              <div className="flex justify-between mt-1">
                <span className="text-[10px] text-green-600 font-semibold">Aman</span>
                <span className="text-[10px] text-amber-600 font-semibold">Waspada</span>
                <span className="text-[10px] text-red-600 font-semibold">Bahaya</span>
              </div>
            </motion.div>

            {/* ── Analyzed Text ─────────────────────────────────────────────── */}
            {analyzedText && (
              <motion.div
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.35 }}
                className="bg-gray-50 rounded-xl p-4 border border-gray-100"
              >
                <h3 className="font-bold text-[var(--color-navy)] flex items-center gap-2 mb-2 text-sm">
                  <FileText className="w-4 h-4 text-gray-400 flex-shrink-0" /> Teks yang Dianalisis
                </h3>
                <p className="font-mono text-sm leading-relaxed whitespace-pre-wrap text-gray-700 break-words">
                  {result.suspiciousKeywords
                    ? getHighlightedText(analyzedText, result.suspiciousKeywords, result.verdict)
                    : analyzedText}
                </p>
              </motion.div>
            )}

            {/* ── Red Flags ─────────────────────────────────────────────────── */}
            {result.redFlags.length > 0 && (
              <motion.div
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.45 }}
                className="bg-red-50 rounded-xl p-4 border border-red-100"
              >
                <h3 className="font-bold text-red-800 flex items-center gap-2 mb-3 text-sm">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" /> Tanda Bahaya yang Ditemukan
                </h3>
                <ul className="space-y-1.5">
                  {result.redFlags.map((flag, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-red-700 text-sm font-medium">
                      <span className="mt-0.5 flex-shrink-0 w-4 h-4 rounded-full bg-red-200 text-red-700 text-[10px] flex items-center justify-center font-bold">
                        {idx + 1}
                      </span>
                      <span>{flag}</span>
                    </li>
                  ))}
                </ul>
              </motion.div>
            )}

            {/* ── Simple Explanation ────────────────────────────────────────── */}
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 }}>
              <h3 className="font-bold text-[var(--color-navy)] mb-2 text-sm">Penjelasan Singkat</h3>
              <p className="text-gray-700 leading-relaxed font-medium text-sm">{result.simpleExplanation}</p>
            </motion.div>

            {/* ── Action Item ───────────────────────────────────────────────── */}
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.6 }}
              className="bg-blue-50 rounded-xl p-4 border border-blue-100"
            >
              <h3 className="font-bold text-[var(--color-navy)] flex items-center gap-2 mb-2 text-sm">
                <CheckCircle2 className="w-4 h-4 text-blue-600 flex-shrink-0" /> Yang Harus Kamu Lakukan
              </h3>
              <p className="text-[var(--color-navy)] font-medium leading-relaxed text-sm">{result.actionItem}</p>
            </motion.div>

            {/* ── Micro Lesson ──────────────────────────────────────────────── */}
            {result.microLesson && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.7 }}
                className="bg-amber-50 rounded-xl p-4 border border-amber-100"
              >
                <h3 className="font-bold text-amber-900 flex items-center gap-2 mb-2 text-sm">
                  <Lightbulb className="w-4 h-4 text-amber-500 flex-shrink-0" /> Tahukah Kamu?
                </h3>
                <p className="text-amber-800 font-medium italic text-sm leading-relaxed">{result.microLesson}</p>
              </motion.div>
            )}

          </div>
        </div>

        {/* ── Share Buttons ──────────────────────────────────────────────────── */}
        {!isCapturing && (
          <div className="px-6 pb-6 pt-0 border-t border-gray-100 flex gap-3 mt-2">
            <button
              onClick={handleShare}
              className="flex-1 flex items-center justify-center gap-2 bg-white border border-gray-200 hover:bg-gray-50 text-[var(--color-navy)] py-3 px-4 rounded-xl font-bold transition-colors text-sm"
            >
              <Download className="w-4 h-4" /> Simpan Gambar
            </button>
            <button
              onClick={async () => {
                try {
                  if (navigator.share) {
                    await navigator.share({
                      title: 'Hasil Analisis CyberSensei',
                      text: `Pesan ini terdeteksi: ${result.verdict}! Cek ancaman digitalmu di CyberSensei.`,
                      url: window.location.href,
                    });
                  } else {
                    handleShare();
                  }
                } catch (e) {
                  console.log('Share canceled');
                }
              }}
              className="flex-1 flex items-center justify-center gap-2 bg-[var(--color-navy)] text-white hover:bg-[#152B47] py-3 px-4 rounded-xl font-bold transition-colors text-sm"
            >
              <Share2 className="w-4 h-4" /> Bagikan Hasil
            </button>
          </div>
        )}
      </motion.div>
    </AnimatePresence>
  );
}
