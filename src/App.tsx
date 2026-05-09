import { useState, useEffect, useRef, useCallback } from 'react';
import { Search, Link as LinkIcon, FileText, RotateCcw, ChevronRight, Shield, BookOpen, Package, Trophy, Landmark, Smartphone, BadgeDollarSign, Users, ShieldAlert, CreditCard, Heart, Briefcase, QrCode, Banknote, Check } from 'lucide-react';
import { AnalysisPanel } from './components/AnalysisPanel';
import { HistorySidebar } from './components/HistorySidebar';
import { MiniQuiz } from './components/MiniQuiz';
import { analyzeTextLocal } from './lib/analyzer';
import { AnalysisResult, HistoryItem } from './types';

const TEXT_EXAMPLES = [
  { label: 'Phishing Paket', icon: Package, text: 'Halo kak, pket anda trtunda. Slahkn cekk r3si d aplikasi ini untk mmperbarui alamt pengiriman. http://resi-jnt-express.apk' },
  { label: 'Undian WA', icon: Trophy, text: 'S3LAMAT!!! N0mor Anda trplih memenangkn und!an 50 Juta dari kmpanye Shopee. Klik tautan brikut s.id/PemenangShopee untk klaim.' },
  { label: 'Minta OTP', icon: Smartphone, text: 'hai, maaf aku salah masukkin nomor hp jadi OTP-nya ke kamu. Tolong kasih tau kode 6 digit yang barusan masuk ke SMS kamu ya, penting banget!' },
  { label: 'Boss Scam', icon: Briefcase, text: 'Ini bos, ganti nomor baru. Tolong segera transfer ke rekening BCA 1234567890 a/n PT Vendor Jaya sebesar Rp 15.000.000 untuk pembayaran client. Jangan bilang siapapun soal ini, rahasia. Proses sekarang ya.' },
  { label: 'Pinjol Ilegal', icon: Banknote, text: 'Selamat! Pengajuan pinjaman Anda ACC. Plafon Rp 20 juta, bunga 0%. Transfer biaya asuransi Rp 350.000 ke BRI 0987654321 a/n Admin untuk proses pencairan dana ke rekening Anda.' },
  { label: 'Investasi Bodong', icon: BadgeDollarSign, text: 'Bergabung sekarang di grup VIP trading kami! Return 15% per bulan sudah terbukti. Deposit minimal Rp 500.000 bisa profit Rp 10.000.000. Sudah ribuan member berhasil. Gabung sebelum kuota penuh!' },
  { label: 'Romance Scam', icon: Heart, text: 'Halo aku menemukan kontakmu di Facebook. Aku tentara Amerika sedang bertugas di Afghanistan. Aku jatuh cinta padamu dari fotomu. Aku butuh uang untuk biaya dokumen izin cuti supaya bisa ke Indonesia menemuimu.' },
  { label: 'Kerja Luar Negeri', icon: Users, text: 'Lowongan kerja ke Malaysia gaji 3000 ringgit per bulan. Proses cepat tanpa tes, siap berangkat dalam 1 minggu. Transfer biaya penempatan Rp 3.000.000 ke rekening agen untuk proses dokumen.' },
  { label: 'Tagihan Pajak', icon: CreditCard, text: 'SURAT PERINGATAN: Anda memiliki tunggakan pajak yang belum dibayar sebesar Rp 5.000.000. Segera bayar melalui link berikut sebelum rekening diblokir permanen: s.id/bayar-pajak-sekarang' },
  { label: 'Virtual Kidnapping', icon: ShieldAlert, text: 'Anak anda ada di tangan kami. Transfer tebusan Rp 50.000.000 dalam 1 jam atau anak anda celaka. Jangan telepon polisi atau anak anda dalam bahaya. Transfer ke rekening ini sekarang.' },
  { label: 'Quishing QRIS', icon: QrCode, text: 'Pembayaran berhasil diverifikasi. Scan QR code berikut untuk konfirmasi pembayaran pesanan Anda. Kode QR akan expired dalam 10 menit. Scan sekarang untuk menghindari pembatalan otomatis.' },
];

const URL_EXAMPLES = [
  { label: 'Link Bank Palsu', icon: Landmark, url: 'http://www-klikbca-verifikasi-akun.com', isUrl: true },
  { label: 'Serangan Homograph', icon: ShieldAlert, url: 'https://gооgle.com/login', isUrl: true },
  { label: 'Shortener URL', icon: LinkIcon, url: 'https://s.id/PemenangShopee', isUrl: true },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<'analisis' | 'kuis'>('analisis');
  const [input, setInput] = useState('');
  const [analyzedText, setAnalyzedText] = useState('');
  const [inputType, setInputType] = useState<'text' | 'url'>('text');
  const [justAnalyzed, setJustAnalyzed] = useState(false);
  const [currentResult, setCurrentResult] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const saved = localStorage.getItem('cybersensei_history');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) setHistory(parsed);
      } catch (e) {
        console.error("Failed to parse history", e);
      }
    }
  }, []);

  const saveToHistory = (item: HistoryItem) => {
    const newHistory = [item, ...history].filter((v, i, a) => a.findIndex(t => (t.id === v.id)) === i).slice(0, 5); // Keep last 5 unique
    setHistory(newHistory);
    localStorage.setItem('cybersensei_history', JSON.stringify(newHistory));
  };

  const handleAnalyze = useCallback(() => {
    if (!input.trim()) return;

    setError(null);
    setCurrentResult(null);

    const result = analyzeTextLocal(input, inputType === 'url');
    setCurrentResult(result);
    setAnalyzedText(input);
    setJustAnalyzed(true);

    const historyItem: HistoryItem = {
      id: Date.now().toString(),
      timestamp: Date.now(),
      input,
      inputType,
      result
    };
    saveToHistory(historyItem);

    // Auto-scroll to results on mobile
    setTimeout(() => {
      resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);

    // Reset feedback indicator after brief delay
    setTimeout(() => setJustAnalyzed(false), 1200);
  }, [input, inputType, history]);

  const handleSelectHistory = (item: HistoryItem) => {
    setInput(item.input);
    setInputType(item.inputType);
    setCurrentResult(item.result);
    setAnalyzedText(item.input);
    setError(null);
    setTimeout(() => {
      resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
  };

  const handleReset = () => {
    setInput('');
    setCurrentResult(null);
    setError(null);
  };

  const handleExampleSelect = (example: { url?: string, text?: string, isUrl?: boolean }) => {
    setInput(example.url || example.text || '');
    setInputType(example.isUrl ? 'url' : 'text');
    setCurrentResult(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen flex flex-col font-sans text-[var(--color-navy)]">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-md border-b border-gray-200/70 sticky top-0 z-30 shadow-sm">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 sm:h-20 flex items-center justify-between">
          <div className="flex items-center gap-3 sm:gap-4">
            <div className="flex items-center">
              <img src="/logo_cybersensei_maskot.png" alt="CyberSensei Logo" className="h-9 sm:h-13 w-auto object-contain drop-shadow-sm" />
            </div>
            <div className="flex flex-col">
              <h1 className="text-lg sm:text-2xl font-extrabold text-[var(--color-navy)] leading-tight tracking-tight flex items-center gap-2">
                CyberSensei
                <span className="bg-blue-100 text-blue-700 text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-widest align-middle">v1.0.0</span>
              </h1>
              <p className="text-[10px] sm:text-xs text-gray-400 font-semibold uppercase tracking-wider hidden sm:block">
                Deteksi Penipuan Digital &middot; Powered by AI
              </p>
            </div>
          </div>
          
          <div className="flex bg-gray-100 p-1 rounded-xl">
            <button
              onClick={() => setActiveTab('analisis')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
                activeTab === 'analisis'
                  ? 'bg-[var(--color-navy)] text-white shadow-md'
                  : 'text-gray-500 hover:text-gray-900'
              }`}
            >
              <Shield className="w-4 h-4" /> <span className="hidden sm:inline">Analisis</span>
            </button>
            <button
              onClick={() => setActiveTab('kuis')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
                activeTab === 'kuis'
                  ? 'bg-[var(--color-navy)] text-white shadow-md'
                  : 'text-gray-500 hover:text-gray-900'
              }`}
            >
              <BookOpen className="w-4 h-4" /> <span className="hidden sm:inline">Uji Kemampuan</span>
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 sm:px-6 py-8 sm:py-10 w-full flex-grow">
        {activeTab === 'analisis' ? (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            
            {/* Left Column: Input Form */}
            <div className="lg:col-span-7 space-y-8">
              
              <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-5 sm:p-7">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-6 gap-4">
                  <h2 className="text-lg font-bold flex items-center gap-2">
                    <Search className="w-5 h-5 text-[var(--color-navy)]" />
                    Apa yang ingin kamu periksa hari ini?
                  </h2>
                  {(input || currentResult) && (
                    <button 
                      onClick={handleReset}
                      className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-[var(--color-danger)] transition-colors px-3 py-1.5 rounded-lg hover:bg-red-50 bg-gray-50 self-start sm:self-auto"
                    >
                      <RotateCcw className="w-4 h-4" /> <span>Reset</span>
                    </button>
                  )}
                </div>

                <div className="flex gap-2 mb-4 bg-gray-50 p-1.5 rounded-xl w-full flex-wrap sm:flex-nowrap">
                  <button
                    onClick={() => { setInputType('text'); setInput(''); setCurrentResult(null); setError(null); }}
                    className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-semibold transition-colors ${inputType === 'text' ? 'bg-white text-[var(--color-navy)] shadow-sm' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100/50'}`}
                  >
                    <FileText className="w-4 h-4" /> Pesan / Email
                  </button>
                  <button
                    onClick={() => { setInputType('url'); setInput(''); setCurrentResult(null); setError(null); }}
                    className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-semibold transition-colors ${inputType === 'url' ? 'bg-white text-[var(--color-navy)] shadow-sm' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100/50'}`}
                  >
                    <LinkIcon className="w-4 h-4" /> Tautan (Web/Link)
                  </button>
                </div>

                {inputType === 'text' ? (
                   <textarea 
                     value={input}
                     onChange={(e) => setInput(e.target.value)}
                     placeholder="Contoh: Selamat! Anda memenangkan hadiah Rp 50 juta dari BRI. Klik tautan berikut untuk klaim..."
                     className="w-full h-40 p-4 rounded-xl border border-gray-200 focus:border-[var(--color-navy)] focus:ring-1 focus:ring-[var(--color-navy)] outline-none resize-none transition-all text-gray-800 bg-gray-50 focus:bg-white"
                   />
                ) : (
                   <input 
                     type="text"
                     value={input}
                     onChange={(e) => setInput(e.target.value)}
                     placeholder="Masukkan tautan yang mencurigakan (contoh: www-bca-verifikasi.com)"
                     className="w-full p-4 rounded-xl border border-gray-200 focus:border-[var(--color-navy)] focus:ring-1 focus:ring-[var(--color-navy)] outline-none transition-all text-gray-800 bg-gray-50 focus:bg-white"
                   />
                )}

                {error && (
                  <div className="mt-4 p-4 rounded-xl bg-red-50 text-red-700 text-sm border border-red-100 font-medium flex gap-3 items-start">
                    <span className="text-lg">😓</span> {error}
                  </div>
                )}

                <button
                  onClick={handleAnalyze}
                  disabled={!input.trim()}
                  className={`w-full mt-6 flex items-center justify-center gap-2 py-4 px-6 rounded-xl font-bold text-base transition-all shadow-md disabled:opacity-70 disabled:cursor-not-allowed ${
                    justAnalyzed
                      ? 'bg-emerald-500 text-white scale-[0.98]'
                      : 'bg-[var(--color-navy)] hover:bg-[#152B47] text-white active:scale-[0.97]'
                  }`}
                >
                  {justAnalyzed ? (
                    <>
                      <Check className="w-5 h-5" />
                      <span>Telah Diperiksa</span>
                    </>
                  ) : (
                    <>
                      <Search className="w-5 h-5" />
                      <span>Periksa Sekarang</span>
                    </>
                  )}
                </button>

                <div className="mt-8 pt-6 border-t border-gray-100">
                  <p className="text-xs text-gray-500 font-bold mb-3 uppercase tracking-wider">Coba contoh kasus nyata:</p>
                  <div className="flex flex-wrap gap-2 sm:gap-2.5">
                    {(inputType === 'text' ? TEXT_EXAMPLES : URL_EXAMPLES).map((example, i) => {
                      const Icon = example.icon;
                      return (
                        <button
                          key={i}
                          onClick={() => handleExampleSelect(example)}
                          className="flex items-center gap-1.5 text-[13px] sm:text-sm bg-white text-slate-600 hover:text-blue-700 hover:bg-blue-50 py-1.5 px-3.5 rounded-full transition-all border border-slate-200 hover:border-blue-200 font-medium shadow-[0_1px_2px_rgba(0,0,0,0.02)] hover:shadow-sm active:scale-[0.98] group"
                        >
                          <Icon className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-slate-400 group-hover:text-blue-500 transition-colors" />
                          <span>{example.label}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>

            </div>

            {/* Right Column: Output Panel & History */}
            <div className="lg:col-span-5 flex flex-col gap-6 scroll-mt-24 sm:scroll-mt-28" ref={resultsRef}>
              <AnalysisPanel result={currentResult} analyzedText={analyzedText} />
              {history.length > 0 && (
                <HistorySidebar history={history} onSelect={handleSelectHistory} />
              )}
            </div>
            
          </div>
        ) : (
          <div className="max-w-3xl mx-auto py-4">
            <MiniQuiz />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="py-6 mt-8 text-center border-t border-gray-200/60 bg-white/60 backdrop-blur-sm">
        <p className="text-sm text-gray-400 font-medium">
          © {new Date().getFullYear()} CyberSensei &mdash; Dari ide ke kenyataan oleh <span className="font-semibold text-[var(--color-navy)]">Rizal TH</span>
          &nbsp;&middot;&nbsp; VibesCoding &times; Gemini
        </p>
        <p className="text-xs text-gray-300 mt-1 font-medium">
          Analisis bersifat edukatif. Selalu verifikasi ke sumber resmi.
        </p>
      </footer>
    </div>
  );
}
