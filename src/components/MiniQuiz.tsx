import { useState, ReactNode } from 'react';
import { ShieldCheck, ShieldAlert, ChevronRight, HelpCircle, Target, CheckCircle2, XCircle, RotateCcw } from 'lucide-react';
import { processQuizAnswerLocal } from '../lib/analyzer';

const QUIZ_EXAMPLES = [
  {
    id: 1,
    isSafe: false,
    type: 'Pesan Singkat / SMS',
    content: "INFO R3SMI: N0mor anda mmenangkn unDian Rp 50jt dr Sh0pee. Klik link brikut utk klaim s.id/hadiah-shopee-resmi",
    highlights: ["INFO R3SMI", "Rp 50jt", "s.id/hadiah-shopee-resmi"]
  },
  {
    id: 2,
    isSafe: false,
    type: 'Email',
    content: "Yth. Nasabah,\n\nAkun m-banking anda telah D1Batasi smentara krna ada aktivitas mncurigakn. Segera lakukn verivikasi data anda dlm 24 jam untk mnghindari pemblokiran permanen, klik:\nwww-bca-verifikasi-id.com/aman",
    highlights: ["D1Batasi", "dlm 24 jam", "www-bca-verifikasi-id.com/aman"]
  },
  {
    id: 3,
    isSafe: true,
    type: 'Email',
    content: "Halo Budi,\n\nMengingatkan kembali jadwal meeting kita besok jam 10 pagi terkait proyek X. Tautan Google Meet sudah saya lampirkan di kalender ya.\n\nSalam,\nAndi",
    highlights: []
  }
];

function getHighlightedText(text: string, highlights: string[], showHighlight: boolean): ReactNode[] | string {
  if (!showHighlight || highlights.length === 0) return text;
  
  const regex = new RegExp(`(${highlights.map(h => h.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`, 'gi');
  const tokens = text.split(regex);
  
  return tokens.map((part, i) => {
    if (highlights.find(h => h.toLowerCase() === part.toLowerCase())) {
      return <span key={i} className="text-red-300 font-bold bg-red-900/40 px-1 rounded mx-0.5">{part}</span>;
    }
    return <span key={i}>{part}</span>;
  });
}

export function MiniQuiz() {
  const [currentIdx, setCurrentIdx] = useState(0);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [score, setScore] = useState(0);
  const [showFinalScore, setShowFinalScore] = useState(false);
  const [userCorrect, setUserCorrect] = useState<boolean | null>(null);

  const currentExample = QUIZ_EXAMPLES[currentIdx];

  const handleGuess = async (isSafeGuess: boolean) => {
    setIsLoading(true);
    setFeedback(null);
    setUserCorrect(null);
    
    // Check answer immediately
    const correct = (isSafeGuess === currentExample.isSafe);
    setUserCorrect(correct);
    if (correct) {
      setScore(s => s + 1);
    }

    try {
      const response = processQuizAnswerLocal(currentExample.content, isSafeGuess, currentExample.id);
      setFeedback(response);
    } catch (err) {
      setFeedback("Maaf, terjadi kesalahan saat mengecek jawaban.");
    } finally {
      setIsLoading(false);
    }
  };

  const nextQuestion = () => {
    if (currentIdx === QUIZ_EXAMPLES.length - 1) {
      setShowFinalScore(true);
    } else {
      setFeedback(null);
      setUserCorrect(null);
      setCurrentIdx((prev) => prev + 1);
    }
  };

  const resetQuiz = () => {
    setScore(0);
    setCurrentIdx(0);
    setFeedback(null);
    setShowFinalScore(false);
    setUserCorrect(null);
  };

  if (showFinalScore) {
    let level = "Pemula 👶";
    if (score === QUIZ_EXAMPLES.length) level = "Pejuang Digital 🛡️";
    else if (score > 0) level = "Murid Berbakat 🎓";

    return (
      <div className="bg-[var(--color-navy)] text-white rounded-2xl shadow-sm overflow-hidden mt-8 relative">
         <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none w-64 h-64">
           <HelpCircle className="w-48 h-48" />
         </div>
         <div className="relative p-8 text-center flex flex-col items-center">
            <div className="w-20 h-20 bg-blue-500/20 rounded-full flex items-center justify-center mb-6">
              <Target className="w-10 h-10 text-blue-300" />
            </div>
            <h3 className="text-2xl font-bold mb-2">Uji Kemampuan Selesai!</h3>
            <p className="text-gray-300 mb-6 font-medium">Kamu menjawab {score} dari {QUIZ_EXAMPLES.length} pertanyaan dengan benar.</p>
            <div className="bg-white/10 border border-white/20 rounded-xl p-6 mb-8 w-full max-w-sm">
              <p className="text-sm text-blue-200 uppercase tracking-wider font-semibold mb-1">Level Kamu</p>
              <p className="text-2xl font-bold">{level}</p>
            </div>
            <button 
              onClick={resetQuiz}
              className="flex items-center justify-center gap-2 bg-white text-[var(--color-navy)] hover:bg-gray-100 py-3 px-6 rounded-xl font-bold transition-colors w-full sm:w-auto"
            >
              <RotateCcw className="w-5 h-5" /> Ulangi Kuis
            </button>
         </div>
      </div>
    );
  }

  return (
    <div className="bg-[var(--color-navy)] text-white rounded-2xl shadow-sm overflow-hidden mt-8 relative">
       {/* Background decoration */}
       <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
         <HelpCircle className="w-48 h-48" />
       </div>
       
       <div className="relative p-8">
          <div className="flex justify-between items-center mb-6">
             <h3 className="text-xl font-bold flex items-center gap-2"><Target className="w-6 h-6 text-blue-300" /> Uji Kemampuanmu</h3>
             <span className="text-sm font-medium bg-white/20 px-3 py-1 rounded-full">
               Soal {currentIdx + 1} / {QUIZ_EXAMPLES.length}
             </span>
          </div>

          <div className="bg-white/10 rounded-xl p-5 mb-6 backdrop-blur-sm border border-white/10">
            <span className="text-xs font-semibold text-blue-200 uppercase tracking-wider mb-2 block">
              {currentExample.type}
            </span>
            <p className="font-mono text-sm leading-relaxed whitespace-pre-wrap">
              {getHighlightedText(currentExample.content, currentExample.highlights, feedback !== null)}
            </p>
          </div>

          {!feedback ? (
            <div className="flex flex-col sm:flex-row gap-3 sm:gap-4">
               <button 
                 onClick={() => handleGuess(true)}
                 disabled={isLoading}
                 className="flex-1 flex items-center justify-center gap-2 bg-green-500 hover:bg-green-600 active:bg-green-700 text-white py-3 px-4 rounded-xl font-medium transition-colors disabled:opacity-50"
               >
                 <ShieldCheck className="w-5 h-5" /> Aman
               </button>
               <button 
                 onClick={() => handleGuess(false)}
                 disabled={isLoading}
                 className="flex-1 flex items-center justify-center gap-2 bg-[var(--color-danger)] hover:bg-red-600 active:bg-red-700 text-white py-3 px-4 rounded-xl font-medium transition-colors disabled:opacity-50"
               >
                 <ShieldAlert className="w-5 h-5" /> Berbahaya
               </button>
            </div>
          ) : (
            <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
               <div className={`rounded-xl p-5 border mb-4 text-sm leading-relaxed ${userCorrect ? 'bg-green-900/40 border-green-500/50' : 'bg-red-900/40 border-red-500/50'}`}>
                 <div className="flex items-center gap-2 mb-2 font-bold text-lg">
                   {userCorrect ? (
                     <><CheckCircle2 className="w-6 h-6 text-green-400" /> <span className="text-green-400">Tebakanmu Benar!</span></>
                   ) : (
                     <><XCircle className="w-6 h-6 text-red-400" /> <span className="text-red-400">Ups, Kurang Tepat!</span></>
                   )}
                 </div>
                 <div className="text-gray-100">
                   {feedback}
                 </div>
               </div>
               <button 
                 onClick={nextQuestion}
                 className="w-full flex items-center justify-center gap-2 bg-white text-[var(--color-navy)] hover:bg-gray-100 py-3 px-4 rounded-xl font-bold transition-colors"
               >
                 {currentIdx === QUIZ_EXAMPLES.length - 1 ? 'Lihat Nilai Akhir' : 'Lanjut'} <ChevronRight className="w-5 h-5" />
               </button>
            </div>
          )}
          
          {isLoading && (
            <p className="text-center text-sm text-blue-200 mt-4 animate-pulse">
              CyberSensei sedang mengevaluasi analisismu...
            </p>
          )}
       </div>
    </div>
  );
}
