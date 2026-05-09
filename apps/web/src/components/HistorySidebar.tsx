import { HistoryItem } from '../types';
import { Clock, ShieldCheck, AlertTriangle, ShieldAlert, ChevronRight } from 'lucide-react';

export function HistorySidebar({ history, onSelect }: { history: HistoryItem[], onSelect: (item: HistoryItem) => void }) {
  if (history.length === 0) {
    return null;
  }

  return (
    <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6">
      <div className="flex items-center justify-between mb-5">
        <h3 className="font-bold text-[var(--color-navy)] flex items-center gap-2">
          <Clock className="w-5 h-5 text-gray-400" /> Riwayat Analisis
        </h3>
        <span className="text-xs font-semibold text-gray-400 bg-gray-50 px-2 py-1 rounded-md">{history.length} Terakhir</span>
      </div>
      <div className="space-y-3">
        {history.map((item) => {
          const isSafe = item.result.verdict === 'AMAN';
          const isSuspicious = item.result.verdict === 'MENCURIGAKAN';
          
          let Icon = ShieldAlert;
          let colorClass = 'text-red-600 bg-red-50';
          let textColor = 'text-red-700';
          
          if (isSafe) {
            Icon = ShieldCheck;
            colorClass = 'text-green-600 bg-green-50';
            textColor = 'text-green-700';
          } else if (isSuspicious) {
            Icon = AlertTriangle;
            colorClass = 'text-amber-600 bg-amber-50';
            textColor = 'text-amber-700';
          }

          return (
            <button
              key={item.id}
              onClick={() => onSelect(item)}
              className="w-full text-left p-3.5 rounded-xl hover:bg-gray-50 border border-gray-100 hover:border-gray-200 hover:shadow-sm transition-all flex items-center gap-3 group"
            >
              <div className={`p-2 rounded-lg flex-shrink-0 ${colorClass}`}>
                <Icon className="w-4 h-4" />
              </div>
              <div className="flex-1 overflow-hidden min-w-0">
                <p className="text-sm font-semibold text-gray-900 truncate">
                  {item.input}
                </p>
                <div className="flex items-center gap-2 mt-1">
                  <span className={`text-xs font-bold ${textColor}`}>
                    {item.result.verdict}
                  </span>
                  <span className="text-gray-300 text-xs">&bull;</span>
                  <span className="text-xs text-gray-400 font-medium">
                    {new Date(item.timestamp).toLocaleDateString('id-ID', { day: 'numeric', month: 'short' })}
                  </span>
                </div>
              </div>
              <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-gray-500 flex-shrink-0" />
            </button>
          );
        })}
      </div>
    </div>
  );
}
