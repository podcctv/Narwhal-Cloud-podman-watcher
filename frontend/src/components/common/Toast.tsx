import React from 'react';
import { CheckCircle, AlertCircle, Info, X } from 'lucide-react';

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'info';
  message: string;
}

interface ToastContainerProps {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts, onDismiss }) => {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 pointer-events-none max-w-sm w-full">
      {toasts.map((toast) => {
        const isSuccess = toast.type === 'success';
        const isError = toast.type === 'error';

        return (
          <div
            key={toast.id}
            className={`pointer-events-auto flex items-start gap-3 rounded-xl border p-3.5 shadow-2xl transition-all animate-in fade-in slide-in-from-bottom-5 duration-200 ${
              isSuccess
                ? 'border-emerald-500/40 bg-emerald-950/95 text-emerald-100 shadow-emerald-950/50'
                : isError
                ? 'border-rose-500/40 bg-rose-950/95 text-rose-100 shadow-rose-950/50'
                : 'border-sky-500/40 bg-sky-950/95 text-sky-100 shadow-sky-950/50'
            }`}
          >
            {isSuccess && <CheckCircle className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />}
            {isError && <AlertCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />}
            {!isSuccess && !isError && <Info className="h-5 w-5 text-sky-400 shrink-0 mt-0.5" />}

            <div className="flex-1 text-sm font-medium">{toast.message}</div>

            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              className="text-slate-400 hover:text-slate-200 p-0.5 rounded transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
