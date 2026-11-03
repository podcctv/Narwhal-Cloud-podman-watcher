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
    <div
      aria-live="polite"
      className="pointer-events-none fixed right-3 bottom-4 left-3 z-50 flex flex-col gap-2 sm:right-5 sm:bottom-5 sm:left-auto sm:w-full sm:max-w-sm"
    >
      {toasts.map((toast) => {
        const isSuccess = toast.type === 'success';
        const isError = toast.type === 'error';

        return (
          <div
            key={toast.id}
            role={isError ? 'alert' : 'status'}
            aria-atomic="true"
            className={`pointer-events-auto flex items-start gap-3 rounded-xl border p-3.5 shadow-2xl backdrop-blur-md transition-all animate-in fade-in slide-in-from-bottom-5 duration-200 ${
              isSuccess
                ? 'border-emerald-500/45 bg-emerald-950/95 text-emerald-100 shadow-emerald-950/50'
                : isError
                ? 'border-rose-500/45 bg-rose-950/95 text-rose-100 shadow-rose-950/50'
                : 'border-sky-500/45 bg-sky-950/95 text-sky-100 shadow-sky-950/50'
            }`}
          >
            {isSuccess && <CheckCircle className="mt-0.5 h-5 w-5 shrink-0 text-emerald-400" />}
            {isError && <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" />}
            {!isSuccess && !isError && <Info className="mt-0.5 h-5 w-5 shrink-0 text-sky-400" />}

            <div className="min-w-0 flex-1 wrap-break-word text-sm font-medium leading-5">{toast.message}</div>

            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              aria-label={`关闭提示：${toast.message}`}
              className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-slate-800/70 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-300"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
