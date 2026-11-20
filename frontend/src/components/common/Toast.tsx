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
      className="pointer-events-none fixed right-3 bottom-4 left-3 z-[180] flex flex-col gap-2.5 sm:right-5 sm:bottom-5 sm:left-auto sm:w-full sm:max-w-sm"
    >
      {toasts.map((toast) => {
        const isSuccess = toast.type === 'success';
        const isError = toast.type === 'error';

        const frameClass = isSuccess
          ? 'border-[#9de2d8] border-l-4 border-l-[#147468] bg-white text-[#0b1636]'
          : isError
          ? 'border-[#f9b8c4] border-l-4 border-l-[#dc2626] bg-white text-[#0b1636]'
          : 'border-[#a9d1ff] border-l-4 border-l-[#087bff] bg-white text-[#0b1636]';

        const iconChipClass = isSuccess
          ? 'bg-[#e6f7f4] text-[#147468]'
          : isError
          ? 'bg-[#ffeef1] text-[#b41835]'
          : 'bg-[#e8f3ff] text-[#087bff]';

        return (
          <div
            key={toast.id}
            role={isError ? 'alert' : 'status'}
            aria-atomic="true"
            className={`pointer-events-auto flex items-start gap-3 rounded-xl border p-3.5 shadow-[0_12px_30px_rgba(12,37,65,0.16)] transition-all duration-200 ${frameClass}`}
          >
            <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${iconChipClass}`}>
              {isSuccess && <CheckCircle className="h-4.5 w-4.5" aria-hidden="true" />}
              {isError && <AlertCircle className="h-4.5 w-4.5" aria-hidden="true" />}
              {!isSuccess && !isError && <Info className="h-4.5 w-4.5" aria-hidden="true" />}
            </div>

            <div className="min-w-0 flex-1 pt-0.5 wrap-break-word text-sm font-semibold leading-5 text-[#0b1636]">
              {toast.message}
            </div>

            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              aria-label={`关闭提示：${toast.message}`}
              className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg text-[#697b9c] transition-colors hover:bg-[#f4f8fd] hover:text-[#0b1636] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#087bff]"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
