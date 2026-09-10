import React, { useEffect, useRef } from 'react';
import { AlertTriangle, LoaderCircle } from 'lucide-react';

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  tone?: 'danger' | 'primary';
  isSubmitting?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/** A keyboard-accessible replacement for browser confirm() in security flows. */
export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open,
  title,
  description,
  confirmLabel,
  tone = 'danger',
  isSubmitting = false,
  onConfirm,
  onCancel,
}) => {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);

  useEffect(() => {
    if (!open) return;
    cancelRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !isSubmitting) {
        onCancel();
        return;
      }
      if (event.key !== 'Tab') return;
      const focusable = dialogRef.current?.querySelectorAll<HTMLElement>('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled])');
      if (!focusable?.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, isSubmitting, onCancel]);

  if (!open) return null;

  const confirmClasses = tone === 'danger'
    ? 'border-rose-500/60 bg-rose-950 text-rose-100 hover:bg-rose-900'
    : 'border-sky-500/60 bg-sky-950 text-sky-100 hover:bg-sky-900';

  return (
    <div className="fixed inset-0 z-[60] flex items-end bg-slate-950/80 p-4 backdrop-blur-sm sm:items-center sm:justify-center" role="presentation">
      <button
        type="button"
        className="absolute inset-0 cursor-default"
        aria-label="关闭确认对话框"
        disabled={isSubmitting}
        onClick={onCancel}
      />
      <section
        ref={dialogRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-description"
        className="relative w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-5 shadow-2xl"
      >
        <div className="flex gap-3">
          <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${tone === 'danger' ? 'border-rose-500/40 bg-rose-950/70 text-rose-300' : 'border-sky-500/40 bg-sky-950/70 text-sky-300'}`}>
            <AlertTriangle className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <h2 id="confirm-dialog-title" className="text-base font-semibold text-slate-100">{title}</h2>
            <p id="confirm-dialog-description" className="mt-2 text-sm leading-6 text-slate-300">{description}</p>
          </div>
        </div>
        <div className="mt-5 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <button ref={cancelRef} type="button" disabled={isSubmitting} onClick={onCancel} className="min-h-11 rounded-lg border border-slate-700 bg-slate-800 px-4 text-sm font-medium text-slate-200 transition-colors hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-sky-400 disabled:opacity-50">
            取消
          </button>
          <button type="button" disabled={isSubmitting} onClick={onConfirm} className={`min-h-11 rounded-lg border px-4 text-sm font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-sky-400 disabled:opacity-50 ${confirmClasses}`}>
            {isSubmitting && <LoaderCircle className="mr-2 inline h-4 w-4 animate-spin" aria-hidden="true" />}
            {isSubmitting ? '处理中…' : confirmLabel}
          </button>
        </div>
      </section>
    </div>
  );
};
