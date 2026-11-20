import React, { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
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
  children?: React.ReactNode;
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
  children,
}) => {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const onCancelRef = useRef(onCancel);
  const isSubmittingRef = useRef(isSubmitting);
  onCancelRef.current = onCancel;
  isSubmittingRef.current = isSubmitting;

  useEffect(() => {
    if (!open) return;
    const previousFocus = document.activeElement as HTMLElement | null;
    cancelRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !isSubmittingRef.current) {
        onCancelRef.current();
        return;
      }
      if (event.key !== 'Tab') return;
      const focusable = dialogRef.current?.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled])'
      );
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
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      if (previousFocus?.isConnected) previousFocus.focus();
    };
  }, [open]);

  if (!open) return null;

  const confirmClasses = tone === 'danger'
    ? 'border-[#b91c1c] bg-linear-to-r from-[#dc2626] to-[#be123c] text-white shadow-[0_4px_12px_rgba(220,38,38,0.28)] hover:from-[#b91c1c] hover:to-[#9f1239] focus-visible:ring-[#dc2626]'
    : 'border-[#ea5e00] bg-linear-to-r from-[#ff6b00] to-[#ff8100] text-white shadow-[0_4px_12px_rgba(255,107,0,0.32)] hover:from-[#e05b00] hover:to-[#f06e00] focus-visible:ring-[#ff6b00]';

  return createPortal(
    <div
      className="fixed inset-0 z-200 flex items-end bg-[#02182f]/68 p-3 backdrop-blur-xs sm:items-center sm:justify-center sm:p-4"
      role="presentation"
    >
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
        className="relative max-h-[90dvh] w-full max-w-md overflow-y-auto rounded-[14px] border border-[#cedae7] bg-white text-[#0b1636] shadow-[0_24px_60px_rgba(3,24,46,0.38)]"
      >
        <div className={`rn2-card-head ${tone === 'primary' ? 'rn2-card-head-blue' : ''}`}>
          <div className="flex min-w-0 items-center gap-3">
            <div
              className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-[10px] border ${
                tone === 'danger'
                  ? 'border-rose-400/45 bg-rose-500/20 text-rose-200'
                  : 'border-[#54c7ff]/45 bg-[#087bff]/25 text-[#b8e6ff]'
              }`}
            >
              <AlertTriangle className="h-4.5 w-4.5" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <span className="rn2-eyebrow block text-[10px] text-[#54c7ff]">
                {tone === 'danger' ? 'CRITICAL CONFIRMATION' : 'ACTION CONFIRMATION'}
              </span>
              <h2 id="confirm-dialog-title" className="mt-0.5 text-base font-bold leading-snug text-white">
                {title}
              </h2>
            </div>
          </div>
        </div>

        <div className="p-5">
          <p id="confirm-dialog-description" className="wrap-break-word text-sm leading-6 text-[#31485e]">
            {description}
          </p>
          {children}
          <div className="mt-5 flex flex-col-reverse gap-2.5 border-t border-[#dce5ef] pt-4 sm:flex-row sm:justify-end">
            <button
              ref={cancelRef}
              type="button"
              disabled={isSubmitting}
              onClick={onCancel}
              className="min-h-11 rounded-[10px] border border-[#cedae7] bg-white px-4 text-sm font-semibold text-[#0b1636] transition-colors hover:border-[#087bff] hover:bg-[#f4f8fd] hover:text-[#08458c] focus:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff] disabled:opacity-50"
            >
              取消
            </button>
            <button
              type="button"
              disabled={isSubmitting}
              onClick={onConfirm}
              className={`inline-flex min-h-11 items-center justify-center rounded-[10px] border px-4 text-sm font-bold transition-colors focus:outline-hidden focus-visible:ring-2 disabled:opacity-50 ${confirmClasses}`}
            >
              {isSubmitting && <LoaderCircle className="mr-2 inline h-4 w-4 animate-spin" aria-hidden="true" />}
              {isSubmitting ? '处理中…' : confirmLabel}
            </button>
          </div>
        </div>
      </section>
    </div>,
    document.body
  );
};
