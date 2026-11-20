import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  private handleReload = () => {
    window.location.reload();
  };

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-[300px] items-center justify-center p-6">
          <div className="rn2-card w-full max-w-lg overflow-hidden border-[#f9b8c4]">
            <div className="rn2-card-head">
              <div className="flex min-w-0 items-center gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[10px] border border-rose-400/45 bg-rose-500/20 text-rose-200">
                  <AlertTriangle className="h-4.5 w-4.5" aria-hidden="true" />
                </div>
                <div className="min-w-0">
                  <span className="rn2-eyebrow block text-[10px] text-[#54c7ff]">RENDER RECOVERY</span>
                  <h3 className="mt-0.5 text-base font-bold text-white">
                    {this.props.fallbackTitle || '界面渲染遇到问题'}
                  </h3>
                </div>
              </div>
            </div>
            <div className="p-5 sm:p-6">
              <p className="wrap-break-word rounded-xl border border-[#f9b8c4] bg-[#ffeef1]/70 p-3.5 text-left font-mono text-xs leading-relaxed text-[#9f1239]">
                {this.state.error?.message || '组件渲染发生未预期异常'}
              </p>
              <div className="mt-5 flex flex-wrap items-center justify-end gap-2.5">
                <button
                  type="button"
                  onClick={this.handleReset}
                  className="rn2-btn rn2-btn-ghost"
                >
                  重试加载
                </button>
                <button
                  type="button"
                  onClick={this.handleReload}
                  className="rn2-btn rn2-btn-blue"
                >
                  <RefreshCw className="h-4 w-4" aria-hidden="true" />
                  <span>刷新整页</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
