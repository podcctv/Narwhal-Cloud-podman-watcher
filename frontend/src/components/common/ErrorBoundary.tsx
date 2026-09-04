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
        <div className="min-h-[300px] flex items-center justify-center p-6">
          <div className="max-w-lg w-full rounded-2xl border border-rose-500/30 bg-slate-900/95 p-6 shadow-2xl backdrop-blur-sm text-center">
            <div className="mx-auto w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 mb-4">
              <AlertTriangle className="h-6 w-6" />
            </div>
            <h3 className="text-base font-bold text-slate-100">
              {this.props.fallbackTitle || '界面渲染遇到问题'}
            </h3>
            <p className="mt-2 text-xs text-slate-400 leading-relaxed break-words font-mono bg-slate-950/80 p-3 rounded-lg border border-slate-800 text-left">
              {this.state.error?.message || '组件渲染发生未预期异常'}
            </p>
            <div className="mt-5 flex items-center justify-center gap-3">
              <button
                type="button"
                onClick={this.handleReset}
                className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-750 transition-colors"
              >
                重试加载
              </button>
              <button
                type="button"
                onClick={this.handleReload}
                className="flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-950/80 px-4 py-2 text-xs font-semibold text-sky-300 hover:bg-sky-900 transition-colors"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                <span>刷新整页</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
