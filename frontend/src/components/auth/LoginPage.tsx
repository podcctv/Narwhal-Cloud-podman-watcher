import React, { useState } from 'react';
import { Activity, ArrowRight, Eye, EyeOff, LockKeyhole, Server, ShieldCheck } from 'lucide-react';

export const LoginPage: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setError('');
    setBusy(true);
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        credentials: 'same-origin',
        signal: controller.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password,
          next: new URLSearchParams(window.location.search).get('next') || '/',
        }),
      });
      const result = await response.json();
      if (!response.ok) {
        setError(result.detail || '暂时无法登录，请稍后重试');
        return;
      }
      // A server-validated local destination; never navigate to another origin.
      const target = new URL(result.next || '/', window.location.origin);
      window.location.replace(target.origin === window.location.origin ? target.href : '/');
    } catch {
      setError('连接未成功，请检查网络后重试');
    } finally {
      window.clearTimeout(timeout);
      setBusy(false);
    }
  };

  const inputClass =
    'mt-2 min-h-12 w-full rounded-xl border border-slate-700/90 bg-slate-950/90 px-4 text-base text-slate-100 placeholder:text-slate-500 transition-colors hover:border-slate-600 focus:border-sky-400 focus:outline-hidden focus:ring-2 focus:ring-sky-400/30 disabled:opacity-60';

  return (
    <main className="flex min-h-dvh items-center justify-center bg-slate-950 px-4 py-8 font-sans text-slate-100 sm:px-8 sm:py-12">
      <div className="w-full max-w-5xl">
        <div className="mb-8 flex items-center gap-3.5 sm:mb-14">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-sky-400/40 bg-sky-950/70 font-mono text-base font-extrabold text-sky-300 shadow-glow">
            NW
          </div>
          <div>
            <p className="text-lg font-semibold tracking-tight text-slate-100">Narwhal Monitor</p>
            <p className="mt-0.5 text-xs text-slate-400">云原生监控与安全运维</p>
          </div>
        </div>

        <div className="grid items-center gap-10 lg:grid-cols-[1fr_430px] lg:gap-20">
          <section className="hidden lg:block" aria-label="控制台简介">
            <p className="mb-4 font-mono text-xs font-semibold tracking-[0.18em] text-sky-400">
              YOUR INFRASTRUCTURE, IN VIEW
            </p>
            <h1 className="text-4xl font-semibold leading-snug tracking-tight text-slate-50">
              运行状态，一目了然。
              <br />
              <span className="text-slate-400">安全运维，从这里开始。</span>
            </h1>
            <p className="mt-5 max-w-md text-sm leading-7 text-slate-300">
              统一查看主机与容器状态，追踪告警，
              <br />
              在一个控制台里完成日常排查与运维。
            </p>
            <div className="mt-9 grid gap-4 border-t border-slate-800/90 pt-7">
              {[
                { Icon: Server, label: '主机与容器', text: '资源、流量与服务状态实时核验' },
                { Icon: ShieldCheck, label: '安全与告警', text: '风险发现、受控保护与事件追踪' },
                { Icon: Activity, label: '集中运维', text: '诊断、排查、防火墙与操作审计' },
              ].map(({ Icon, label, text }) => (
                <div
                  key={label}
                  className="flex items-center gap-4 rounded-xl border border-slate-800/70 bg-slate-900/40 px-4 py-3"
                >
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-sky-500/25 bg-sky-950/50 text-sky-400">
                    <Icon aria-hidden="true" className="h-4.5 w-4.5" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-slate-100">{label}</p>
                    <p className="mt-0.5 text-xs text-slate-400">{text}</p>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section
            className="ui-surface-card w-full p-6 shadow-2xl shadow-black/40 sm:p-9"
            aria-labelledby="login-title"
          >
            <div className="mb-5 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-sky-500/25 bg-sky-500/10">
              <LockKeyhole aria-hidden="true" className="h-5 w-5 text-sky-400" />
            </div>
            <h2 id="login-title" className="text-2xl font-semibold tracking-tight text-slate-100">
              登录监控控制台
            </h2>
            <p className="mt-2 text-sm leading-6 text-slate-400">
              使用现有账号，继续管理你的基础设施。
            </p>
            <form onSubmit={submit} className="mt-7 space-y-5" aria-busy={busy}>
              <div>
                <label htmlFor="login-username" className="text-sm font-medium text-slate-200">
                  用户名
                </label>
                <input
                  id="login-username"
                  name="username"
                  autoComplete="username"
                  autoCapitalize="none"
                  spellCheck={false}
                  autoFocus
                  required
                  maxLength={128}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={busy}
                  className={inputClass}
                  placeholder="请输入用户名"
                />
              </div>
              <div>
                <label htmlFor="login-password" className="text-sm font-medium text-slate-200">
                  密码
                </label>
                <div className="relative">
                  <input
                    id="login-password"
                    name="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    required
                    maxLength={4096}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={busy}
                    className={`${inputClass} pr-14`}
                    placeholder="请输入密码"
                    aria-describedby={error ? 'login-error' : undefined}
                    aria-invalid={Boolean(error)}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    disabled={busy}
                    aria-label={showPassword ? '隐藏密码' : '显示密码'}
                    aria-pressed={showPassword}
                    className="absolute right-1.5 top-2.5 flex h-11 w-11 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-slate-800/70 hover:text-slate-100 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-sky-400"
                  >
                    {showPassword ? (
                      <EyeOff aria-hidden="true" className="h-5 w-5" />
                    ) : (
                      <Eye aria-hidden="true" className="h-5 w-5" />
                    )}
                  </button>
                </div>
              </div>
              <div
                className="min-h-6 text-sm leading-6 text-rose-300"
                id="login-error"
                role="alert"
                aria-live="polite"
              >
                {error}
              </div>
              <button
                type="submit"
                disabled={busy}
                className="flex min-h-12 w-full items-center justify-center gap-2 rounded-xl bg-sky-400 px-4 font-semibold text-slate-950 shadow-sm transition-colors hover:bg-sky-300 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-sky-300 focus-visible:ring-offset-4 focus-visible:ring-offset-slate-900 disabled:cursor-wait disabled:opacity-60"
              >
                <span>{busy ? '正在登录…' : '登录控制台'}</span>
                <ArrowRight aria-hidden="true" className="h-4 w-4" />
              </button>
            </form>
            <p className="mt-7 border-t border-slate-800/90 pt-5 text-xs leading-6 text-slate-400">
              登录会话最长保留 12 小时。退出登录或服务重启后，需要重新验证身份。
            </p>
          </section>
        </div>
        <footer className="mt-10 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500 sm:mt-14">
          <span>独角鲸 · Narwhal Monitor</span>
          <span className="break-all font-mono">{window.location.hostname}</span>
        </footer>
      </div>
    </main>
  );
};
