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
    'ui-input mt-2 min-h-12 rounded-xl px-4 text-base disabled:opacity-60';

  return (
    <main className="flex min-h-dvh items-center justify-center bg-[#02182f] bg-[radial-gradient(ellipse_80%_50%_at_50%_-10%,rgba(7,51,101,0.75),rgba(3,29,61,0.35)_50%,transparent_80%)] px-4 py-8 font-sans text-slate-100 sm:px-8 sm:py-12">
      <div className="w-full max-w-5xl">
        <div className="mb-8 flex items-center gap-3.5 sm:mb-14">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-[#00b6ec]/55 bg-gradient-to-br from-[#073365] to-[#031d3d] font-mono text-base font-extrabold text-[#00b6ec] shadow-glow">
            NW
          </div>
          <div>
            <p className="text-lg font-bold tracking-tight text-slate-50">Narwhal Monitor</p>
            <p className="mt-0.5 text-xs text-slate-400">云原生监控与安全运维</p>
          </div>
        </div>

        <div className="grid items-center gap-10 lg:grid-cols-[1fr_430px] lg:gap-16">
          <section className="hidden lg:block" aria-label="控制台简介">
            <span className="rn-eyebrow inline-flex items-center gap-2 rounded-full border border-[#54c7ff]/30 bg-[#073365]/60 px-3 py-1">
              <span className="h-1.5 w-1.5 rounded-full bg-[#00b6ec]" aria-hidden="true" />
              YOUR INFRASTRUCTURE, IN VIEW
            </span>
            <h1 className="mt-5 text-4xl font-extrabold leading-snug tracking-tight text-slate-50">
              运行状态，一目了然。
              <br />
              <span className="text-[#54c7ff]">安全运维，从这里开始。</span>
            </h1>
            <p className="mt-4 max-w-md text-sm leading-7 text-slate-300">
              统一查看主机与容器状态，追踪告警，
              <br />
              在一个控制台里完成日常排查与运维。
            </p>
            <div className="rn-spec-card mt-8">
              <div className="rn-spec-card-head">
                <span className="rn-eyebrow">PLATFORM CAPABILITIES</span>
                <span className="font-mono text-[11px] font-semibold text-slate-400">24/7 TELEMETRY</span>
              </div>
              <div className="divide-y divide-[#54c7ff]/15">
                {[
                  { Icon: Server, label: '主机与容器', text: '资源、流量与服务状态实时核验', tag: 'LIVE' },
                  { Icon: ShieldCheck, label: '安全与告警', text: '风险发现、受控保护与事件追踪', tag: 'GUARD' },
                  { Icon: Activity, label: '集中运维', text: '诊断、排查、防火墙与操作审计', tag: 'OPS' },
                ].map(({ Icon, label, text, tag }) => (
                  <div
                    key={label}
                    className="flex items-center justify-between gap-4 bg-[#02182f]/70 px-4 py-3.5"
                  >
                    <div className="flex items-center gap-3.5">
                      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[#54c7ff]/30 bg-[#073365]/70 text-[#00b6ec]">
                        <Icon aria-hidden="true" className="h-4.5 w-4.5" />
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-slate-100">{label}</p>
                        <p className="mt-0.5 text-xs text-slate-400">{text}</p>
                      </div>
                    </div>
                    <span className="rounded border border-[#54c7ff]/25 bg-[#031d3d] px-2 py-0.5 font-mono text-[10px] font-bold tracking-wider text-[#54c7ff]">
                      {tag}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </section>

          <section
            className="rn-spec-card w-full bg-gradient-to-b from-[#073365] via-[#031d3d] to-[#02182f] shadow-2xl shadow-black/50"
            aria-labelledby="login-title"
          >
            <div className="rn-spec-card-head">
              <span className="rn-eyebrow">CONSOLE ACCESS</span>
              <span className="font-mono text-[11px] font-semibold text-[#54c7ff]">TLS / SESSION</span>
            </div>
            <div className="p-6 sm:p-8">
              <div className="mb-5 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-[#00b6ec]/40 bg-[#073365]/70 shadow-glow">
                <LockKeyhole aria-hidden="true" className="h-5 w-5 text-[#00b6ec]" />
              </div>
              <h2 id="login-title" className="text-2xl font-bold tracking-tight text-slate-50">
                登录监控控制台
              </h2>
              <p className="mt-2 text-sm leading-6 text-slate-300">
                使用现有账号，继续管理你的基础设施。
              </p>
              <form onSubmit={submit} className="mt-7 space-y-5" aria-busy={busy}>
                <div>
                  <label htmlFor="login-username" className="text-sm font-semibold text-slate-200">
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
                  <label htmlFor="login-password" className="text-sm font-semibold text-slate-200">
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
                      className="absolute right-1.5 top-2.5 flex h-11 w-11 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-[#073365]/70 hover:text-[#54c7ff] focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#54c7ff]"
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
                  className="ui-btn ui-btn-primary min-h-11 w-full rounded-xl px-4 text-base font-bold disabled:cursor-wait"
                >
                  <span>{busy ? '正在登录…' : '登录控制台'}</span>
                  <ArrowRight aria-hidden="true" className="h-4 w-4" />
                </button>
              </form>
              <p className="mt-7 border-t border-[#54c7ff]/15 pt-5 text-xs leading-6 text-slate-400">
                登录会话最长保留 12 小时。退出登录或服务重启后，需要重新验证身份。
              </p>
            </div>
          </section>
        </div>
        <footer className="mt-10 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500 sm:mt-14">
          <span>独角鲸 · Narwhal Monitor</span>
          <span className="break-all font-mono text-slate-400">{window.location.hostname}</span>
        </footer>
      </div>
    </main>
  );
};
