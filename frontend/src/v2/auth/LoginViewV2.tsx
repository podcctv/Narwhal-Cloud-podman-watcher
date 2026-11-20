import React, { useState } from 'react';
import { Activity, ArrowRight, Eye, EyeOff, LockKeyhole, Server, ShieldCheck } from 'lucide-react';

const PLATFORM_HIGHLIGHTS = [
  {
    Icon: Server,
    label: '主机与容器',
    text: '资源、流量与服务状态实时核验',
    tag: 'LIVE',
  },
  {
    Icon: ShieldCheck,
    label: '安全与告警',
    text: '风险发现、受控保护与事件追踪',
    tag: 'GUARD',
  },
  {
    Icon: Activity,
    label: '集中运维',
    text: '诊断、排查、防火墙与操作审计',
    tag: 'OPS',
  },
] as const;

export const LoginViewV2: React.FC = () => {
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
      let result: { detail?: string; next?: string } = {};
      try {
        result = await response.json();
      } catch {
        if (!response.ok) {
          setError('暂时无法登录，请稍后重试');
          return;
        }
        throw new Error('invalid login response');
      }
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
    'mt-2 block min-h-12 w-full min-w-0 rounded-xl border border-[#cedae7] bg-[#f4f8fd] px-4 text-base text-[#0b1636] placeholder:text-[#697b9c] transition-colors hover:border-[#087bff]/60 focus:border-[#087bff] focus:bg-white focus:outline-hidden focus:ring-3 focus:ring-[#087bff]/20 disabled:cursor-not-allowed disabled:opacity-60';

  return (
    <main className="flex min-h-dvh items-center justify-center bg-[#02182f] bg-[radial-gradient(ellipse_at_50%_45%,#073365_0%,#031d3d_65%,#02182f_100%)] px-4 py-6 font-sans text-slate-100 sm:px-8 sm:py-12">
      <div className="w-full max-w-5xl min-w-0">
        <div className="mb-8 flex items-center gap-3.5 sm:mb-12">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-[#54c7ff]/55 bg-gradient-to-br from-[#073365] to-[#031d3d] font-mono text-base font-extrabold text-[#00b6ec] shadow-[0_0_22px_-4px_rgba(0,182,236,0.45)]">
            NW
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-lg font-bold tracking-tight text-slate-50">Narwhal Monitor</p>
              <span className="rounded-md border border-[#54c7ff]/45 bg-[#073365]/75 px-1.5 py-0.5 font-mono text-[10px] font-bold tracking-wider text-[#54c7ff]">
                2.0
              </span>
            </div>
            <p className="mt-0.5 text-xs text-slate-300">云原生监控与安全运维</p>
          </div>
        </div>

        <div className="grid items-center gap-10 lg:grid-cols-[minmax(0,1fr)_430px] lg:gap-12 xl:gap-16">
          <section className="hidden min-w-0 lg:block" aria-label="控制台简介">
            <span className="inline-flex items-center gap-2 rounded-full border border-[#54c7ff]/35 bg-[#073365]/65 px-3 py-1 font-mono text-[11px] font-bold tracking-[0.14em] uppercase text-[#54c7ff]">
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

            <div className="mt-8 overflow-hidden rounded-[14px] border border-[#cedae7] bg-white text-[#0b1636] shadow-[0_14px_34px_rgba(1,10,22,0.45)]">
              <div className="flex items-center justify-between border-b border-[#0f3459] bg-[linear-gradient(125deg,#163957,#0e233c_58%,#0c1c30)] px-4 py-3 text-[#e6f4ff]">
                <span className="font-mono text-[11px] font-bold tracking-[0.14em] uppercase text-[#54c7ff]">
                  PLATFORM CAPABILITIES
                </span>
                <span className="font-mono text-[11px] font-semibold text-[#cde8ff]">
                  24/7 TELEMETRY
                </span>
              </div>
              <div className="divide-y divide-[#d2dfec]">
                {PLATFORM_HIGHLIGHTS.map(({ Icon, label, text, tag }) => (
                  <div
                    key={label}
                    className="flex items-center justify-between gap-4 border-[#d2dfec] bg-[#f4f8fd] px-4 py-3.5 text-[#0b1636]"
                  >
                    <div className="flex min-w-0 items-center gap-3.5">
                      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[#d2dfec] bg-white text-[#087bff]">
                        <Icon aria-hidden="true" className="h-4.5 w-4.5" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-bold text-[#0b1636]">{label}</p>
                        <p className="mt-0.5 text-xs text-[#506483]">{text}</p>
                      </div>
                    </div>
                    <span className="shrink-0 rounded-md border border-[#d2dfec] bg-white px-2 py-0.5 font-mono text-[10px] font-bold tracking-wider text-[#08458c]">
                      {tag}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </section>

          <section
            className="w-full min-w-0 overflow-hidden rounded-[14px] border border-[#cedae7] bg-white text-[#0b1636] shadow-[0_20px_50px_rgba(1,10,22,0.55)]"
            aria-labelledby="login-title"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#0f3459] bg-[linear-gradient(125deg,#163957,#0e233c_58%,#0c1c30)] px-5 py-3 text-[#e6f4ff] sm:px-6">
              <span className="font-mono text-[11px] font-bold tracking-[0.14em] uppercase text-[#54c7ff]">
                CONSOLE ACCESS · 2.0
              </span>
              <span className="font-mono text-[11px] font-semibold text-[#cde8ff]">
                TLS / SESSION
              </span>
            </div>

            <div className="p-5 sm:p-8">
              <div className="mb-5 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-[#d2dfec] bg-[#f4f8fd] text-[#087bff]">
                <LockKeyhole aria-hidden="true" className="h-5 w-5" />
              </div>
              <h2 id="login-title" className="text-2xl font-bold tracking-tight text-[#0b1636]">
                登录监控控制台
              </h2>
              <p className="mt-2 text-sm leading-6 text-[#506483]">
                使用现有账号，继续管理你的基础设施。
              </p>

              <form onSubmit={submit} className="mt-6 space-y-5" aria-busy={busy}>
                <div>
                  <label htmlFor="login-username" className="block text-sm font-semibold text-[#0b1636]">
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
                  <label htmlFor="login-password" className="block text-sm font-semibold text-[#0b1636]">
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
                      className="absolute right-1.5 top-2.5 flex h-11 w-11 items-center justify-center rounded-lg text-[#506483] transition-colors hover:bg-[#e8f1fc] hover:text-[#087bff] focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff]"
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
                  id="login-error"
                  role="alert"
                  aria-live="polite"
                  className={
                    error
                      ? 'rounded-xl border border-rose-300 bg-rose-50 px-3.5 py-2.5 text-sm font-medium leading-6 text-rose-700'
                      : 'min-h-6 text-sm leading-6'
                  }
                >
                  {error}
                </div>

                <button
                  type="submit"
                  disabled={busy}
                  className="inline-flex min-h-12 w-full cursor-pointer items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-[#ff6b00] to-[#ff8100] px-4 text-base font-bold text-white shadow-[0_6px_18px_-4px_rgba(255,107,0,0.5)] transition-all hover:from-[#e05b00] hover:to-[#ff6b00] focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff] focus-visible:ring-offset-2 disabled:cursor-wait disabled:opacity-65"
                >
                  <span>{busy ? '正在登录…' : '登录控制台'}</span>
                  <ArrowRight aria-hidden="true" className="h-4 w-4" />
                </button>
              </form>

              <p className="mt-7 border-t border-[#d2dfec] pt-5 text-xs leading-6 text-[#697b9c]">
                登录会话最长保留 12 小时。退出登录或服务重启后，需要重新验证身份。
              </p>
            </div>
          </section>
        </div>

        <footer className="mt-10 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400 sm:mt-14">
          <span>独角鲸 · Narwhal Monitor</span>
          <span className="break-all font-mono text-slate-300">{window.location.hostname}</span>
        </footer>
      </div>
    </main>
  );
};
