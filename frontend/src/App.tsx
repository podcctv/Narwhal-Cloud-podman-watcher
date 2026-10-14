import React, { lazy, Suspense } from 'react';
import { LoginPage } from './components/auth/LoginPage';

// Login does not load charts, run dashboard polling, or fetch protected data.
const Dashboard = lazy(() => import('./Dashboard').then(module => ({ default: module.Dashboard })));
const TcpingPage = lazy(() => import('./components/tcping/TcpingPage').then(module => ({ default: module.TcpingPage })));
const TcpingManage = lazy(() => import('./components/tcping/TcpingManage').then(module => ({ default: module.TcpingManage })));

export const App: React.FC = () => window.location.pathname === '/login'
  ? <LoginPage />
  : <Suspense fallback={<main className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-300" role="status">正在载入页面…</main>}>
      {window.location.pathname === '/tcping' ? <TcpingPage /> : window.location.pathname === '/tcping/manage' ? <TcpingManage /> : <Dashboard />}
    </Suspense>;
