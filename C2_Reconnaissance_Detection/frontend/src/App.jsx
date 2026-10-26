import { useEffect, useState } from 'react';
import { api } from './api.js';
import Overview from './pages/Overview.jsx';
import Replay from './pages/Replay.jsx';
import Compare from './pages/Compare.jsx';
import Validation from './pages/Validation.jsx';
import History from './pages/History.jsx';
import ScoreFile from './pages/ScoreFile.jsx';
import Metrics from './pages/Metrics.jsx';
import Guide from './pages/Guide.jsx';

const PAGES = [
  { id: 'overview', label: 'Overview', el: Overview },
  { id: 'metrics', label: 'Metrics', el: Metrics },
  { id: 'replay', label: 'Traffic replay', el: Replay },
  { id: 'compare', label: 'Compare', el: Compare },
  { id: 'guide', label: 'Walkthrough', el: Guide },
  { id: 'validation', label: 'Data checks', el: Validation },
  { id: 'history', label: 'CIC audit', el: History },
  { id: 'score', label: 'Score a file', el: ScoreFile },
];

function useHashPage() {
  const get = () => (location.hash.slice(1) || 'overview').split('?')[0];
  const [page, setPage] = useState(get);
  useEffect(() => {
    const on = () => setPage(get());
    addEventListener('hashchange', on);
    return () => removeEventListener('hashchange', on);
  }, []);
  return page;
}

function ThemeToggle() {
  const meta = document.querySelector('meta[name="color-scheme"]');
  const [mode, setMode] = useState(meta?.content ?? 'light');
  const next = { 'light dark': 'dark', dark: 'light', light: 'light dark' };
  const label = { 'light dark': 'Theme: system', dark: 'Theme: dark', light: 'Theme: light' };
  return (
    <button
      className="btn ghost small"
      onClick={() => {
        const m = next[mode];
        meta.content = m;
        document.documentElement.style.colorScheme = m;
        try {
          localStorage.setItem('color-scheme', m);
        } catch {}
        setMode(m);
      }}
    >
      {label[mode]}
    </button>
  );
}

export default function App() {
  const page = useHashPage();
  useEffect(() => { window.scrollTo(0, 0); }, [page]);
  const [health, setHealth] = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => {
    api.health().then(setHealth).catch((e) => setErr(e.message));
  }, []);
  const Page = (PAGES.find((p) => p.id === page) ?? PAGES[0]).el;
  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">C2</span>
          <div>
            <div className="brand-title">Modbus Recon</div>
            <div className="brand-sub">J26-CS-318 / Component 2</div>
          </div>
        </div>
        <nav className="nav" aria-label="Dashboard pages">
          {PAGES.map((p) => (
            <a key={p.id} href={`#${p.id}`} aria-current={p.id === page ? 'page' : undefined} className={p.id === page ? 'active' : ''}>
              {p.label}
            </a>
          ))}
        </nav>
        <div className="topbar-right">
          {health && (
            <span className={`status ${health.integrity.missing_or_changed.length ? 'bad' : 'ok'}`}>
              {health.integrity.missing_or_changed.length
                ? `Bundle changed: ${health.integrity.missing_or_changed.length} files`
                : 'Models ready'}
            </span>
          )}
          <ThemeToggle />
        </div>
      </header>
      <main className="main">
        {err ? (
          <div className="panel error">Backend not reachable: {err}. Start it with start_c2_demo.ps1.</div>
        ) : (
          <Page />
        )}
      </main>
      <footer className="app-footer"><span>Recorded Modbus/TCP experiments · research demonstration</span><a href="#guide">Reading this dashboard</a></footer>
    </div>
  );
}
