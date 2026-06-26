import { useState, useEffect } from 'react';
import IOCInput from './components/IOCInput.jsx';
import ScanningLoader from './components/ScanningLoader.jsx';
import ThreatReport from './components/ThreatReport.jsx';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001';
const HISTORY_KEY = 'threatlens_history';
const THEME_KEY = 'threatlens_theme';

export default function App() {
  const [view, setView] = useState('input');      // 'input' | 'loading' | 'results'
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);     // last 5 IOCs
  const [theme, setTheme] = useState('dark');      // 'dark' | 'light'

  // Load theme preference on mount — defaults to dark, respects saved choice
  useEffect(() => {
    const saved = localStorage.getItem(THEME_KEY);
    const initial = saved === 'light' ? 'light' : 'dark';
    setTheme(initial);
    document.documentElement.setAttribute('data-theme', initial);
  }, []);

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem(THEME_KEY, next);
  };

  // Load history from sessionStorage on mount
  useEffect(() => {
    try {
      const saved = sessionStorage.getItem(HISTORY_KEY);
      if (saved) setHistory(JSON.parse(saved));
    } catch {}
  }, []);

  const saveHistory = (ioc, iocType, riskLevel) => {
    const entry = { ioc, iocType, riskLevel, ts: Date.now() };
    setHistory(prev => {
      const filtered = prev.filter(h => h.ioc !== ioc).slice(0, 4);
      const updated = [entry, ...filtered];
      try { sessionStorage.setItem(HISTORY_KEY, JSON.stringify(updated)); } catch {}
      return updated;
    });
  };

  const handleAnalyze = async (ioc) => {
    setError(null);
    setResult(null);
    setView('loading');

    try {
      const res = await fetch(`${API_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ioc: ioc.trim() })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Analysis failed.');

      setResult(data);
      saveHistory(data.ioc, data.ioc_type, data.risk_level);
      setView('results');
    } catch (err) {
      setError(err.message === 'Failed to fetch'
        ? 'Cannot reach the backend. Make sure it is running on port 3001.'
        : err.message);
      setView('input');
    }
  };

  const handleReset = () => { setView('input'); setResult(null); setError(null); };
  const handleHistoryClick = (ioc) => handleAnalyze(ioc);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Header
        onLogoClick={view !== 'input' ? handleReset : undefined}
        theme={theme}
        onToggleTheme={toggleTheme}
      />
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {view === 'input' && (
          <IOCInput
            onAnalyze={handleAnalyze}
            error={error}
            history={history}
            onHistoryClick={handleHistoryClick}
          />
        )}
        {view === 'loading' && <ScanningLoader />}
        {view === 'results' && result && (
          <ThreatReport data={result} onNewScan={handleReset} />
        )}
      </main>
      <Footer />
    </div>
  );
}

function Header({ onLogoClick, theme, onToggleTheme }) {
  return (
    <header style={{
      display:'flex', alignItems:'center', justifyContent:'space-between',
      padding:'16px 36px', borderBottom:'1px solid var(--border)',
      background:'var(--bg-1)', backdropFilter:'blur(12px)',
      position:'sticky', top:0, zIndex:100
    }}>
      <div
        style={{ display:'flex', alignItems:'center', gap:12, cursor: onLogoClick ? 'pointer' : 'default' }}
        onClick={onLogoClick}
      >
        <div style={{
          width:34, height:34, borderRadius:9, border:'1.5px solid var(--accent)',
          display:'flex', alignItems:'center', justifyContent:'center',
          background:'var(--accent-dim)', fontSize:16
        }}>🔍</div>
        <div>
          <div style={{ fontFamily:'var(--font-display)', fontSize:19, fontWeight:600, letterSpacing:'0.02em', color:'var(--text-0)' }}>ThreatLens</div>
          <div style={{ fontFamily:'var(--font-mono)', fontSize:9, letterSpacing:'0.1em', color:'var(--text-2)' }}>AI THREAT INTELLIGENCE PLATFORM</div>
        </div>
      </div>

      <div style={{ display:'flex', alignItems:'center', gap:18 }}>
        <div style={{ display:'flex', alignItems:'center', gap:8 }}>
          <span style={{ width:7, height:7, borderRadius:'50%', background:'var(--accent)', display:'inline-block', animation:'pulse 2s ease-in-out infinite' }} />
          <span style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--accent)', letterSpacing:'0.08em' }}>LIVE</span>
        </div>

        {/* Theme toggle switch */}
        <button
          className="theme-toggle"
          onClick={onToggleTheme}
          aria-label="Toggle light/dark theme"
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          <span className="knob">{theme === 'dark' ? '🌙' : '☀️'}</span>
        </button>
      </div>
    </header>
  );
}

function Footer() {
  return (
    <footer style={{
      padding:'14px 36px', borderTop:'1px solid var(--border)',
      fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-3)',
      textAlign:'center', letterSpacing:'0.04em'
    }}>
      ThreatLens v1.0 · Powered by Llama 3.3 70B · Sources: AbuseIPDB · VirusTotal · AlienVault OTX · URLhaus · IPInfo · MITRE ATT&CK®
    </footer>
  );
}
