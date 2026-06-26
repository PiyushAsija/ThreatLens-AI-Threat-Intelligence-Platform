import { useState, useCallback } from 'react';

function detectType(val) {
  const v = val.trim();
  if (!v) return null;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'IP';
  if (/^[a-fA-F0-9]{64}$/.test(v)) return 'SHA256';
  if (/^[a-fA-F0-9]{32}$/.test(v)) return 'MD5';
  if (/^https?:\/\/.+/i.test(v)) return 'URL';
  if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(v)) return 'DOMAIN';
  return null;
}

const RISK_COLORS = {
  Critical: 'var(--critical)',
  Malicious: 'var(--malicious)',
  Suspicious: 'var(--suspicious)',
  Clean: 'var(--clean)',
};

const EXAMPLES = [
  { label: 'Known bad IP', value: '185.220.101.45' },
  { label: 'WannaCry hash', value: '84c82835a5d21bbcf75a61706d8ab549' },
  { label: 'Malware domain', value: 'malware-delivery.ru' },
];

export default function IOCInput({ onAnalyze, error, history, onHistoryClick }) {
  const [value, setValue] = useState('');
  const [iocType, setIocType] = useState(null);

  const handleChange = useCallback((e) => {
    const v = e.target.value;
    setValue(v);
    setIocType(detectType(v));
  }, []);

  const handleSubmit = () => {
    if (value.trim() && iocType) onAnalyze(value.trim());
  };

  const handleKey = (e) => { if (e.key === 'Enter') handleSubmit(); };

  // IOC type badge colors — distinct hues, all cool-toned to match the navy/cobalt brand
  const typeBadgeColor = {
    IP: '#3a63ff', DOMAIN: '#a78bfa', URL: '#f59e0b',
    MD5: '#06b6d4', SHA256: '#06b6d4',
  };

  return (
    <div style={S.page}>
      <div style={S.centerCol}>

        <div style={S.hero}>
          <div style={S.tag}>THREAT INTELLIGENCE PLATFORM</div>
          <h1 style={S.title}>Analyze Any IOC<br />in Seconds</h1>
          <p style={S.sub}>
            Paste an IP address, domain, URL, or file hash. ThreatLens queries
            5 threat intelligence databases simultaneously and uses AI to
            synthesize a single actionable verdict.
          </p>
        </div>

        {error && (
          <div style={S.errorBox}>
            <span style={{ color:'var(--critical)', marginRight:8 }}>⚠</span>{error}
          </div>
        )}

        <div className="card-elevated" style={S.inputCard}>
          <div style={S.inputRow}>
            <div style={S.inputWrap}>
              <input
                style={S.input}
                type="text"
                value={value}
                onChange={handleChange}
                onKeyDown={handleKey}
                placeholder="Enter IP, domain, URL, or file hash..."
                autoFocus
                spellCheck={false}
                autoComplete="off"
              />
              {iocType && (
                <span style={{ ...S.typeBadge, background: typeBadgeColor[iocType] + '20', color: typeBadgeColor[iocType], border: `1px solid ${typeBadgeColor[iocType]}50` }}>
                  {iocType}
                </span>
              )}
            </div>
            <button
              style={{ ...S.analyzeBtn, opacity: (!value.trim() || !iocType) ? 0.45 : 1 }}
              onClick={handleSubmit}
              disabled={!value.trim() || !iocType}
            >
              <span style={{ marginRight:6 }}>▶</span> ANALYZE
            </button>
          </div>

          {!iocType && value.trim() && (
            <p style={S.hint}>Could not detect IOC type. Supported: IPv4, domain, URL, MD5 or SHA256 hash.</p>
          )}

          <div style={S.sourceRow}>
            {['AbuseIPDB','VirusTotal (90 engines)','AlienVault OTX','URLhaus','IPInfo'].map(s => (
              <span key={s} style={S.srcBadge}>{s}</span>
            ))}
          </div>
        </div>

        <div style={S.examplesRow}>
          <span style={S.exLabel}>TRY:</span>
          {EXAMPLES.map(ex => (
            <button key={ex.value} style={S.exBtn} onClick={() => {
              setValue(ex.value);
              setIocType(detectType(ex.value));
            }}>
              {ex.label}
            </button>
          ))}
        </div>

        {history.length > 0 && (
          <div style={S.historySection}>
            <div style={S.historyLabel}>RECENT SEARCHES</div>
            <div style={S.historyChips}>
              {history.map((h, i) => {
                const c = RISK_COLORS[h.riskLevel] || 'var(--text-2)';
                return (
                  <button key={i} style={S.historyChip} onClick={() => onHistoryClick(h.ioc)}>
                    <span style={{ fontFamily:'var(--font-mono)', fontSize:9, color:c, letterSpacing:'0.07em', marginRight:5 }}>{h.iocType?.toUpperCase()}</span>
                    <span style={{ fontSize:12, color:'var(--text-1)', fontFamily:'var(--font-mono)' }}>{h.ioc.length > 28 ? h.ioc.slice(0,26)+'…' : h.ioc}</span>
                    <span style={{ marginLeft:6, fontSize:10, padding:'1px 6px', borderRadius:3, background: c + '20', color: c, border: `1px solid ${c}40`, fontFamily:'var(--font-mono)' }}>{h.riskLevel}</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        <div style={S.statsStrip}>
          {[['5', 'Intelligence Sources'], ['4', 'IOC Types Supported'], ['<5s', 'Avg Response Time'], ['Free', 'Forever']].map(([v, l]) => (
            <div key={l} style={S.statItem}>
              <div style={S.statVal}>{v}</div>
              <div style={S.statLabel}>{l}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

const S = {
  page: { flex:1, display:'flex', alignItems:'center', justifyContent:'center', padding:'48px 24px' },
  centerCol: { width:'100%', maxWidth:680, display:'flex', flexDirection:'column', alignItems:'center', gap:28 },
  hero: { textAlign:'center' },
  tag: { fontFamily:'var(--font-mono)', fontSize:11, letterSpacing:'0.15em', color:'var(--accent)', marginBottom:16 },
  title: { fontFamily:'var(--font-display)', fontSize:50, fontWeight:600, lineHeight:1.1, color:'var(--text-0)', marginBottom:16, letterSpacing:'-0.01em' },
  sub: { fontSize:16, color:'var(--text-2)', lineHeight:1.7, maxWidth:520, margin:'0 auto' },
  errorBox: { width:'100%', padding:'11px 16px', background:'var(--critical-dim)', border:'1px solid var(--critical-border)', borderRadius:8, fontFamily:'var(--font-mono)', fontSize:13, color:'var(--text-1)' },
  inputCard: { width:'100%', background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:12, padding:'26px', position:'relative' },
  inputRow: { display:'flex', gap:10, marginBottom:12 },
  inputWrap: { flex:1, position:'relative', display:'flex', alignItems:'center' },
  input: {
    width:'100%', padding:'14px 90px 14px 16px',
    background:'var(--bg-2)', border:'1px solid var(--border-strong)',
    borderRadius:8, color:'var(--text-0)', fontSize:15,
    fontFamily:'var(--font-mono)', outline:'none',
    letterSpacing:'0.02em',
  },
  typeBadge: { position:'absolute', right:10, fontFamily:'var(--font-mono)', fontSize:10, fontWeight:700, padding:'3px 8px', borderRadius:5, letterSpacing:'0.08em' },
  analyzeBtn: {
    fontFamily:'var(--font-display)', fontSize:15, fontWeight:600, letterSpacing:'0.04em',
    padding:'14px 28px', background:'var(--accent)', border:'none', borderRadius:8,
    color:'#ffffff', cursor:'pointer', whiteSpace:'nowrap', transition:'opacity 0.15s',
  },
  hint: { fontFamily:'var(--font-mono)', fontSize:11, color:'var(--suspicious)', marginBottom:8 },
  sourceRow: { display:'flex', gap:6, flexWrap:'wrap' },
  srcBadge: { fontFamily:'var(--font-mono)', fontSize:10, padding:'3px 9px', background:'var(--bg-2)', border:'1px solid var(--border)', borderRadius:5, color:'var(--text-2)', letterSpacing:'0.04em' },
  examplesRow: { display:'flex', alignItems:'center', gap:8, flexWrap:'wrap' },
  exLabel: { fontFamily:'var(--font-mono)', fontSize:10, color:'var(--text-3)', letterSpacing:'0.1em' },
  exBtn: { fontFamily:'var(--font-mono)', fontSize:11, padding:'5px 12px', background:'transparent', border:'1px solid var(--border)', borderRadius:6, color:'var(--accent)', cursor:'pointer' },
  historySection: { width:'100%' },
  historyLabel: { fontFamily:'var(--font-mono)', fontSize:10, letterSpacing:'0.12em', color:'var(--text-3)', marginBottom:8 },
  historyChips: { display:'flex', flexWrap:'wrap', gap:7 },
  historyChip: { display:'flex', alignItems:'center', padding:'6px 12px', background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:7, cursor:'pointer' },
  statsStrip: { display:'flex', gap:0, borderRadius:10, overflow:'hidden', border:'1px solid var(--border)', width:'100%' },
  statItem: { flex:1, padding:'14px 16px', textAlign:'center', background:'var(--bg-card)', borderRight:'1px solid var(--border)' },
  statVal: { fontFamily:'var(--font-display)', fontSize:24, fontWeight:600, color:'var(--accent)', marginBottom:2 },
  statLabel: { fontFamily:'var(--font-mono)', fontSize:10, color:'var(--text-2)', letterSpacing:'0.06em' },
};
