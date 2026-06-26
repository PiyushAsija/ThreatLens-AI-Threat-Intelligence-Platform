import { useEffect, useState } from 'react';

const RISK_CONFIG = {
  Critical:   { color:'var(--critical)',   glowVar:'var(--critical-border)',   label:'CRITICAL',   bgVar:'var(--critical-dim)' },
  Malicious:  { color:'var(--malicious)',  glowVar:'var(--malicious-border)',  label:'MALICIOUS',  bgVar:'var(--malicious-dim)' },
  Suspicious: { color:'var(--suspicious)', glowVar:'var(--suspicious-border)', label:'SUSPICIOUS', bgVar:'var(--suspicious-dim)' },
  Clean:      { color:'var(--clean)',      glowVar:'var(--clean-border)',      label:'CLEAN',      bgVar:'var(--clean-dim)' },
};

// Resolved hex fallback (used for SVG stroke since CSS vars in SVG strokes
// don't always inherit theme changes reliably across all browsers)
const RISK_HEX_DARK = { Critical:'#ff4d4d', Malicious:'#f97316', Suspicious:'#eab308', Clean:'#22c55e' };
const RISK_HEX_LIGHT = { Critical:'#dc2626', Malicious:'#ea580c', Suspicious:'#ca8a04', Clean:'#16a34a' };

export default function ThreatScore({ score, riskLevel, confidence }) {
  const [displayScore, setDisplayScore] = useState(0);
  const cfg = RISK_CONFIG[riskLevel] || RISK_CONFIG.Suspicious;

  const isLight = typeof document !== 'undefined' &&
    document.documentElement.getAttribute('data-theme') === 'light';
  const strokeColor = (isLight ? RISK_HEX_LIGHT : RISK_HEX_DARK)[riskLevel] || (isLight ? '#ca8a04' : '#eab308');

  useEffect(() => {
    let start = 0;
    const step = score / 40;
    const timer = setInterval(() => {
      start += step;
      if (start >= score) { setDisplayScore(score); clearInterval(timer); }
      else setDisplayScore(Math.floor(start));
    }, 30);
    return () => clearInterval(timer);
  }, [score]);

  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:16 }}>
      <div style={{ position:'relative', width:160, height:160 }}>
        <svg width="160" height="160" viewBox="0 0 160 160" style={{ transform:'rotate(-90deg)' }}>
          <circle cx="80" cy="80" r={radius} fill="none" stroke="var(--border)" strokeWidth="8" />
          <circle
            cx="80" cy="80" r={radius} fill="none"
            stroke={strokeColor} strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition:'stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1)' }}
          />
        </svg>
        <div style={{ position:'absolute', inset:0, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center' }}>
          <div style={{ fontFamily:'var(--font-display)', fontSize:44, fontWeight:700, color: cfg.color, lineHeight:1 }}>
            {displayScore}
          </div>
          <div style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'var(--text-2)', letterSpacing:'0.08em', marginTop:2 }}>/100</div>
        </div>
      </div>

      <div style={{
        fontFamily:'var(--font-display)', fontSize:18, fontWeight:600,
        letterSpacing:'0.08em', padding:'8px 24px', borderRadius:8,
        background: cfg.bgVar, border: `1.5px solid ${cfg.glowVar}`, color: cfg.color,
        animation: riskLevel === 'Critical' ? 'glowPulse 2.5s ease-in-out infinite' : 'none',
      }}>
        {cfg.label}
      </div>

      {confidence != null && (
        <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-2)', letterSpacing:'0.06em' }}>
          AI CONFIDENCE: <span style={{ color:'var(--text-0)' }}>{confidence}%</span>
        </div>
      )}
    </div>
  );
}
