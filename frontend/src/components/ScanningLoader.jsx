import { useState, useEffect } from 'react';

const STEPS = [
  { msg: 'Detecting IOC type...', duration: 600 },
  { msg: 'Querying AbuseIPDB...', duration: 1000 },
  { msg: 'Checking VirusTotal (90 engines)...', duration: 1200 },
  { msg: 'Scanning AlienVault OTX...', duration: 1000 },
  { msg: 'Checking URLhaus database...', duration: 800 },
  { msg: 'Fetching IPInfo geolocation...', duration: 700 },
  { msg: 'AI synthesizing intelligence...', duration: 2000 },
  { msg: 'Generating threat assessment...', duration: 800 },
];

export default function ScanningLoader() {
  const [step, setStep] = useState(0);
  const [done, setDone] = useState([]);

  useEffect(() => {
    let delay = 0;
    STEPS.forEach((s, i) => {
      delay += s.duration;
      const t = setTimeout(() => {
        setDone(p => [...p, i]);
        setStep(i + 1);
      }, delay);
      return () => clearTimeout(t);
    });
  }, []);

  return (
    <div style={S.page}>
      <div style={S.radarWrap}>
        <svg width="180" height="180" viewBox="0 0 180 180" style={{ position:'absolute' }}>
          <circle cx="90" cy="90" r="88" stroke="var(--border)" strokeWidth="1" fill="none" />
          <circle cx="90" cy="90" r="60" stroke="var(--border)" strokeWidth="1" fill="none" />
          <circle cx="90" cy="90" r="32" stroke="var(--border)" strokeWidth="1" fill="none" />
          <line x1="90" y1="2" x2="90" y2="178" stroke="var(--border)" strokeWidth="1" />
          <line x1="2" y1="90" x2="178" y2="90" stroke="var(--border)" strokeWidth="1" />
          <g style={{ transformOrigin:'90px 90px', animation:'radarSweep 2.5s linear infinite' }}>
            <defs>
              <linearGradient id="sweep" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#3a63ff" stopOpacity="0" />
                <stop offset="100%" stopColor="#3a63ff" stopOpacity="0.45" />
              </linearGradient>
            </defs>
            <path d="M90,90 L90,2 A88,88 0 0,1 163,137 Z" fill="url(#sweep)" />
          </g>
        </svg>
        {[{x:120,y:55,d:'0.3s'},{x:65,y:120,d:'1.1s'},{x:140,y:100,d:'0.7s'}].map((p,i) => (
          <div key={i} style={{
            position:'absolute', left:p.x, top:p.y,
            width:7, height:7, borderRadius:'50%',
            background:'var(--critical)', animation:`ping 1.8s ease-out ${p.d} infinite`
          }} />
        ))}
        <div style={S.radarCenter} />
      </div>

      <div className="card-elevated" style={S.terminal}>
        <div style={S.termBar}>
          {['#ff5f57','#febc2e','#28c840'].map(c => <div key={c} style={{ width:10,height:10,borderRadius:'50%',background:c }} />)}
          <span style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-2)', marginLeft:8 }}>threatlens — analyzing</span>
        </div>
        <div style={S.termBody}>
          {STEPS.map((s, i) => {
            if (i > step) return null;
            const isDone = done.includes(i);
            const isActive = step === i;
            return (
              <div key={i} style={{ display:'flex', alignItems:'center', gap:10, marginBottom:8, animation:'fadeInUp 0.25s ease' }}>
                <span style={{ color:'var(--accent)', fontFamily:'var(--font-mono)', fontSize:12 }}>$</span>
                <span style={{
                  fontFamily:'var(--font-mono)', fontSize:12, letterSpacing:'0.05em',
                  color: isDone ? 'var(--accent)' : isActive ? 'var(--text-0)' : 'var(--text-2)'
                }}>{s.msg}</span>
                {isDone && <span style={{ marginLeft:'auto', color:'var(--accent)', fontSize:11 }}>✓</span>}
                {isActive && <span style={{ color:'var(--text-0)', animation:'blink 1s step-end infinite', marginLeft:2, fontFamily:'var(--font-mono)' }}>█</span>}
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ display:'flex', alignItems:'center', gap:12 }}>
        <div style={{ width:16, height:16, border:'2px solid var(--border)', borderTopColor:'var(--accent)', borderRadius:'50%', animation:'spin 0.8s linear infinite' }} />
        <span style={{ fontFamily:'var(--font-mono)', fontSize:12, color:'var(--text-2)', letterSpacing:'0.1em' }}>INTELLIGENCE GATHERING IN PROGRESS</span>
      </div>
    </div>
  );
}

const S = {
  page: { flex:1, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', gap:40, padding:40 },
  radarWrap: { width:180, height:180, position:'relative', display:'flex', alignItems:'center', justifyContent:'center' },
  radarCenter: { width:8, height:8, borderRadius:'50%', background:'var(--accent)', position:'absolute', boxShadow:'0 0 10px var(--accent)' },
  terminal: { width:'100%', maxWidth:500, background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:10, overflow:'hidden' },
  termBar: { display:'flex', alignItems:'center', gap:6, padding:'10px 14px', background:'var(--bg-2)', borderBottom:'1px solid var(--border)' },
  termBody: { padding:'18px 18px', minHeight:160 },
};
