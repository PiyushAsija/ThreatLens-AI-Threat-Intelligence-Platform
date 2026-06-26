import { useState } from 'react';

function ScoreBar({ value, max = 100, color }) {
  return (
    <div style={{ height:4, background:'var(--border)', borderRadius:2, overflow:'hidden', margin:'6px 0' }}>
      <div style={{ width:`${(value/max)*100}%`, height:'100%', background:color, borderRadius:2, transition:'width 1s ease' }} />
    </div>
  );
}

function SourceCard({ source }) {
  if (!source.available) {
    return (
      <div style={S.card}>
        <div style={S.cardHeader}>
          <span style={S.sourceName}>{source.source}</span>
          <span style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'var(--text-3)', padding:'2px 7px', background:'var(--bg-2)', borderRadius:4 }}>UNAVAILABLE</span>
        </div>
        <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-3)' }}>{source.error || 'No data returned'}</div>
      </div>
    );
  }

  if (source.source === 'AbuseIPDB') {
    const score = source.abuse_confidence;
    const color = score > 70 ? 'var(--critical)' : score > 30 ? 'var(--suspicious)' : 'var(--clean)';
    return (
      <div style={S.card}>
        <div style={S.cardHeader}>
          <span style={S.sourceName}>AbuseIPDB</span>
          <span style={{ fontFamily:'var(--font-mono)', fontSize:13, fontWeight:700, color }}>{score}% confidence</span>
        </div>
        <ScoreBar value={score} color={color} />
        <div style={S.row}><span style={S.key}>Reports (90d)</span><span style={S.val}>{source.total_reports}</span></div>
        <div style={S.row}><span style={S.key}>Reporters</span><span style={S.val}>{source.distinct_reporters}</span></div>
        <div style={S.row}><span style={S.key}>ISP</span><span style={S.val}>{source.isp || '—'}</span></div>
        <div style={S.row}><span style={S.key}>Tor exit</span><span style={{ ...S.val, color: source.is_tor ? 'var(--critical)' : 'var(--clean)' }}>{source.is_tor ? 'YES' : 'No'}</span></div>
        {source.last_reported && <div style={S.row}><span style={S.key}>Last seen</span><span style={S.val}>{new Date(source.last_reported).toLocaleDateString()}</span></div>}
      </div>
    );
  }

  if (source.source === 'VirusTotal') {
    const color = source.malicious > 10 ? 'var(--critical)' : source.malicious > 0 ? 'var(--suspicious)' : 'var(--clean)';
    return (
      <div style={S.card}>
        <div style={S.cardHeader}>
          <span style={S.sourceName}>VirusTotal</span>
          <span style={{ fontFamily:'var(--font-mono)', fontSize:13, fontWeight:700, color }}>{source.malicious}/{source.total_engines} engines</span>
        </div>
        <ScoreBar value={source.malicious} max={source.total_engines} color={color} />
        <div style={S.row}><span style={S.key}>Malicious</span><span style={{ ...S.val, color:'var(--critical)' }}>{source.malicious}</span></div>
        <div style={S.row}><span style={S.key}>Suspicious</span><span style={{ ...S.val, color:'var(--suspicious)' }}>{source.suspicious}</span></div>
        <div style={S.row}><span style={S.key}>Harmless</span><span style={{ ...S.val, color:'var(--clean)' }}>{source.harmless}</span></div>
        {source.threat_category && <div style={S.row}><span style={S.key}>Category</span><span style={S.val}>{source.threat_category}</span></div>}
        {source.tags?.length > 0 && (
          <div style={{ display:'flex', gap:4, flexWrap:'wrap', marginTop:6 }}>
            {source.tags.map(t => <span key={t} style={S.tag}>{t}</span>)}
          </div>
        )}
      </div>
    );
  }

  if (source.source === 'AlienVault OTX') {
    const color = source.pulse_count > 5 ? 'var(--critical)' : source.pulse_count > 0 ? 'var(--suspicious)' : 'var(--clean)';
    return (
      <div style={S.card}>
        <div style={S.cardHeader}>
          <span style={S.sourceName}>AlienVault OTX</span>
          <span style={{ fontFamily:'var(--font-mono)', fontSize:13, fontWeight:700, color }}>{source.pulse_count} pulses</span>
        </div>
        <ScoreBar value={Math.min(source.pulse_count * 10, 100)} color={color} />
        {source.pulses?.map((p, i) => (
          <div key={i} style={S.pulseBlock}>
            <div style={{ fontSize:12, color:'var(--text-1)', marginBottom:3 }}>{p.name}</div>
            {p.malware_families?.length > 0 && (
              <div style={{ display:'flex', gap:4, flexWrap:'wrap' }}>
                {p.malware_families.map(f => <span key={f} style={{ ...S.tag, color:'var(--critical)', borderColor:'var(--critical-border)', background:'var(--critical-dim)' }}>{f}</span>)}
              </div>
            )}
          </div>
        ))}
        {source.pulse_count === 0 && <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--clean)' }}>Not found in any threat pulses</div>}
      </div>
    );
  }

  if (source.source === 'URLhaus') {
    const color = source.found ? 'var(--critical)' : 'var(--clean)';
    return (
      <div style={S.card}>
        <div style={S.cardHeader}>
          <span style={S.sourceName}>URLhaus</span>
          <span style={{ fontFamily:'var(--font-mono)', fontSize:12, color }}>{source.found ? source.threat || 'FOUND' : 'NOT FOUND'}</span>
        </div>
        {source.found ? (
          <>
            <div style={S.row}><span style={S.key}>Status</span><span style={{ ...S.val, color:'var(--critical)' }}>{source.status}</span></div>
            {source.url_count && <div style={S.row}><span style={S.key}>URLs tracked</span><span style={S.val}>{source.url_count}</span></div>}
          </>
        ) : (
          <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--clean)' }}>Not found in URLhaus malware database</div>
        )}
      </div>
    );
  }

  if (source.source === 'IPInfo') {
    return (
      <div style={S.card}>
        <div style={S.cardHeader}>
          <span style={S.sourceName}>IPInfo</span>
          <span style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-2)' }}>Geolocation</span>
        </div>
        <div style={S.row}><span style={S.key}>Location</span><span style={S.val}>{[source.city, source.region, source.country].filter(Boolean).join(', ') || '—'}</span></div>
        <div style={S.row}><span style={S.key}>ASN</span><span style={S.val}>{source.asn || '—'}</span></div>
        <div style={S.row}><span style={S.key}>ISP</span><span style={S.val}>{source.isp || '—'}</span></div>
        <div style={S.row}><span style={S.key}>VPN</span><span style={{ ...S.val, color: source.is_vpn ? 'var(--suspicious)' : 'var(--text-2)' }}>{source.is_vpn ? 'Yes' : 'No'}</span></div>
        <div style={S.row}><span style={S.key}>Tor</span><span style={{ ...S.val, color: source.is_tor ? 'var(--critical)' : 'var(--text-2)' }}>{source.is_tor ? 'Yes' : 'No'}</span></div>
        <div style={S.row}><span style={S.key}>Hosting</span><span style={{ ...S.val, color: source.is_hosting ? 'var(--suspicious)' : 'var(--text-2)' }}>{source.is_hosting ? 'Yes' : 'No'}</span></div>
      </div>
    );
  }

  return null;
}

export default function SourceResults({ sources }) {
  return (
    <div>
      <div style={{ fontFamily:'var(--font-mono)', fontSize:10, letterSpacing:'0.12em', color:'var(--text-3)', marginBottom:12 }}>
        {sources.filter(s => s.available).length}/{sources.length} SOURCES AVAILABLE
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(240px, 1fr))', gap:10 }}>
        {sources.map((s, i) => <SourceCard key={i} source={s} />)}
      </div>
    </div>
  );
}

const S = {
  card: { background:'var(--bg-card2)', border:'1px solid var(--border)', borderRadius:9, padding:'14px', display:'flex', flexDirection:'column', gap:6 },
  cardHeader: { display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:4 },
  sourceName: { fontFamily:'var(--font-mono)', fontSize:12, fontWeight:700, color:'var(--text-0)', letterSpacing:'0.05em' },
  row: { display:'flex', justifyContent:'space-between', alignItems:'center', gap:8 },
  key: { fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-2)' },
  val: { fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-1)', textAlign:'right' },
  tag: { fontFamily:'var(--font-mono)', fontSize:10, padding:'2px 7px', background:'var(--bg-2)', border:'1px solid var(--border)', borderRadius:4, color:'var(--text-2)' },
  pulseBlock: { padding:'6px 8px', background:'var(--bg-2)', borderRadius:5, border:'1px solid var(--border)' },
};
