import ThreatScore from './ThreatScore.jsx';
import SourceResults from './SourceResults.jsx';
import { downloadReport } from '../utils/reportGenerator.js';

const IOC_TYPE_COLORS = {
  ip:'#3a63ff', domain:'#a78bfa', url:'#f59e0b', md5:'#06b6d4', sha256:'#06b6d4'
};

export default function ThreatReport({ data, onNewScan }) {
  const iocColor = IOC_TYPE_COLORS[data.ioc_type] || '#888';

  return (
    <div style={S.page}>
      <div style={S.topBar}>
        <div style={S.iocDisplay}>
          <span style={{ ...S.iocTypeBadge, background: iocColor + '18', color: iocColor, border: `1px solid ${iocColor}50` }}>
            {data.ioc_type?.toUpperCase()}
          </span>
          <span style={S.iocValue}>{data.ioc}</span>
        </div>
        <div style={{ display:'flex', gap:10 }}>
          <button style={S.dlBtn} onClick={() => downloadReport(data)}>⬇ Download Report</button>
          <button style={S.newBtn} onClick={onNewScan}>↺ New Scan</button>
        </div>
      </div>

      <div style={S.content}>
        <div style={S.topGrid}>
          <div className="card-elevated" style={S.scoreCard}>
            <ThreatScore
              score={data.threat_score}
              riskLevel={data.risk_level}
              confidence={data.confidence}
            />
            {data.geo && (data.geo.country || data.geo.city) && (
              <GeoBlock geo={data.geo} />
            )}
          </div>

          <div style={{ display:'flex', flexDirection:'column', gap:14 }}>
            <div className="card-elevated" style={S.narrativeCard}>
              <div style={S.sectionLabel}>AI ANALYST ASSESSMENT</div>
              <p style={S.narrative}>{data.narrative}</p>
            </div>

            <div style={S.recommendationCard}>
              <div style={S.sectionLabel}>RECOMMENDED ACTION</div>
              <div style={S.recommendation}>⚡ {data.recommendation}</div>
            </div>

            {data.mitre_techniques?.length > 0 && (
              <div className="card-elevated" style={S.mitreCard}>
                <div style={S.sectionLabel}>MITRE ATT&CK TECHNIQUES</div>
                <div style={{ display:'flex', flexWrap:'wrap', gap:8, marginTop:4 }}>
                  {data.mitre_techniques.map((t, i) => (
                    <a
                      key={i}
                      href={`https://attack.mitre.org/techniques/${t.id?.replace('.','/')}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={S.mitrePill}
                      title={t.relevance}
                    >
                      <span style={{ color:'var(--accent)', fontWeight:700 }}>{t.id}</span>
                      <span style={{ color:'var(--text-2)', marginLeft:6 }}>{t.name}</span>
                      <span style={{ marginLeft:6, opacity:0.5, fontSize:10 }}>↗</span>
                    </a>
                  ))}
                </div>
              </div>
            )}

            {data.threat_categories?.length > 0 && (
              <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
                {data.threat_categories.map((c, i) => (
                  <span key={i} style={S.catBadge}>{c}</span>
                ))}
              </div>
            )}
          </div>
        </div>

        <div style={S.section}>
          <div style={S.sectionLabel}>INTELLIGENCE SOURCES</div>
          <SourceResults sources={data.sources_detail || data.sources_checked || []} />
        </div>

        <div style={S.metaBar}>
          <span>Analyzed: {data.meta?.analyzed_at ? new Date(data.meta.analyzed_at).toLocaleString() : '—'}</span>
          <span>Query time: {data.meta?.query_time_ms}ms</span>
          <span>Sources: {data.meta?.sources_available}/{data.meta?.sources_queried}</span>
        </div>
      </div>
    </div>
  );
}

function GeoBlock({ geo }) {
  const flags = { 'DE':'🇩🇪','US':'🇺🇸','RU':'🇷🇺','CN':'🇨🇳','NL':'🇳🇱','FR':'🇫🇷','GB':'🇬🇧','IN':'🇮🇳' };
  return (
    <div style={{ marginTop:16, padding:'12px', background:'var(--bg-2)', border:'1px solid var(--border)', borderRadius:8, width:'100%' }}>
      <div style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'var(--text-3)', letterSpacing:'0.1em', marginBottom:8 }}>GEOLOCATION</div>
      <div style={{ fontFamily:'var(--font-display)', fontSize:20, fontWeight:600, color:'var(--text-0)', marginBottom:4 }}>
        {flags[geo.country] || '🌐'} {[geo.city, geo.country].filter(Boolean).join(', ')}
      </div>
      {geo.isp && <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-2)', marginBottom:6 }}>{geo.isp}</div>}
      <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
        {geo.is_tor && <span style={{ fontFamily:'var(--font-mono)', fontSize:10, padding:'2px 7px', background:'var(--critical-dim)', border:'1px solid var(--critical-border)', borderRadius:4, color:'var(--critical)' }}>TOR EXIT</span>}
        {geo.is_vpn && <span style={{ fontFamily:'var(--font-mono)', fontSize:10, padding:'2px 7px', background:'var(--suspicious-dim)', border:'1px solid var(--suspicious-border)', borderRadius:4, color:'var(--suspicious)' }}>VPN</span>}
        {geo.is_proxy && <span style={{ fontFamily:'var(--font-mono)', fontSize:10, padding:'2px 7px', background:'var(--suspicious-dim)', border:'1px solid var(--suspicious-border)', borderRadius:4, color:'var(--suspicious)' }}>PROXY</span>}
        {geo.is_hosting && <span style={{ fontFamily:'var(--font-mono)', fontSize:10, padding:'2px 7px', background:'var(--bg-card2)', border:'1px solid var(--border)', borderRadius:4, color:'var(--text-2)' }}>HOSTING</span>}
        {geo.asn && <span style={{ fontFamily:'var(--font-mono)', fontSize:10, padding:'2px 7px', background:'var(--bg-card2)', border:'1px solid var(--border)', borderRadius:4, color:'var(--text-2)' }}>{geo.asn}</span>}
      </div>
    </div>
  );
}

const S = {
  page: { flex:1, display:'flex', flexDirection:'column' },
  topBar: {
    display:'flex', alignItems:'center', justifyContent:'space-between', gap:12,
    padding:'12px 32px', borderBottom:'1px solid var(--border)',
    background:'var(--bg-1)', backdropFilter:'blur(12px)',
    position:'sticky', top:64, zIndex:50, flexWrap:'wrap'
  },
  iocDisplay: { display:'flex', alignItems:'center', gap:10 },
  iocTypeBadge: { fontFamily:'var(--font-mono)', fontSize:10, fontWeight:700, padding:'3px 8px', borderRadius:5, letterSpacing:'0.08em' },
  iocValue: { fontFamily:'var(--font-mono)', fontSize:14, color:'var(--text-0)', letterSpacing:'0.03em' },
  dlBtn: { fontFamily:'var(--font-mono)', fontSize:12, padding:'8px 16px', background:'var(--accent)', border:'none', borderRadius:7, color:'#ffffff', cursor:'pointer', fontWeight:700 },
  newBtn: { fontFamily:'var(--font-mono)', fontSize:12, padding:'8px 14px', background:'transparent', border:'1px solid var(--border-strong)', borderRadius:7, color:'var(--text-1)', cursor:'pointer' },
  content: { padding:'28px 32px', maxWidth:1100, margin:'0 auto', width:'100%', display:'flex', flexDirection:'column', gap:24 },
  topGrid: { display:'grid', gridTemplateColumns:'220px 1fr', gap:20, alignItems:'start' },
  scoreCard: { display:'flex', flexDirection:'column', alignItems:'center', gap:12, background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:12, padding:'24px 16px' },
  narrativeCard: { background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:10, padding:'16px 18px' },
  recommendationCard: { background:'var(--accent-dim)', border:'1px solid var(--border-accent)', borderRadius:10, padding:'14px 18px' },
  mitreCard: { background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:10, padding:'14px 18px' },
  sectionLabel: { fontFamily:'var(--font-mono)', fontSize:10, letterSpacing:'0.12em', color:'var(--text-3)', marginBottom:8 },
  narrative: { fontSize:14, color:'var(--text-1)', lineHeight:1.75 },
  recommendation: { fontSize:14, color:'var(--accent)', lineHeight:1.7, fontWeight:500 },
  mitrePill: {
    display:'inline-flex', alignItems:'center', padding:'6px 12px',
    background:'var(--bg-2)', border:'1px solid var(--border)', borderRadius:7,
    fontFamily:'var(--font-mono)', fontSize:12, textDecoration:'none', cursor:'pointer',
  },
  catBadge: { fontFamily:'var(--font-mono)', fontSize:10, padding:'3px 9px', background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:5, color:'var(--text-2)' },
  section: {},
  metaBar: { display:'flex', gap:20, fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-3)', flexWrap:'wrap', paddingTop:8, borderTop:'1px solid var(--border)' },
};
