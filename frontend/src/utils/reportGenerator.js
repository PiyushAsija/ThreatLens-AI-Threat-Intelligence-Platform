export function downloadReport(data) {
  const ts = new Date().toLocaleString();
  const riskColors = { Critical:'#dc2626', Malicious:'#ea580c', Suspicious:'#ca8a04', Clean:'#16a34a' };
  const rc = riskColors[data.risk_level] || '#888';
  const brandBlue = '#3151e0';

  const mitreRows = (data.mitre_techniques || []).map(t => `
    <tr>
      <td style="font-family:monospace;color:${brandBlue};padding:6px 10px">${t.id}</td>
      <td style="padding:6px 10px">${t.name}</td>
      <td style="padding:6px 10px;color:#555">${t.relevance || ''}</td>
    </tr>`).join('');

  const sourceRows = (data.sources_detail || data.sources_checked || []).map(s => {
    const ok = s.available !== false;
    return `<tr>
      <td style="font-family:monospace;padding:6px 10px;font-weight:bold">${s.source}</td>
      <td style="padding:6px 10px"><span style="color:${ok?'#16a34a':'#dc2626'}">${ok?'Available':'Unavailable'}</span></td>
      <td style="padding:6px 10px;font-size:12px;color:#555">${s.error || ''}</td>
    </tr>`;
  }).join('');

  const html = `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>ThreatLens Report — ${data.ioc}</title>
<style>
  body{font-family:'Segoe UI',Arial,sans-serif;max-width:860px;margin:0 auto;padding:40px 30px;color:#0c1228;background:#fff}
  h1{font-size:26px;margin:0;font-weight:700} h2{font-size:16px;font-weight:600;border-bottom:1px solid #e5e7eb;padding-bottom:8px;margin:28px 0 14px}
  .header{border-bottom:3px solid ${brandBlue};padding-bottom:20px;margin-bottom:28px}
  .score-row{display:flex;align-items:center;gap:32px;margin:20px 0}
  .score-circle{width:90px;height:90px;border-radius:50%;background:${rc}15;border:3px solid ${rc};display:flex;align-items:center;justify-content:center;flex-direction:column}
  .score-num{font-size:28px;font-weight:700;color:${rc};line-height:1}
  .score-max{font-size:11px;color:#888;font-family:monospace}
  .risk-badge{padding:8px 20px;border-radius:6px;background:${rc}15;border:1.5px solid ${rc};color:${rc};font-weight:700;font-size:16px;letter-spacing:0.06em}
  .narrative{background:#f6f7fb;border-left:3px solid ${brandBlue};padding:14px 18px;border-radius:0 6px 6px 0;font-size:14px;line-height:1.7;color:#333;margin:12px 0}
  .rec{background:#eef1fd;border:1px solid #c7d0fa;border-radius:6px;padding:12px 16px;font-size:14px;color:#2942b0;margin:12px 0}
  table{width:100%;border-collapse:collapse;font-size:14px} th{text-align:left;padding:8px 10px;background:#f4f5f9;font-size:11px;letter-spacing:0.05em;color:#666}
  tr:not(:last-child) td{border-bottom:1px solid #f0f0f0}
  .meta{display:flex;gap:28px;flex-wrap:wrap;margin-top:16px}
  .meta-item label{display:block;font-family:monospace;font-size:10px;color:#888;letter-spacing:0.08em;margin-bottom:3px}
  .meta-item span{font-family:monospace;font-size:13px;color:#111}
  .print-btn{display:inline-block;margin-bottom:20px;padding:10px 22px;background:${brandBlue};color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer;font-weight:600}
  @media print{.print-btn{display:none}}
</style>
</head><body>
<button class="print-btn" onclick="window.print()">🖨 Print / Save as PDF</button>

<div class="header">
  <div style="font-family:monospace;font-size:11px;color:${brandBlue};letter-spacing:0.15em;margin-bottom:8px">THREATLENS — AI THREAT INTELLIGENCE PLATFORM</div>
  <h1>Threat Intelligence Report</h1>
  <div class="meta">
    <div class="meta-item"><label>IOC</label><span>${data.ioc}</span></div>
    <div class="meta-item"><label>TYPE</label><span>${data.ioc_type?.toUpperCase()}</span></div>
    <div class="meta-item"><label>ANALYZED</label><span>${ts}</span></div>
    <div class="meta-item"><label>SOURCES</label><span>${data.meta?.sources_available || '?'}/${data.meta?.sources_queried || '?'} available</span></div>
  </div>
</div>

<h2>Threat Assessment</h2>
<div class="score-row">
  <div class="score-circle">
    <div class="score-num">${data.threat_score}</div>
    <div class="score-max">/100</div>
  </div>
  <div>
    <div class="risk-badge">${data.risk_level?.toUpperCase()}</div>
    ${data.confidence ? `<div style="font-family:monospace;font-size:12px;color:#888;margin-top:8px">AI Confidence: ${data.confidence}%</div>` : ''}
  </div>
</div>

<h2>AI Analyst Narrative</h2>
<div class="narrative">${data.narrative}</div>

<h2>Recommended Action</h2>
<div class="rec">⚡ ${data.recommendation}</div>

${data.geo ? `<h2>Geographic Information</h2>
<table><tr><th>FIELD</th><th>VALUE</th></tr>
  <tr><td>Country</td><td>${data.geo.country || '—'}</td></tr>
  <tr><td>City / Region</td><td>${[data.geo.city, data.geo.region].filter(Boolean).join(', ') || '—'}</td></tr>
  <tr><td>ASN</td><td>${data.geo.asn || '—'}</td></tr>
  <tr><td>ISP</td><td>${data.geo.isp || '—'}</td></tr>
  <tr><td>Tor Exit Node</td><td style="color:${data.geo.is_tor?'#dc2626':'#16a34a'}">${data.geo.is_tor ? 'YES' : 'No'}</td></tr>
  <tr><td>VPN / Proxy</td><td>${data.geo.is_vpn || data.geo.is_proxy ? 'Yes' : 'No'}</td></tr>
</table>` : ''}

${mitreRows ? `<h2>MITRE ATT&CK Techniques</h2>
<table><tr><th>ID</th><th>TECHNIQUE</th><th>RELEVANCE</th></tr>${mitreRows}</table>` : ''}

<h2>Intelligence Sources</h2>
<table><tr><th>SOURCE</th><th>STATUS</th><th>NOTES</th></tr>${sourceRows}</table>

<div style="margin-top:40px;padding-top:16px;border-top:1px solid #e5e7eb;font-family:monospace;font-size:11px;color:#aaa">
  Generated by ThreatLens v1.0 · Powered by Llama 3.3 70B (Groq) ·
  Sources: AbuseIPDB, VirusTotal, AlienVault OTX, URLhaus, IPInfo ·
  MITRE ATT&CK® is a registered trademark of The MITRE Corporation ·
  ${new Date().toISOString()}
</div>
</body></html>`;

  const blob = new Blob([html], { type:'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ThreatLens-Report-${data.ioc.replace(/[^a-zA-Z0-9]/g,'_')}-${Date.now()}.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
