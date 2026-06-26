const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const Groq = require('groq-sdk');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const IS_DEV = process.env.NODE_ENV !== 'production';

// ─── Security Middleware ──────────────────────────────────────────────────────

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));
app.use(express.json({ limit: '10kb' })); // Limit request body size

// Rate limiting — 10 requests per minute per IP (protects free API quotas)
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Max 10 per minute.', code: 'RATE_LIMITED' }
});
app.use('/api/', limiter);

// ─── Groq Client ──────────────────────────────────────────────────────────────

const groq = new Groq({ apiKey: process.env.GROQ_KEY });

// ─── IOC Detection ────────────────────────────────────────────────────────────
// Detects: IPv4 | domain | URL | MD5 hash | SHA256 hash

const PRIVATE_IP_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/,
  /^fe80:/,
  /^0\.0\.0\.0$/,
  /^255\.255\.255\.255$/
];

function detectIOCType(ioc) {
  const trimmed = ioc.trim();

  // IPv4 address
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(trimmed)) {
    const parts = trimmed.split('.').map(Number);
    if (parts.every(p => p >= 0 && p <= 255)) {
      return 'ip';
    }
  }

  // SHA256 hash (64 hex chars)
  if (/^[a-fA-F0-9]{64}$/.test(trimmed)) return 'sha256';

  // MD5 hash (32 hex chars)
  if (/^[a-fA-F0-9]{32}$/.test(trimmed)) return 'md5';

  // URL (starts with http:// or https://)
  if (/^https?:\/\/.+/i.test(trimmed)) return 'url';

  // Domain (contains a dot, no spaces, valid TLD-like structure)
  if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(trimmed)) {
    return 'domain';
  }

  return null;
}

// ─── SSRF Prevention ──────────────────────────────────────────────────────────
// Blocks internal IPs from being submitted as IOCs (OWASP A10)

function isPrivateIP(ip) {
  return PRIVATE_IP_RANGES.some(range => range.test(ip));
}

function validateIOC(ioc, type) {
  if (type === 'ip' && isPrivateIP(ioc)) {
    return { valid: false, reason: 'Private/internal IP addresses cannot be analyzed.' };
  }

  // Block localhost/internal domains
  const blockedDomains = ['localhost', '127.0.0.1', 'internal', 'local', 'corp', 'intranet'];
  if ((type === 'domain' || type === 'url') &&
      blockedDomains.some(b => ioc.toLowerCase().includes(b))) {
    return { valid: false, reason: 'Internal/localhost domains cannot be analyzed.' };
  }

  return { valid: true };
}

// ─── API Helper — Safe axios with timeout ─────────────────────────────────────

async function safeGet(url, options = {}) {
  try {
    const res = await axios.get(url, { timeout: 8000, ...options });
    return { success: true, data: res.data };
  } catch (err) {
    return {
      success: false,
      error: err.response?.data?.error || err.message || 'Request failed',
      status: err.response?.status
    };
  }
}

async function safePost(url, body, options = {}) {
  try {
    const res = await axios.post(url, body, { timeout: 8000, ...options });
    return { success: true, data: res.data };
  } catch (err) {
    return {
      success: false,
      error: err.response?.data?.error || err.message || 'Request failed',
      status: err.response?.status
    };
  }
}

// ─── Individual API Query Functions ──────────────────────────────────────────

// AbuseIPDB — check IP reputation
async function queryAbuseIPDB(ip) {
  const result = await safeGet('https://api.abuseipdb.com/api/v2/check', {
    headers: { Key: process.env.ABUSEIPDB_KEY, Accept: 'application/json' },
    params: { ipAddress: ip, maxAgeInDays: 90, verbose: true }
  });
  if (!result.success) return { source: 'AbuseIPDB', available: false, error: result.error };
  const d = result.data.data;
  return {
    source: 'AbuseIPDB',
    available: true,
    abuse_confidence: d.abuseConfidenceScore,
    total_reports: d.totalReports,
    distinct_reporters: d.numDistinctUsers,
    country: d.countryCode,
    isp: d.isp,
    domain: d.domain,
    is_tor: d.isTor,
    is_public: d.isPublic,
    usage_type: d.usageType,
    last_reported: d.lastReportedAt,
    categories: d.reports?.slice(0, 3).map(r => r.categories).flat() || []
  };
}

// AlienVault OTX — threat pulse lookup
async function queryOTX(ioc, type) {
  const endpointMap = {
    ip: `https://otx.alienvault.com/api/v1/indicators/IPv4/${ioc}/general`,
    domain: `https://otx.alienvault.com/api/v1/indicators/domain/${ioc}/general`,
    url: `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(ioc)}/general`,
    md5: `https://otx.alienvault.com/api/v1/indicators/file/${ioc}/general`,
    sha256: `https://otx.alienvault.com/api/v1/indicators/file/${ioc}/general`
  };

  const url = endpointMap[type];
  if (!url) return { source: 'AlienVault OTX', available: false, error: 'Type not supported' };

  const result = await safeGet(url, {
    headers: { 'X-OTX-API-KEY': process.env.OTX_KEY }
  });

  if (!result.success) return { source: 'AlienVault OTX', available: false, error: result.error };
  const d = result.data;
  return {
    source: 'AlienVault OTX',
    available: true,
    pulse_count: d.pulse_info?.count || 0,
    pulses: d.pulse_info?.pulses?.slice(0, 3).map(p => ({
      name: p.name,
      tags: p.tags?.slice(0, 5) || [],
      malware_families: p.malware_families?.slice(0, 3) || [],
      attack_ids: p.attack_ids?.slice(0, 3) || []
    })) || [],
    reputation: d.reputation || 0,
    country: d.country_name || null,
    asn: d.asn || null
  };
}

// VirusTotal — multi-engine scan
async function queryVirusTotal(ioc, type) {
  const vtTypeMap = {
    ip: { path: 'ip_addresses', encoder: v => v },
    domain: { path: 'domains', encoder: v => v },
    url: { path: 'urls', encoder: v => Buffer.from(v).toString('base64').replace(/=/g, '') },
    md5: { path: 'files', encoder: v => v },
    sha256: { path: 'files', encoder: v => v }
  };

  const mapping = vtTypeMap[type];
  if (!mapping) return { source: 'VirusTotal', available: false, error: 'Type not supported' };

  const result = await safeGet(
    `https://www.virustotal.com/api/v3/${mapping.path}/${mapping.encoder(ioc)}`,
    { headers: { 'x-apikey': process.env.VT_KEY } }
  );

  if (!result.success) return { source: 'VirusTotal', available: false, error: result.error };
  const stats = result.data.data?.attributes?.last_analysis_stats || {};
  const names = result.data.data?.attributes?.popular_threat_classification || null;

  return {
    source: 'VirusTotal',
    available: true,
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    undetected: stats.undetected || 0,
    harmless: stats.harmless || 0,
    total_engines: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0),
    threat_category: names?.suggested_threat_label || null,
    reputation: result.data.data?.attributes?.reputation || null,
    tags: result.data.data?.attributes?.tags?.slice(0, 5) || []
  };
}

// URLhaus — malicious URL/domain database
async function queryURLhaus(ioc, type) {
  let body;
  let endpoint;

  if (type === 'url') {
    endpoint = 'https://urlhaus-api.abuse.ch/v1/url/';
    body = new URLSearchParams({ url: ioc });
  } else if (type === 'domain') {
    endpoint = 'https://urlhaus-api.abuse.ch/v1/host/';
    body = new URLSearchParams({ host: ioc });
  } else if (type === 'md5' || type === 'sha256') {
    endpoint = 'https://urlhaus-api.abuse.ch/v1/payload/';
    body = new URLSearchParams({ md5_hash: type === 'md5' ? ioc : undefined, sha256_hash: type === 'sha256' ? ioc : undefined });
  } else {
    endpoint = 'https://urlhaus-api.abuse.ch/v1/host/';
    body = new URLSearchParams({ host: ioc });
  }

  const result = await safePost(endpoint, body.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });

  if (!result.success) return { source: 'URLhaus', available: false, error: result.error };
  const d = result.data;

  if (d.query_status === 'no_results' || d.query_status === 'not_found') {
    return { source: 'URLhaus', available: true, found: false, status: 'Not in URLhaus database' };
  }

  return {
    source: 'URLhaus',
    available: true,
    found: true,
    status: d.urlhaus_status || d.query_status,
    threat: d.threat || null,
    url_count: d.urls_count || null,
    blacklists: d.blacklists || null,
    urls: d.urls?.slice(0, 3).map(u => ({
      url: u.url,
      status: u.url_status,
      threat: u.threat,
      date_added: u.date_added
    })) || []
  };
}

// IPInfo — geolocation and ASN
async function queryIPInfo(ip) {
  const result = await safeGet(`https://ipinfo.io/${ip}/json`, {
    headers: { Authorization: `Bearer ${process.env.IPINFO_KEY}` }
  });
  if (!result.success) return { source: 'IPInfo', available: false, error: result.error };
  const d = result.data;
  return {
    source: 'IPInfo',
    available: true,
    ip: d.ip,
    city: d.city || null,
    region: d.region || null,
    country: d.country || null,
    org: d.org || null,
    asn: d.org?.split(' ')[0] || null,
    isp: d.org?.split(' ').slice(1).join(' ') || null,
    is_vpn: d.privacy?.vpn || false,
    is_tor: d.privacy?.tor || false,
    is_proxy: d.privacy?.proxy || false,
    is_hosting: d.privacy?.hosting || false,
    timezone: d.timezone || null,
    loc: d.loc || null
  };
}

// ─── Route API calls by IOC type ─────────────────────────────────────────────

async function queryAllSources(ioc, type) {
  const queries = [];

  if (type === 'ip') {
    queries.push(
      queryAbuseIPDB(ioc),
      queryOTX(ioc, 'ip'),
      queryVirusTotal(ioc, 'ip'),
      queryIPInfo(ioc),
      queryURLhaus(ioc, 'ip')
    );
  } else if (type === 'domain') {
    queries.push(
      queryOTX(ioc, 'domain'),
      queryVirusTotal(ioc, 'domain'),
      queryURLhaus(ioc, 'domain')
    );
  } else if (type === 'url') {
    queries.push(
      queryURLhaus(ioc, 'url'),
      queryVirusTotal(ioc, 'url'),
      queryOTX(ioc, 'url')
    );
  } else if (type === 'md5' || type === 'sha256') {
    queries.push(
      queryVirusTotal(ioc, type),
      queryOTX(ioc, type),
      queryURLhaus(ioc, type)
    );
  }

  // Run ALL queries in parallel — total time = slowest single API, not sum
  const results = await Promise.all(queries);
  return results;
}

// ─── Groq AI Synthesis ────────────────────────────────────────────────────────

async function synthesizeWithAI(ioc, type, sourceResults) {
  const availableSources = sourceResults.filter(s => s.available);
  const failedSources = sourceResults.filter(s => !s.available);

  const prompt = `You are a senior threat intelligence analyst. Analyze this IOC and synthesize the data from multiple sources into a single coherent assessment.

IOC: ${ioc}
IOC TYPE: ${type.toUpperCase()}

THREAT INTELLIGENCE DATA FROM SOURCES:
${JSON.stringify(availableSources, null, 2)}

${failedSources.length > 0 ? `UNAVAILABLE SOURCES (API error or no data): ${failedSources.map(s => s.source).join(', ')}` : ''}

ANALYSIS INSTRUCTIONS:
1. If sources disagree, explain WHY they might disagree and which source is more authoritative for this IOC type
2. Weight sources by relevance: AbuseIPDB is most authoritative for IP reputation; VirusTotal for malware hashes; URLhaus for malicious URLs/domains
3. Consider context: a Tor exit node with SSH brute force reports is different from a botnet C2 node
4. Be specific — mention actual numbers from the data (e.g. "47 abuse reports", "12/90 VirusTotal engines")
5. For the MITRE ATT&CK techniques, only include techniques that have DIRECT evidence in the data

Return ONLY a valid JSON object with exactly this structure:
{
  "threat_score": <integer 0-100>,
  "risk_level": "Clean" or "Suspicious" or "Malicious" or "Critical",
  "narrative": "<3-4 sentences. Be specific. Reference actual data points. Explain any source conflicts.>",
  "mitre_techniques": [
    {"id": "T1090.003", "name": "Proxy: Multi-hop Proxy", "relevance": "one sentence why"}
  ],
  "recommendation": "<one specific, immediately actionable step for the security team>",
  "confidence": <integer 0-100>,
  "threat_categories": ["<category1>", "<category2>"]
}

Scoring guide:
0-20 = Clean (no indicators, benign infrastructure)
21-40 = Low risk (minor indicators, probably legitimate)
41-60 = Suspicious (multiple weak signals, warrants monitoring)
61-80 = Malicious (strong evidence of malicious activity)
81-100 = Critical (confirmed active threat, immediate action required)`;

  const completion = await groq.chat.completions.create({
    model: 'llama-3.3-70b-versatile',
    temperature: 0.1,
    max_tokens: 1500,
    response_format: { type: 'json_object' },
    messages: [
      {
        role: 'system',
        content: 'You are a senior threat intelligence analyst. You synthesize data from multiple threat intelligence sources into clear, actionable security assessments. You always return valid JSON only.'
      },
      { role: 'user', content: prompt }
    ]
  });

  const text = completion.choices[0].message.content;
  return JSON.parse(text);
}

// ─── Helper: extract geo from sources ────────────────────────────────────────

function extractGeo(sourceResults) {
  const ipinfo = sourceResults.find(s => s.source === 'IPInfo' && s.available);
  const abuse = sourceResults.find(s => s.source === 'AbuseIPDB' && s.available);
  const otx = sourceResults.find(s => s.source === 'AlienVault OTX' && s.available);

  return {
    country: ipinfo?.country || abuse?.country || otx?.country || null,
    city: ipinfo?.city || null,
    region: ipinfo?.region || null,
    asn: ipinfo?.asn || otx?.asn || null,
    isp: ipinfo?.isp || abuse?.isp || null,
    is_tor: ipinfo?.is_tor || abuse?.is_tor || false,
    is_vpn: ipinfo?.is_vpn || false,
    is_proxy: ipinfo?.is_proxy || false,
    is_hosting: ipinfo?.is_hosting || false,
    loc: ipinfo?.loc || null
  };
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  const keys = {
    abuseipdb: !!process.env.ABUSEIPDB_KEY && process.env.ABUSEIPDB_KEY !== 'your-abuseipdb-key-here',
    otx: !!process.env.OTX_KEY && process.env.OTX_KEY !== 'your-otx-key-here',
    virustotal: !!process.env.VT_KEY && process.env.VT_KEY !== 'your-virustotal-key-here',
    ipinfo: !!process.env.IPINFO_KEY && process.env.IPINFO_KEY !== 'your-ipinfo-key-here',
    groq: !!process.env.GROQ_KEY && process.env.GROQ_KEY !== 'your-groq-key-here'
  };
  const allConfigured = Object.values(keys).every(Boolean);
  res.json({
    status: allConfigured ? 'ok' : 'partial',
    service: 'ThreatLens API',
    keys_configured: keys,
    ready: allConfigured
  });
});

// Quick API test — checks Groq connection
app.get('/test-api', async (req, res) => {
  try {
    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      max_tokens: 50,
      messages: [{ role: 'user', content: 'Reply with only: {"status":"ok"}' }],
      response_format: { type: 'json_object' }
    });
    res.json({ success: true, groq: JSON.parse(completion.choices[0].message.content) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Main analysis route
app.post('/api/analyze', async (req, res) => {
  const { ioc } = req.body;

  // 1. Input validation
  if (!ioc || typeof ioc !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid ioc field.', code: 'MISSING_IOC' });
  }

  const cleaned = ioc.trim();
  if (cleaned.length === 0 || cleaned.length > 2048) {
    return res.status(400).json({ error: 'IOC must be between 1 and 2048 characters.', code: 'INVALID_LENGTH' });
  }

  // 2. Detect IOC type
  const iocType = detectIOCType(cleaned);
  if (!iocType) {
    return res.status(400).json({
      error: 'Could not identify IOC type. Supported: IPv4 address, domain name, URL, MD5 hash, SHA256 hash.',
      code: 'UNKNOWN_IOC_TYPE',
      input: cleaned
    });
  }

  // 3. SSRF + security validation (OWASP A10)
  const validation = validateIOC(cleaned, iocType);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.reason, code: 'INVALID_IOC' });
  }

  // 4. Check required keys are set
  if (!process.env.GROQ_KEY || process.env.GROQ_KEY === 'your-groq-key-here') {
    return res.status(500).json({ error: 'GROQ_KEY not configured in .env', code: 'NO_GROQ_KEY' });
  }

  console.log(`[${new Date().toISOString()}] Analyzing ${iocType.toUpperCase()}: ${cleaned}`);

  try {
    // 5. Query all intelligence sources in PARALLEL
    const startTime = Date.now();
    const sourceResults = await queryAllSources(cleaned, iocType);
    const queryTime = Date.now() - startTime;

    const availableCount = sourceResults.filter(s => s.available).length;
    console.log(`  Sources: ${availableCount}/${sourceResults.length} available in ${queryTime}ms`);

    // 6. AI synthesis
    const aiResult = await synthesizeWithAI(cleaned, iocType, sourceResults);

    // 7. Build final response
    const response = {
      ioc: cleaned,
      ioc_type: iocType,
      threat_score: aiResult.threat_score ?? 0,
      risk_level: aiResult.risk_level ?? 'Unknown',
      narrative: aiResult.narrative ?? 'Analysis unavailable.',
      mitre_techniques: aiResult.mitre_techniques ?? [],
      threat_categories: aiResult.threat_categories ?? [],
      recommendation: aiResult.recommendation ?? 'No specific action required.',
      confidence: aiResult.confidence ?? 50,
      geo: iocType === 'ip' ? extractGeo(sourceResults) : null,
      sources_checked: sourceResults.map(s => ({
        source: s.source,
        available: s.available,
        error: s.available ? undefined : s.error
      })),
      sources_detail: sourceResults,
      meta: {
        query_time_ms: queryTime,
        sources_queried: sourceResults.length,
        sources_available: availableCount,
        analyzed_at: new Date().toISOString()
      }
    };

    console.log(`  Score: ${response.threat_score} | Risk: ${response.risk_level}`);
    return res.json(response);

  } catch (err) {
    console.error('Analysis error:', err.message);

    if (err.message?.includes('429')) {
      return res.status(429).json({ error: 'AI rate limit reached. Wait 1 minute and try again.', code: 'GROQ_RATE_LIMITED' });
    }
    if (err.message?.includes('401') || err.message?.includes('invalid_api_key')) {
      return res.status(500).json({ error: 'Invalid Groq API key. Check GROQ_KEY in .env', code: 'INVALID_GROQ_KEY' });
    }

    return res.status(500).json({
      error: 'Analysis failed. Please try again.',
      code: 'SERVER_ERROR',
      ...(IS_DEV && { debug: err.message })
    });
  }
});

// ─── Error Handler ────────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Unexpected server error.', code: 'INTERNAL_ERROR' });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  const keys = {
    ABUSEIPDB: process.env.ABUSEIPDB_KEY && process.env.ABUSEIPDB_KEY !== 'your-abuseipdb-key-here',
    OTX: process.env.OTX_KEY && process.env.OTX_KEY !== 'your-otx-key-here',
    VIRUSTOTAL: process.env.VT_KEY && process.env.VT_KEY !== 'your-virustotal-key-here',
    IPINFO: process.env.IPINFO_KEY && process.env.IPINFO_KEY !== 'your-ipinfo-key-here',
    GROQ: process.env.GROQ_KEY && process.env.GROQ_KEY !== 'your-groq-key-here'
  };
  const allOk = Object.values(keys).every(Boolean);
  const keyStatus = Object.entries(keys).map(([k, v]) => `  ${v ? '✅' : '❌'} ${k}`).join('\n');

  console.log(`
  ╔══════════════════════════════════════════════════════╗
  ║   ThreatLens API — Running on port ${PORT}             ║
  ║   AI Engine: Llama 3.3 70B via Groq                  ║
  ╚══════════════════════════════════════════════════════╝

  API Keys:
${keyStatus}

  ${allOk ? '✅ All keys configured — ready to analyze!' : '⚠️  Some keys missing — check .env file'}

  Health:   http://localhost:${PORT}/health
  API test: http://localhost:${PORT}/test-api
  `);
});
