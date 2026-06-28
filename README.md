# ThreatLens — AI Threat Intelligence Platform

> Analyze any IP, domain, URL, or file hash against 5 threat intelligence databases. AI synthesizes all results into a single actionable verdict in under 5 seconds.

![Stack](https://img.shields.io/badge/Stack-React%20%2B%20Node.js%20%2B%20Llama%203.3-3151e0)
![OWASP](https://img.shields.io/badge/Security-OWASP%20Top%2010%20Tested-dc2626)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-3a63ff)
![Free](https://img.shields.io/badge/Cost-100%25%20Free-3151e0)

**Live Demo:** [your-vercel-url.vercel.app]

---

## The Problem This Solves

Every SOC analyst manually checks 5+ threat databases for every suspicious IOC — copy-pasting the same IP or domain into AbuseIPDB, VirusTotal, AlienVault OTX, URLhaus, one by one. That's 30+ minutes per investigation, multiplied by hundreds of alerts per day.

Enterprise Threat Intelligence Platforms (TIPs) like ThreatConnect and Anomali automate this — at $100,000+/year.

ThreatLens does the same thing for free.

---

## What It Does

1. Paste any IOC — IP address, domain, URL, MD5 or SHA256 hash
2. Auto-detects the IOC type using regex pattern matching
3. Queries 5 free threat intelligence sources **simultaneously** (Promise.all — not sequentially)
4. AI synthesizes all results including resolving conflicts between sources
5. Returns: Threat Score (0–100), Risk Level, MITRE ATT&CK techniques, geographic info, recommended action
6. Downloadable HTML incident report for Jira/ticket workflows
7. **Light / Dark mode toggle** — preference saved across sessions

---

## Tech Stack

| Layer        | Technology                                                 | Why                                                                               |
| ------------ | ---------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Frontend     | React + Vite                                               | Fast SPA with a Cyber Navy & Cobalt dashboard aesthetic, light/dark theme support |
| Backend      | Node.js + Express                                          | Lightweight REST API with parallel API orchestration                              |
| AI Engine    | Llama 3.3 70B via Groq                                     | Free tier, JSON mode, excellent reasoning for threat synthesis                    |
| Threat Intel | AbuseIPDB + VirusTotal + AlienVault OTX + URLhaus + IPInfo | 5 complementary free sources covering all IOC types                               |
| Security     | Helmet + express-rate-limit                                | OWASP-aligned headers and quota protection                                        |
| Deployment   | Vercel (frontend) + Render (backend)                       | Free CI/CD pipeline                                                               |

---

## Design

ThreatLens uses a **Cyber Navy & Cobalt** visual identity — deep navy-black backgrounds with a saturated cobalt-blue brand accent, Space Grotesk + IBM Plex Mono typography, and severity colors (red/orange/amber/green) reserved exclusively for risk levels so they always stand out against the neutral chrome.

A theme toggle in the header switches between dark mode (default) and a clean light mode, with the choice persisted in `localStorage`.

---

## IOC Types Supported

| Type         | Detection                           | Sources Queried                                            |
| ------------ | ----------------------------------- | ---------------------------------------------------------- |
| IPv4 Address | Regex: `(\d{1,3}\.){3}\d{1,3}`      | AbuseIPDB + VirusTotal + AlienVault OTX + IPInfo + URLhaus |
| Domain       | Valid hostname format               | VirusTotal + AlienVault OTX + URLhaus                      |
| URL          | Starts with `http://` or `https://` | URLhaus + VirusTotal + AlienVault OTX                      |
| MD5 Hash     | 32 hex characters                   | VirusTotal + AlienVault OTX + URLhaus                      |
| SHA256 Hash  | 64 hex characters                   | VirusTotal + AlienVault OTX + URLhaus                      |

---

## Project Structure

```
threatlens/
├── backend/
│   ├── index.js          ← Express server — IOC detection, parallel API calls, Groq synthesis
│   ├── package.json
│   └── .env.example      ← Copy to .env and add all 5 API keys
├── frontend/
│   ├── src/
│   │   ├── App.jsx                     ← Main state + theme toggle + search history
│   │   ├── App.css                     ← Cyber Navy & Cobalt theme — light/dark CSS variables
│   │   ├── components/
│   │   │   ├── IOCInput.jsx            ← Input with live IOC type detection badge
│   │   │   ├── ScanningLoader.jsx      ← Radar animation + terminal step messages
│   │   │   ├── ThreatReport.jsx        ← Full results dashboard + geo + MITRE
│   │   │   ├── ThreatScore.jsx         ← Animated SVG score circle
│   │   │   └── SourceResults.jsx       ← Per-source breakdown cards
│   │   └── utils/
│   │       └── reportGenerator.js      ← Downloadable HTML incident report
│   ├── index.html
│   ├── .env.example
│   └── vite.config.js
├── .gitignore
└── README.md
```

---

## Quick Start

### Step 1 — Get all 5 free API keys

| API            | Sign up at                         | Free limit       |
| -------------- | ---------------------------------- | ---------------- |
| AbuseIPDB      | abuseipdb.com → Account → API      | 1,000 checks/day |
| AlienVault OTX | otx.alienvault.com                 | Unlimited        |
| VirusTotal     | virustotal.com → Profile → API key | 500 lookups/day  |
| IPInfo         | ipinfo.io → Get API Token          | 50,000/month     |
| Groq           | console.groq.com                   | 14,400/day       |
| URLhaus        | No key needed                      | Unlimited        |

### Step 2 — Run the backend

```bash
cd threatlens/backend
npm install
cp .env.example .env
# Open .env and paste all 5 API keys
node index.js
```

The startup banner shows ✅ or ❌ for each key configured.

### Step 3 — Run the frontend

```bash
cd threatlens/frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Use the toggle switch in the top-right of the header to preview light mode.

### Step 4 — Test with known-bad IOCs

```
IP (Tor exit node):    185.220.101.45
Domain:                malware-delivery.ru
Hash (WannaCry):       84c82835a5d21bbcf75a61706d8ab549
```

---

## Architecture

```
User Input (IOC)
      │
      ▼
Auto-detect type (IP / Domain / URL / MD5 / SHA256)
      │
      ▼
SSRF Validation (block private IP ranges)
      │
      ▼
Promise.all — parallel queries:
  ├── AbuseIPDB API
  ├── AlienVault OTX API
  ├── VirusTotal API v3
  ├── URLhaus API
  └── IPInfo API
      │
      ▼
Groq AI (Llama 3.3 70B)
  → Synthesize conflicts
  → Assign threat score
  → Map to MITRE ATT&CK
  → Write analyst narrative
      │
      ▼
React Dashboard (Cyber Navy & Cobalt theme, light/dark toggle)
  → Animated threat score circle
  → Source breakdown cards
  → MITRE technique pills (clickable → attack.mitre.org)
  → Geographic info + Tor/VPN flags
  → Downloadable incident report
```

---

## Key Engineering Decisions

**Why Promise.all instead of sequential API calls?**
All 5 APIs run simultaneously. Total response time = slowest single API (~2-3s), not sum of all APIs (~10-15s). This is the same pattern enterprise TIPs use for performance.

**Why does the AI synthesis matter?**
Sources frequently disagree. An IP might be clean on VirusTotal (malware removed) but have 500 AbuseIPDB reports (still actively abusing). Raw tools show the conflict. The AI explains WHY the conflict exists and gives a single correct verdict — exactly what a Tier 2 analyst does manually.

**How is SSRF prevented?**
The backend validates all IOCs before making any API calls. Private IP ranges (10.x.x.x, 192.168.x.x, 127.x.x.x, 169.254.x.x) are blocked. This prevents attackers from using ThreatLens to probe internal infrastructure (OWASP A10).

**Why a separate theme system instead of a CSS framework?**
All colors are defined as CSS custom properties under `[data-theme="dark"]` and `[data-theme="light"]` selectors. Components reference `var(--accent)`, `var(--bg-card)`, etc. — never hardcoded hex values — so switching themes requires zero component logic, only flipping the `data-theme` attribute on `<html>`.

---

## Security Testing — OWASP Top 10

> Tested using the same manual methodology as InsightGuard — Burp Suite, custom payloads, npm audit, and DevTools inspection. Re-verify against your own deployed instance before treating this as a final audit.

| Category                    | Status  | Notes                                                                                                                                                                                                                                         |
| --------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A01 — Broken Access Control | ✅ PASS | Origin-based validation blocks any request without an authorized `Origin` header — tested via `curl` from both Windows and Kali with no `-H "Origin: ..."`, returns `403 UNAUTHORIZED_ORIGIN`. Rate limiting (10 req/min) adds a second layer |

| A02 — Cryptographic Failures | ✅ PASS | Confirmed zero key strings in `frontend/dist` build output (`grep`/`findstr`) and `.env` never appears in git history (`git log --all --full-history -- "**/.env"`). Deliberately avoided a client-side `X-API-Key` header — any header sent from the browser is visible in DevTools → Network regardless of CORS config, so it provides no real protection once deployed |
| A03 — Injection | ✅ PASS | IOC validated by regex before any API call |
| A05 — Security Misconfiguration | ✅ PASS | Helmet sets 14 secure headers |
| A07 — Rate Limiting | ✅ PASS | 10 req/min per IP via express-rate-limit |
| A09 — Logging | ✅ PASS | All requests logged with timestamp and IP |
| A10 — SSRF | ✅ PASS | Private IP ranges blocked from submission |

---

**Why origin-based access control instead of an API key?**
A client-side API key looks like authentication but isn't — any value sent from browser JavaScript is visible to anyone via DevTools → Network, no matter what CORS settings restrict it server-side. Instead, `/api/analyze` checks the `Origin` header against an allowlist of deployed frontend URLs. Browsers attach this header automatically and a normal page can't forge it, which blocks casual scraping and quota abuse — the actual threat model here, since there's no per-user data to protect, only a shared API quota. It is not equivalent to real authentication (a determined attacker can still spoof `Origin` with `curl`), and that tradeoff is intentional and documented rather than hidden.

## Deployment (Both Free)

### Backend — Render

1. Push to GitHub
2. render.com → New Web Service → Connect repo
3. Root: `backend` | Start: `node index.js`
4. Add environment variables: `ABUSEIPDB_KEY`, `OTX_KEY`, `VT_KEY`, `IPINFO_KEY`, `GROQ_KEY`, `NODE_ENV=production`, `FRONTEND_URL=<vercel url>`

### Frontend — Vercel

1. vercel.com → New Project → Import repo
2. Root: `frontend`
3. Add `VITE_API_URL=<render backend url>`

---

## Future Enhancements

- [ ] Bulk IOC upload (CSV with 100s of IPs from firewall logs)
- [ ] Redis caching — same IOC shouldn't re-query all sources for 1 hour
- [ ] SIEM webhook integration (Splunk, Microsoft Sentinel)
- [ ] Historical tracking — has this IOC's score changed over time?
- [ ] Shodan integration for port/service fingerprinting

---

_Llama 3.3 70B inference by Groq · MITRE ATT&CK® is a registered trademark of The MITRE Corporation_
_Sources: AbuseIPDB · VirusTotal · AlienVault OTX · URLhaus · IPInfo_
