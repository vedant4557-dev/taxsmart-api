const express = require('express');
const multer = require('multer');
const cors = require('cors');
const helmet = require('helmet');
const { rateLimit: expressRateLimit } = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ── Security headers ─────────────────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://www.googletagmanager.com", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "https://taxsmart-api.onrender.com", "https://generativelanguage.googleapis.com", "https://api.anthropic.com", "https://www.google-analytics.com"],
      imgSrc: ["'self'", "data:", "https://www.google-analytics.com"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
    }
  }
}));

// ── CORS — env var for custom domain support ─────────────────────────────────
// To add a custom domain: set ALLOWED_ORIGINS=https://taxsmart.in on Render
const defaultOrigins = ['https://vedant4557-dev.github.io', 'http://localhost:3000', 'http://127.0.0.1:5500'];
const envOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()) : [];
const allowedOrigins = [...new Set([...defaultOrigins, ...envOrigins])];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.some(o => origin.startsWith(o))) {
      cb(null, true);
    } else {
      slog(null, 'warn', 'cors_blocked', { origin });
      cb(new Error('Not allowed by CORS'));
    }
  }
}));

app.use(express.json({ limit: '1mb' }));

// ── Structured logging middleware ────────────────────────────────────────────
// Every request gets a UUID — all downstream logs include reqId for correlation
app.use((req, res, next) => {
  req.id = crypto.randomUUID();
  req.startTime = Date.now();
  const rawIp = req.ip || req.connection?.remoteAddress || 'unknown';
  // Mask last octet for privacy
  req.maskedIp = rawIp.replace(/(\d+)$/, '***').replace(/([a-f0-9]+)$/i, '***');
  next();
});

function slog(req, level, event, data = {}) {
  const entry = {
    ts: new Date().toISOString(),
    reqId: req?.id || 'system',
    ip: req?.maskedIp || '-',
    level,   // info | warn | error
    event,   // extraction_start | extraction_ok | extraction_fail | cache_hit | cb_open | quota_hit
    duration_ms: req ? Date.now() - (req.startTime || Date.now()) : 0,
    ...data
  };
  // Use console.error for warn/error so they appear in Render error stream
  if (level === 'error' || level === 'warn') {
    console.error(JSON.stringify(entry));
  } else {
    console.log(JSON.stringify(entry));
  }
}

// ── In-memory SHA256 extraction cache ────────────────────────────────────────
// Same PDF re-uploaded → instant return, zero Gemini calls
const extractionCache = new Map();
const CACHE_MAX = 200;
const CACHE_TTL = 4 * 60 * 60 * 1000; // 4 hours

function getCacheKey(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

function cacheGet(hash) {
  const e = extractionCache.get(hash);
  if (!e) return null;
  if (Date.now() - e.ts > CACHE_TTL) { extractionCache.delete(hash); return null; }
  return e.data;
}

function cacheSet(hash, data) {
  if (extractionCache.size >= CACHE_MAX) extractionCache.delete(extractionCache.keys().next().value);
  extractionCache.set(hash, { data, ts: Date.now() });
}

// ── Daily cost guardrail ─────────────────────────────────────────────────────
// Hard cap: Gemini free tier is 1500/day. Cap at DAILY_QUOTA_MAX (default 1400).
// If someone uploads 15MB × 3 docs × 10 times: 30 calls. Cap protects against abuse.
const dailyQuota = {
  count: 0,
  date: new Date().toISOString().split('T')[0],
  MAX: parseInt(process.env.DAILY_QUOTA_MAX || '1400'),
  check() {
    const today = new Date().toISOString().split('T')[0];
    if (today !== this.date) {
      slog(null, 'info', 'quota_reset', { prev_count: this.count, new_date: today });
      this.count = 0;
      this.date = today;
    }
    if (this.count >= this.MAX) return false;
    this.count++;
    return true;
  },
  remaining() { return Math.max(0, this.MAX - this.count); }
};

// ── Circuit breaker ──────────────────────────────────────────────────────────
// 5 consecutive failures → open for 60s → stops hammering Gemini when it's down
const circuitBreaker = {
  failures: 0,
  openUntil: 0,
  MAX: 5,
  COOLDOWN: 60_000,
  isOpen() { return this.failures >= this.MAX && Date.now() < this.openUntil; },
  success() { if (this.failures > 0) { this.failures = 0; slog(null, 'info', 'cb_closed'); } },
  fail(req) {
    this.failures++;
    if (this.failures >= this.MAX) {
      this.openUntil = Date.now() + this.COOLDOWN;
      slog(req, 'warn', 'cb_open', { until: new Date(this.openUntil).toISOString() });
    }
  }
};

// ── File upload ──────────────────────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Only PDF files allowed'));
  }
});

// ── Rate limiting ────────────────────────────────────────────────────────────
const rateLimit = expressRateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Try again in an hour.' },
  keyGenerator: (req) => req.ip || 'unknown',
});

// ── Helpers ──────────────────────────────────────────────────────────────────
function validatePDF(buffer, name) {
  if (buffer.slice(0, 5).toString('ascii') !== '%PDF-')
    throw new Error(`${name} is not a valid PDF file`);
}

// AbortController with timeout — wraps any async fn with a deadline
async function withTimeout(fn, ms, label) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fn(ctrl.signal);
  } catch (e) {
    if (e.name === 'AbortError') throw new Error(`${label} timed out after ${ms/1000}s`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// ── Prompts (compact — reduce input tokens) ──────────────────────────────────
const PROMPT_F16 = `Extract Form 16 data. Return ONLY valid JSON:
{"name":"","pan":"","employer_name":"","gross_salary":0,"basic_salary":0,"hra_received":0,"special_allowance":0,"prof_tax":0,"epf_employee":0,"epf_employer":0,"sec80c":0,"nps":0,"employer_nps":0,"sec80d_self":0,"home_loan_interest":0,"sec80e":0,"standard_deduction":50000,"tds_deducted_form16":0,"total_income_form16":0,"taxable_income_form16":0}
Rules: gross_salary=total before deductions. tds_deducted_form16=total TDS in Part A. 0 for missing.`;

const PROMPT_26AS = `Extract Form 26AS data. Return ONLY valid JSON:
{"pan":"","tds_entries":[{"deductor":"","amount":0,"tds":0,"pan_deductor":""}],"total_tds_26as":0,"advance_tax":0,"self_assessment_tax":0,"salary_income_26as":0,"interest_income_26as":0}
Rules: total_tds_26as=sum of ALL TDS. 0 for missing.`;

const PROMPT_AIS = `Extract AIS data. Return ONLY valid JSON:
{"pan":"","salary_ais":0,"interest_income_ais":0,"dividend_ais":0,"rental_income_ais":0,"ltcg_ais":0,"stcg_ais":0,"mf_transactions":0,"foreign_income":0,"tds_total_ais":0}
Rules: interest_income_ais=savings+FD+bonds total. 0 for missing.`;

// ── Schema sanitization ───────────────────────────────────────────────────────
// Coerces "1,50,000" strings to numbers, clamps negatives to 0
const STRING_FIELDS = new Set(['name', 'pan', 'employer_name', 'deductor', 'pan_deductor']);
function sanitize(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k === 'tds_entries' && Array.isArray(v)) out[k] = v.map(sanitize);
    else if (typeof v === 'string' && !STRING_FIELDS.has(k)) {
      const n = parseFloat(v.replace(/,/g, ''));
      out[k] = isNaN(n) ? v : Math.max(0, n);
    } else if (typeof v === 'number') out[k] = Math.max(0, v);
    else out[k] = v;
  }
  return out;
}

// Shape check — fill missing required fields with 0 rather than crashing
const REQUIRED = { f16: ['gross_salary','tds_deducted_form16'], as26: ['total_tds_26as'], ais: ['salary_ais'] };
function checkShape(data, type) {
  (REQUIRED[type] || []).filter(k => !(k in data)).forEach(k => { data[k] = 0; });
  return data;
}

// Parse Gemini response text to JSON
function parseGeminiJSON(text) {
  let clean = text.replace(/```json/g, '').replace(/```/g, '').trim();
  const s = clean.indexOf('{'), e = clean.lastIndexOf('}');
  if (s !== -1 && e !== -1) clean = clean.substring(s, e + 1);
  return sanitize(JSON.parse(clean));
}

// ── Gemini API calls ─────────────────────────────────────────────────────────

// Pass 1: extract raw text from PDF (cheap, fast)
async function extractText(base64Pdf) {
  const key = process.env.GEMINI_API_KEY;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${key}`;

  return withTimeout(async (signal) => {
    const res = await fetch(url, {
      method: 'POST', signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [
          { inline_data: { mime_type: 'application/pdf', data: base64Pdf } },
          { text: 'Extract all text exactly as it appears. Output only raw text, no commentary.' }
        ]}],
        generationConfig: { temperature: 0, maxOutputTokens: 16384 }
      })
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d?.error?.message || 'Text extraction failed');
    return d.candidates?.[0]?.content?.parts?.[0]?.text || '';
  }, 25_000, 'PDF text extraction');
}

// Pass 2: structured JSON from text (much cheaper than raw PDF)
async function extractStructured(text, prompt) {
  const key = process.env.GEMINI_API_KEY;
  const MODELS = ['gemini-2.0-flash', 'gemini-2.5-flash'];
  let lastErr;

  for (const model of MODELS) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;
    try {
      const result = await withTimeout(async (signal) => {
        const res = await fetch(url, {
          method: 'POST', signal,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: `${prompt}\n\nDOCUMENT TEXT:\n${text.substring(0, 30000)}` }] }],
            generationConfig: { temperature: 0, maxOutputTokens: 2048 }
          })
        });
        const d = await res.json();
        if (res.status === 429) {
          const msg = d?.error?.message || '';
          const m = msg.match(/(\d+\.?\d*)\s*second/i);
          const wait = m ? Math.min(parseFloat(m[1]) + 1, 20) : 8;
          await sleep(wait * 1000);
          throw new Error('quota_retry');
        }
        if (!res.ok) throw new Error(d?.error?.message || `HTTP ${res.status}`);
        const txt = d.candidates?.[0]?.content?.parts?.[0]?.text || '';
        if (!txt) throw new Error('empty_response');
        return parseGeminiJSON(txt);
      }, 20_000, `${model} structured extraction`);

      return result;
    } catch (e) {
      lastErr = e;
      continue;
    }
  }
  throw lastErr || new Error('All models failed');
}

// Fallback: send raw PDF directly (for scanned/image PDFs)
async function extractDirect(base64Pdf, prompt) {
  const key = process.env.GEMINI_API_KEY;
  const MODELS = ['gemini-2.0-flash', 'gemini-2.5-flash'];
  let lastErr;

  for (const model of MODELS) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;
    try {
      const result = await withTimeout(async (signal) => {
        const res = await fetch(url, {
          method: 'POST', signal,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [
              { inline_data: { mime_type: 'application/pdf', data: base64Pdf } },
              { text: prompt }
            ]}],
            generationConfig: { temperature: 0, maxOutputTokens: 4096 }
          })
        });
        const d = await res.json();
        if (res.status === 429) {
          const attempt = MODELS.indexOf(model);
          await sleep(Math.min(5 * Math.pow(2, attempt), 30) * 1000);
          throw new Error('quota_retry');
        }
        if (!res.ok) throw new Error(d?.error?.message || `HTTP ${res.status}`);
        const txt = d.candidates?.[0]?.content?.parts?.[0]?.text || '';
        if (!txt) throw new Error('empty_response');
        return parseGeminiJSON(txt);
      }, 30_000, `${model} direct extraction`);

      return result;
    } catch (e) {
      lastErr = e;
      continue;
    }
  }
  throw lastErr || new Error('All models failed');
}

// ── Main extraction orchestrator ─────────────────────────────────────────────
async function callGemini(base64Pdf, prompt, originalBuffer, req) {
  // 1. Daily quota guard
  if (!dailyQuota.check()) {
    slog(req, 'warn', 'quota_hit', { remaining: 0 });
    throw new Error('Daily AI limit reached. Resets at midnight UTC. Please fill manually.');
  }

  // 2. Circuit breaker
  if (circuitBreaker.isOpen()) {
    slog(req, 'warn', 'cb_blocked');
    throw new Error('AI service temporarily down. Try again in 60 seconds or fill manually.');
  }

  // 3. Cache check
  if (originalBuffer) {
    const hash = getCacheKey(originalBuffer);
    const cached = cacheGet(hash);
    if (cached) {
      slog(req, 'info', 'cache_hit', { quota_remaining: dailyQuota.remaining() });
      return cached;
    }
  }

  // 4. Two-pass extraction (text first → structured JSON)
  try {
    const pdfText = await extractText(base64Pdf);
    slog(req, 'info', 'text_extracted', { chars: pdfText.length });

    let result;
    if (pdfText.length < 100) {
      // Scanned PDF — fall back to direct
      slog(req, 'info', 'fallback_direct', { reason: 'short_text' });
      result = await extractDirect(base64Pdf, prompt);
    } else {
      result = await extractStructured(pdfText, prompt);
    }

    if (originalBuffer) cacheSet(getCacheKey(originalBuffer), result);
    circuitBreaker.success();
    slog(req, 'info', 'extraction_success', { quota_remaining: dailyQuota.remaining() });
    return result;

  } catch (e) {
    slog(req, 'warn', 'two_pass_failed', { err: e.message });
    try {
      const result = await extractDirect(base64Pdf, prompt);
      if (originalBuffer) cacheSet(getCacheKey(originalBuffer), result);
      circuitBreaker.success();
      return result;
    } catch (e2) {
      circuitBreaker.fail(req);
      slog(req, 'error', 'extraction_failed', { err: e2.message, cb_failures: circuitBreaker.failures });
      throw e2;
    }
  }
}

// ── Health & ping endpoints ───────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'TaxSmart API',
    ts: new Date().toISOString(),
    uptime_s: Math.round(process.uptime()),
    cache_size: extractionCache.size,
    quota_used: dailyQuota.count,
    quota_remaining: dailyQuota.remaining(),
    circuit_breaker: circuitBreaker.isOpen() ? 'OPEN' : 'CLOSED',
    cb_failures: circuitBreaker.failures
  });
});

app.get('/ping', (req, res) => res.json({ pong: true, ts: Date.now() }));

// ── Main extraction endpoint ─────────────────────────────────────────────────
app.post('/extract', rateLimit, upload.fields([
  { name: 'f16', maxCount: 1 },
  { name: 'as26', maxCount: 1 },
  { name: 'ais', maxCount: 1 }
]), async (req, res) => {
  if (!process.env.GEMINI_API_KEY)
    return res.status(500).json({ error: 'Server not configured.' });

  const files = req.files || {};
  if (!files.f16 && !files.as26 && !files.ais)
    return res.status(400).json({ error: 'Upload at least one document.' });

  slog(req, 'info', 'request_start', {
    docs: Object.keys(files).join(','),
    quota_remaining: dailyQuota.remaining()
  });

  const out = { f16Data: {}, as26Data: {}, aisData: {}, errors: [], warnings: [] };

  // Extract Form 16
  if (files.f16) {
    try {
      validatePDF(files.f16[0].buffer, 'Form 16');
      slog(req, 'info', 'extraction_start', { doc: 'f16', size: files.f16[0].size });
      const b64 = files.f16[0].buffer.toString('base64');
      out.f16Data = checkShape(await callGemini(b64, PROMPT_F16, files.f16[0].buffer, req), 'f16');
      slog(req, 'info', 'extraction_ok', { doc: 'f16', fields: Object.keys(out.f16Data).length });
    } catch (e) {
      slog(req, 'error', 'extraction_fail', { doc: 'f16', err: e.message });
      out.warnings.push({ doc: 'Form 16', msg: e.message });
    }
    await sleep(2000); // small gap between docs
  }

  // Extract Form 26AS
  if (files.as26) {
    try {
      validatePDF(files.as26[0].buffer, 'Form 26AS');
      slog(req, 'info', 'extraction_start', { doc: '26as', size: files.as26[0].size });
      const b64 = files.as26[0].buffer.toString('base64');
      out.as26Data = checkShape(await callGemini(b64, PROMPT_26AS, files.as26[0].buffer, req), 'as26');
      slog(req, 'info', 'extraction_ok', { doc: '26as', fields: Object.keys(out.as26Data).length });
    } catch (e) {
      slog(req, 'error', 'extraction_fail', { doc: '26as', err: e.message });
      out.warnings.push({ doc: 'Form 26AS', msg: e.message });
    }
    await sleep(2000);
  }

  // Extract AIS
  if (files.ais) {
    try {
      validatePDF(files.ais[0].buffer, 'AIS');
      slog(req, 'info', 'extraction_start', { doc: 'ais', size: files.ais[0].size });
      const b64 = files.ais[0].buffer.toString('base64');
      out.aisData = checkShape(await callGemini(b64, PROMPT_AIS, files.ais[0].buffer, req), 'ais');
      slog(req, 'info', 'extraction_ok', { doc: 'ais', fields: Object.keys(out.aisData).length });
    } catch (e) {
      slog(req, 'error', 'extraction_fail', { doc: 'ais', err: e.message });
      out.warnings.push({ doc: 'AIS', msg: e.message });
    }
  }

  out.errors = runErrorChecks(out.f16Data, out.as26Data, out.aisData);
  slog(req, 'info', 'request_done', { warnings: out.warnings.length, errors: out.errors.length });
  return res.json(out);
});

// ── Cross-document error checks ──────────────────────────────────────────────
function runErrorChecks(f16, as26, ais) {
  const errors = [];

  if (f16.tds_deducted_form16 > 0 && as26.total_tds_26as > 0) {
    const diff = Math.abs(f16.tds_deducted_form16 - as26.total_tds_26as);
    if (diff > 1000) errors.push({
      type:'crit', icon:'warning', severity:'red',
      title:'TDS Mismatch: Form 16 vs 26AS',
      desc:`Form 16 shows ${fmt(f16.tds_deducted_form16)}, 26AS shows ${fmt(as26.total_tds_26as)}. Diff: ${fmt(diff)}.`,
      action:'Contact employer HR immediately. TDS not in 26AS cannot be claimed.'
    });
  }

  if (f16.gross_salary > 0 && ais.salary_ais > 0) {
    const diff = Math.abs(f16.gross_salary - ais.salary_ais);
    if (diff > 5000) errors.push({
      type:'warn', icon:'alert', severity:'amber',
      title:'Salary Mismatch: Form 16 vs AIS',
      desc:`Form 16: ${fmt(f16.gross_salary)}, AIS: ${fmt(ais.salary_ais)}. Diff: ${fmt(diff)}.`,
      action:'AIS may include perquisites. Declare correct figure in ITR.'
    });
  }

  if (as26.tds_entries?.length > 0) {
    const missing = as26.tds_entries.filter(e => !e.pan_deductor || e.pan_deductor === 'PANNOTAVBL' || e.pan_deductor === '');
    if (missing.length > 0) errors.push({
      type:'warn', icon:'id-card', severity:'amber',
      title:`Missing PAN in ${missing.length} TDS ${missing.length > 1 ? 'Entries' : 'Entry'}`,
      desc:`${missing.length} deductor(s) have missing PAN. TDS credit may not be claimable.`,
      action:'Contact deductors to file TDS correction with their PAN.'
    });
  }

  if (ais.interest_income_ais > 0 && as26.interest_income_26as > 0) {
    const diff = Math.abs(ais.interest_income_ais - as26.interest_income_26as);
    if (diff > 2000) errors.push({
      type:'warn', icon:'money', severity:'amber',
      title:'Interest Income Discrepancy',
      desc:`AIS: ${fmt(ais.interest_income_ais)}, 26AS: ${fmt(as26.interest_income_26as)}.`,
      action:'Use the higher figure in ITR to avoid IT notice.'
    });
  }

  if ((ais.ltcg_ais > 0 || ais.stcg_ais > 0) && (ais.ltcg_ais + ais.stcg_ais) > 10000)
    errors.push({
      type:'info', icon:'chart', severity:'blue',
      title:'Capital Gains Found in AIS',
      desc:`LTCG: ${fmt(ais.ltcg_ais||0)}, STCG: ${fmt(ais.stcg_ais||0)}. Auto-filled.`,
      action:"Cross-check with broker's P&L before filing."
    });

  if (ais.dividend_ais > 5000)
    errors.push({
      type:'info', icon:'building', severity:'blue',
      title:'Dividend Income Detected',
      desc:`AIS shows ${fmt(ais.dividend_ais)} dividend. Fully taxable since FY 2020-21.`,
      action:'Declare under Income from Other Sources.'
    });

  return errors;
}

function fmt(n) {
  if (!n) return '₹0';
  n = Math.round(n);
  if (n >= 10000000) return '₹' + (n/10000000).toFixed(1) + ' Cr';
  if (n >= 100000) return '₹' + (n/100000).toFixed(1) + ' L';
  const s = n.toString();
  if (s.length <= 3) return '₹' + s;
  let r = s.slice(-3), rem = s.slice(0, -3);
  while (rem.length > 2) { r = rem.slice(-2) + ',' + r; rem = rem.slice(0, -2); }
  return '₹' + rem + ',' + r;
}

app.listen(PORT, () => {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event: 'server_start', port: PORT }));
  if (!process.env.GEMINI_API_KEY)
    console.error(JSON.stringify({ ts: new Date().toISOString(), event: 'config_error', msg: 'GEMINI_API_KEY not set' }));
});
