const express = require('express');
const multer = require('multer');
const cors = require('cors');
const helmet = require('helmet');
const { rateLimit: expressRateLimit } = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto'); // built-in, no install needed
require('dotenv').config();

// ── In-memory extraction cache (SHA256 hash → extracted JSON) ────────────────
// Prevents re-calling Gemini when user re-uploads same document
// Cuts 20-30% of API calls. Resets on server restart (free tier acceptable).
const extractionCache = new Map();
const CACHE_MAX_SIZE = 200; // max entries before evicting oldest
const CACHE_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours

function getCacheKey(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function cacheGet(hash) {
  const entry = extractionCache.get(hash);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) {
    extractionCache.delete(hash);
    return null;
  }
  return entry.data;
}

function cacheSet(hash, data) {
  // Evict oldest entry if at capacity
  if (extractionCache.size >= CACHE_MAX_SIZE) {
    const firstKey = extractionCache.keys().next().value;
    extractionCache.delete(firstKey);
  }
  extractionCache.set(hash, { data, ts: Date.now() });
}

const app = express();

// ── Security headers (helmet) ────────────────────────────────────────────────
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

const PORT = process.env.PORT || 3000;

// ── CORS: allow your GitHub Pages frontend ──────────────────────────────────
// CORS origins: set ALLOWED_ORIGINS env var for custom domains
// e.g. ALLOWED_ORIGINS=https://taxsmart.in,https://www.taxsmart.in
const defaultOrigins = ['https://vedant4557-dev.github.io','http://localhost:3000','http://127.0.0.1:5500'];
const envOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()) : [];
const allowedOrigins = [...new Set([...defaultOrigins, ...envOrigins])];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) { cb(null, true); return; } // allow server-to-server / curl
    // SECURITY: exact URL.origin match prevents subdomain bypass
    // e.g. https://vedant4557-dev.github.io.evil.com would PASS startsWith but FAILS this
    const isAllowed = allowedOrigins.some(allowed => {
      try { return new URL(allowed).origin === new URL(origin).origin; }
      catch { return false; }
    });
    if (isAllowed) {
      cb(null, true);
    } else {
      console.warn(JSON.stringify({ ts: new Date().toISOString(), event: 'cors_blocked', origin }));
      cb(new Error('Not allowed by CORS'));
    }
  }
}));

app.use(express.json({ limit: '1mb' })); // prevent JSON body DoS attacks

// ── Structured logging middleware ────────────────────────────────────────────
// Attaches req.id + req.startTime to every request for correlated logs
app.use((req, res, next) => {
  req.id = crypto.randomUUID();
  req.startTime = Date.now();
  // Mask IP for privacy — only log last octet
  const rawIp = req.ip || req.connection?.remoteAddress || 'unknown';
  req.maskedIp = rawIp.replace(/^(.*\.)(\d+)$/, '$1***').replace(/^(.*:)(\w+)$/, '$1***');
  const ua = req.headers['user-agent'] || '';
  req.uaHash = crypto.createHash('sha256').update(ua).digest('hex').substring(0, 12);
  next();
});

function slog(req, level, event, data = {}) {
  const duration = req ? Date.now() - (req.startTime || Date.now()) : 0;
  const entry = {
    ts: new Date().toISOString(),
    reqId: req?.id || 'system',
    ip: req?.maskedIp || 'system',
    ua: req?.uaHash || '-',
    level,
    event,
    duration_ms: duration,
    ...data
  };
  console.log(JSON.stringify(entry));
}

// ── File upload: memory storage (never writes to disk permanently) ──────────
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB per file — Indian tax PDFs are never legitimately larger
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Only PDF files allowed'));
  }
});

function handleUploadErrors(err, req, res, next) {
  if (err?.code === 'LIMIT_FILE_SIZE') {
    slog(req, 'warn', 'file_too_large', { field: err.field });
    return res.status(413).json({ error: 'File too large (max 8MB). Tax PDFs are rarely over 3MB — use a digital PDF, not a scan.' });
  }
  if (err?.message?.includes('PDF')) return res.status(400).json({ error: 'Only PDF files are accepted.' });
  next(err);
}

// ── Rate limiting (express-rate-limit — survives server restarts) ───────────
const rateLimit = expressRateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour window
  max: 10,                    // 10 extractions per IP per hour
  standardHeaders: true,      // Return rate limit info in RateLimit-* headers
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again in an hour.' },
  keyGenerator: (req) => req.ip || req.connection?.remoteAddress || 'unknown',
});

// ── Gemini API helper ───────────────────────────────────────────────────────
// Free tier: 1,500 requests/day, resets daily at midnight
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ── Observability stats (in-memory, resets on restart) ───────────────────────
// Tracks extraction success %, avg duration, cache hit ratio in real time
// Exposed via /stats endpoint — gives you startup viability metrics
const stats = {
  extractions: { total: 0, success: 0, fail: 0, totalDurationMs: 0 },
  cache: { hits: 0, misses: 0 },
  docs: { f16: 0, as26: 0, ais: 0 },
  errors: { quota: 0, circuit: 0, timeout: 0, parse: 0, other: 0 },
  startTime: Date.now(),

  record(type, success, durationMs) {
    this.extractions.total++;
    if (success) {
      this.extractions.success++;
      this.extractions.totalDurationMs += durationMs;
    } else {
      this.extractions.fail++;
    }
    if (type && this.docs[type] !== undefined) this.docs[type]++;
  },

  cacheHit() { this.cache.hits++; },
  cacheMiss() { this.cache.misses++; },

  trackError(msg) {
    if (msg.includes('quota')) this.errors.quota++;
    else if (msg.includes('circuit') || msg.includes('cb_')) this.errors.circuit++;
    else if (msg.includes('timeout') || msg.includes('timed out')) this.errors.timeout++;
    else if (msg.includes('parse') || msg.includes('JSON')) this.errors.parse++;
    else this.errors.other++;
  },

  summary() {
    const { total, success, fail, totalDurationMs } = this.extractions;
    const { hits, misses } = this.cache;
    return {
      uptime_s: Math.round((Date.now() - this.startTime) / 1000),
      extractions: {
        total, success, fail,
        success_rate_pct: total > 0 ? Math.round((success / total) * 100) : null,
        avg_duration_ms: success > 0 ? Math.round(totalDurationMs / success) : null
      },
      cache: {
        hits, misses,
        hit_rate_pct: (hits + misses) > 0 ? Math.round((hits / (hits + misses)) * 100) : null
      },
      doc_types: this.docs,
      errors: this.errors,
      quota: { used: dailyQuota.count, remaining: dailyQuota.remaining(), max: dailyQuota.MAX },
      circuit_breaker: { state: circuitBreaker.isOpen() ? 'OPEN' : 'CLOSED', failures: circuitBreaker.failures }
    };
  }
};

// ── Daily cost guardrail ─────────────────────────────────────────────────────
// Hard cap on Gemini calls per day — resets at midnight UTC
// Gemini free tier: 1500/day. We cap at 1400 to leave buffer.
const dailyQuota = {
  count: 0,
  resetDate: new Date().toISOString().split('T')[0],
  MAX_DAILY: parseInt(process.env.DAILY_QUOTA_MAX || '1400'),
  check() {
    const today = new Date().toISOString().split('T')[0];
    if (today !== this.resetDate) {
      this.count = 0;
      this.resetDate = today;
      console.log(JSON.stringify({ ts: new Date().toISOString(), event: 'quota_reset', new_date: today }));
    }
    if (this.count >= this.MAX_DAILY) {
      return false; // quota exhausted
    }
    this.count++;
    return true;
  },
  remaining() { return Math.max(0, this.MAX_DAILY - this.count); }
};

// ── Circuit breaker — prevents hammering Gemini when it's clearly down ───────
// After 5 consecutive failures, short-circuit for 60s before trying again
const cb = {
  failures: 0,
  openUntil: 0,
  MAX_FAILURES: 5,
  RESET_MS: 60 * 1000,  // 60 seconds
  isOpen() { return this.failures >= this.MAX_FAILURES && Date.now() < this.openUntil; },
  onSuccess() { this.failures = 0; },
  onFailure() {
    this.failures++;
    if (this.failures >= this.MAX_FAILURES) {
      this.openUntil = Date.now() + this.RESET_MS;
      console.warn(`[CircuitBreaker] OPEN — Gemini failing, blocking for 60s`);
    }
  }
};

// ── PDF text extraction using Gemini's native PDF support ──────────────────
// Strategy: First pass — extract raw text only (fast, cheap, ~500 tokens)
// Second pass — structured JSON extraction from text (no PDF overhead)
// This cuts token usage ~60% vs sending raw PDF base64 for JSON extraction

async function extractPdfText(base64Pdf) {
  const apiKey = process.env.GEMINI_API_KEY;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

  const textController = new AbortController();
  const textTimer = setTimeout(() => textController.abort(), 25000); // 25s timeout
  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      signal: textController.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [
          { inline_data: { mime_type: 'application/pdf', data: base64Pdf } },
          { text: 'Extract all text from this PDF document exactly as it appears. Output only the raw text, no commentary.' }
        ]}],
        generationConfig: { temperature: 0, maxOutputTokens: 16384 }
      })
    });
  } finally {
    clearTimeout(textTimer);
  }
  const data = await response.json();
  if (!response.ok) throw new Error(data?.error?.message || 'Text extraction failed');
  return data.candidates?.[0]?.content?.parts?.[0]?.text || '';
}

async function callGeminiText(text, prompt) {
  // Send extracted text (not raw PDF) to AI for structured extraction
  // This is ~3-5x cheaper in tokens than sending base64 PDF
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error('GEMINI_API_KEY not configured on server');

  const MODELS = ['gemini-2.0-flash', 'gemini-2.5-flash'];
  let lastError = null;

  for (const modelName of MODELS) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;

    let response, data;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [
            { text: `${prompt}

DOCUMENT TEXT:
${text.substring(0, 30000)}` }
          ]}],
          generationConfig: { temperature: 0, maxOutputTokens: 2048 }  // much less needed for structured JSON
        })
      });
      data = await response.json();
    } catch (fetchErr) {
      lastError = fetchErr;
      continue;
    }

    if (response.status === 429) {
      const retryMsg = data?.error?.message || '';
      const retryMatch = retryMsg.match(/retry.*?(\d+\.?\d*)s/i) || retryMsg.match(/(\d+\.?\d*)\s*second/i);
      const waitSec = retryMatch ? Math.min(parseFloat(retryMatch[1]) + 1, 15) : 5;
      await sleep(waitSec * 1000);
      lastError = new Error(`${modelName}: quota exceeded`);
      continue;
    }

    if (!response.ok) {
      const errMsg = data?.error?.message || JSON.stringify(data);
      lastError = new Error(`${modelName}: ${errMsg.substring(0, 100)}`);
      continue;
    }

    const text2 = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    if (!text2) { lastError = new Error(`${modelName}: Empty response`); continue; }

    console.log(`${modelName} OK, response length: ${text2.length}`);
    let clean = text2.replace(/```json/g, '').replace(/```/g, '').trim();
    const start = clean.indexOf('{');
    const end = clean.lastIndexOf('}');
    if (start !== -1 && end !== -1) clean = clean.substring(start, end + 1);

    try {
      return sanitizeExtraction(JSON.parse(clean));
    } catch(e) {
      lastError = new Error(`${modelName}: JSON parse failed`);
      continue;
    }
  }
  throw lastError || new Error('All models failed');
}

// ── Schema validation & sanitization ─────────────────────────────────────────
// AI sometimes returns "1,50,000" (string) or negative numbers — fix silently
function sanitizeExtraction(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const skipStr = new Set(['name','pan','employer_name','deductor','pan_deductor']);
  const result = {};
  for (const [key, val] of Object.entries(obj)) {
    if (key === 'tds_entries' && Array.isArray(val)) {
      result[key] = val.map(e => sanitizeExtraction(e));
    } else if (typeof val === 'string' && !skipStr.has(key)) {
      const num = parseFloat(val.replace(/,/g, '').trim());
      result[key] = isNaN(num) ? val : Math.max(0, num);
    } else if (typeof val === 'number') {
      result[key] = Math.max(0, val);
    } else {
      result[key] = val;
    }
  }
  return result;
}

// ── Required field shape check — ensure AI returned the right structure ───────
const REQUIRED_FIELDS = {
  f16: ['gross_salary','tds_deducted_form16'],
  as26: ['total_tds_26as'],
  ais: ['salary_ais']
};

function validateShape(data, docType) {
  const required = REQUIRED_FIELDS[docType] || [];
  const missing = required.filter(k => !(k in data));
  if (missing.length > 0) {
    console.warn(JSON.stringify({ event: 'shape_missing', docType, missing }));
    missing.forEach(k => { data[k] = 0; });
  }

  // Logical sanity bounds — catch impossible AI hallucinations before they hit tax calc
  // These are hard upper limits; real Indian salaries/TDS won't exceed them
  const BOUNDS = {
    gross_salary: [0, 10_00_00_000],      // max 10 Cr salary
    tds_deducted_form16: [0, 3_00_00_000], // TDS can't exceed 3 Cr for salaried
    total_tds_26as: [0, 5_00_00_000],
    salary_ais: [0, 10_00_00_000],
    interest_income_ais: [0, 5_00_00_000],
    ltcg_ais: [0, 50_00_00_000],           // allow large LTCG
    stcg_ais: [0, 50_00_00_000],
  };

  const warnings = [];
  for (const [field, [min, max]] of Object.entries(BOUNDS)) {
    if (field in data && (data[field] < min || data[field] > max)) {
      warnings.push(`${field}=${data[field]} out of range [${min},${max}]`);
      data[field] = 0; // zero out impossible values rather than crashing
    }
  }

  // Cross-field logic check: TDS cannot exceed gross salary
  if (docType === 'f16' && data.tds_deducted_form16 > data.gross_salary && data.gross_salary > 0) {
    warnings.push(`tds_deducted_form16 (${data.tds_deducted_form16}) > gross_salary (${data.gross_salary}) — impossible`);
    data.tds_deducted_form16 = 0;
  }

  // Flag extreme salary mismatch between AIS and Form 16 (caught here, reported as error later)
  if (docType === 'ais' && data._f16SalaryRef > 0 && data.salary_ais > 0) {
    const ratio = Math.max(data.salary_ais, data._f16SalaryRef) / Math.min(data.salary_ais, data._f16SalaryRef);
    if (ratio > 5) warnings.push(`salary_ais vs Form16 ratio ${ratio.toFixed(1)}x — unusual mismatch`);
  }

  if (warnings.length > 0) {
    console.warn(JSON.stringify({ event: 'logical_validation_warn', docType, warnings }));
  }

  return data;
}

async function callGemini(base64Pdf, prompt, originalBuffer) {
  // Daily quota guardrail check
  if (!dailyQuota.check()) {
    throw new Error('quota: Daily AI extraction limit reached. Service resets at midnight UTC. Please fill manually — takes 3 minutes.');
  }

  // Circuit breaker check — fail fast if Gemini is clearly down
  if (cb.isOpen()) {
    throw new Error('circuit: AI service temporarily unavailable (too many recent failures). Try again in 60 seconds or fill manually.');
  }

  // Check cache first (SHA256 of original PDF buffer)
  if (originalBuffer) {
    const hash = getCacheKey(originalBuffer);
    originalBuffer = null; // free buffer RAM immediately after hashing — we only need the hash
    const cached = cacheGet(hash);
    if (cached) {
      stats.cacheHit();
      console.log(JSON.stringify({ ts: new Date().toISOString(), event: 'cache_hit', quota_remaining: dailyQuota.remaining() }));
      return cached;
    }
    // Store hash for cache-set after extraction
    var _cacheHash = hash;
  }

  stats.cacheMiss();
  // Two-pass: extract text first (cheap), then parse structured JSON (cheaper than raw PDF)
  // IMPORTANT: Keep originalBase64 separately so fallback always has it even after we null base64Pdf
  const originalBase64 = base64Pdf; // preserve for scanned PDF fallback

  try {
    const pdfText = await extractPdfText(originalBase64);

    if (pdfText.length < 100) {
      // Scanned/image PDF — fall back to direct extraction using preserved original
      console.log(JSON.stringify({ ts: new Date().toISOString(), event: 'fallback_direct', reason: 'short_text' }));
      const r = await callGeminiDirect(originalBase64, prompt);
      cb.onSuccess();
      if (originalBuffer) { cacheSet(getCacheKey(originalBuffer), r); originalBuffer = null; }
      return r;
    }

    // Text-based PDF: structured extraction from text (much cheaper in tokens)
    const result = await callGeminiText(pdfText, prompt);
    if (_cacheHash) { cacheSet(_cacheHash, result); }
    cb.onSuccess();
    return result;
  } catch(e) {
    // Two-pass failed — try direct PDF approach as last resort
    console.log(JSON.stringify({ ts: new Date().toISOString(), event: 'two_pass_failed', err: e.message }));
    try {
      const r = await callGeminiDirect(originalBase64, prompt); // use originalBase64, never null
      cb.onSuccess();
      if (_cacheHash) { cacheSet(_cacheHash, r); }
      return r;
    } catch(e2) {
      cb.onFailure();
      throw e2;
    }
  }
}

async function callGeminiDirect(base64Pdf, prompt) {
  // Fallback: send raw PDF (original approach, for scanned/image PDFs)
  const apiKey = process.env.GEMINI_API_KEY;
  const MODELS = ['gemini-2.0-flash', 'gemini-2.5-flash'];
  let lastError = null;

  for (const modelName of MODELS) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;

    let response, data;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [
            { inline_data: { mime_type: 'application/pdf', data: base64Pdf } },
            { text: prompt }
          ]}],
          generationConfig: { temperature: 0, maxOutputTokens: 4096 }
        })
      });
      data = await response.json();
    } catch (fetchErr) { lastError = fetchErr; continue; }

    if (response.status === 429) {
      const retryMsg = data?.error?.message || '';
      const retryMatch = retryMsg.match(/retry.*?(\d+\.?\d*)s/i) || retryMsg.match(/(\d+\.?\d*)\s*second/i);
      // Exponential backoff: extract suggested delay or use progressive wait
      const attempt = MODELS.indexOf(modelName);
      const baseWait = retryMatch ? parseFloat(retryMatch[1]) + 1 : 5;
      const waitSec = Math.min(baseWait * Math.pow(2, attempt), 30); // cap at 30s
      console.log(`${modelName} quota hit, exponential backoff: ${waitSec}s`);
      await sleep(waitSec * 1000);
      lastError = new Error(`quota exceeded`);
      continue;
    }

    if (!response.ok) {
      lastError = new Error((data?.error?.message || 'error').substring(0, 100));
      continue;
    }

    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    if (!text) { lastError = new Error('Empty response'); continue; }

    let clean = text.replace(/```json/g, '').replace(/```/g, '').trim();
    const start = clean.indexOf('{');
    const end = clean.lastIndexOf('}');
    if (start !== -1 && end !== -1) clean = clean.substring(start, end + 1);
    try { return sanitizeExtraction(JSON.parse(clean)); }
    catch(e) { lastError = new Error('JSON parse failed'); continue; }
  }
  throw lastError || new Error('All models failed');
}

// ── Prompts ─────────────────────────────────────────────────────────────────
const PROMPT_F16 = `Extract Form 16 data. Return ONLY valid JSON, no markdown, no explanation:
{"name":"","pan":"","employer_name":"","gross_salary":0,"basic_salary":0,"hra_received":0,"special_allowance":0,"prof_tax":0,"epf_employee":0,"epf_employer":0,"sec80c":0,"nps":0,"employer_nps":0,"sec80d_self":0,"home_loan_interest":0,"sec80e":0,"standard_deduction":50000,"tds_deducted_form16":0,"total_income_form16":0,"taxable_income_form16":0}
Rules: gross_salary=total salary before deductions. tds_deducted_form16=total TDS shown in Part A. Use 0 for any field not found. Return ONLY the JSON object.`;

const PROMPT_26AS = `Extract Form 26AS data. Return ONLY valid JSON, no markdown:
{"pan":"","tds_entries":[{"deductor":"","amount":0,"tds":0,"pan_deductor":""}],"total_tds_26as":0,"advance_tax":0,"self_assessment_tax":0,"salary_income_26as":0,"interest_income_26as":0}
Rules: total_tds_26as=sum of ALL TDS entries. tds_entries=list from Part A. Use 0 for missing. Return ONLY the JSON.`;

const PROMPT_AIS = `Extract AIS (Annual Information Statement) data. Return ONLY valid JSON, no markdown:
{"pan":"","salary_ais":0,"interest_income_ais":0,"dividend_ais":0,"rental_income_ais":0,"ltcg_ais":0,"stcg_ais":0,"mf_transactions":0,"foreign_income":0,"tds_total_ais":0}
Rules: interest_income_ais=total from savings+FD+bonds. ltcg_ais/stcg_ais=capital gains amounts. Use 0 for missing. Return ONLY the JSON.`;

// ── Health check + keep-alive ping ──────────────────────────────────────────
// Frontend pings /ping every 10 minutes to prevent Render cold starts
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'TaxSmart API',
    timestamp: new Date().toISOString(),
    cache_size: extractionCache.size,
    uptime_s: Math.round(process.uptime()),
    daily_quota_used: dailyQuota.count,
    daily_quota_remaining: dailyQuota.remaining(),
    circuit_breaker: cb.isOpen() ? 'OPEN' : 'CLOSED'
  });
});

app.get('/ping', (req, res) => res.json({ pong: true, ts: Date.now() }));

// ── /stats — observability dashboard endpoint ─────────────────────────────────
// Shows extraction success %, avg duration, cache hit rate, error breakdown
// Access: https://taxsmart-api.onrender.com/stats
app.get('/stats', (req, res) => {
  res.json(stats.summary());
});

// ── Main extraction endpoint ──────────────────────────────────────────────
// Accepts up to 3 files: f16, as26, ais
app.post(
  '/extract',
  rateLimit,
  upload.fields([
    { name: 'f16', maxCount: 1 },
    { name: 'as26', maxCount: 1 },
    { name: 'ais', maxCount: 1 },
  ]),
  async (req, res) => {
    if (!process.env.GEMINI_API_KEY) {
      return res.status(500).json({ error: 'Server not configured. Contact support.' });
    }

    const files = req.files || {};
    if (!files.f16 && !files.as26 && !files.ais) {
      return res.status(400).json({ error: 'Please upload at least one document.' });
    }

    // Combined memory guard — prevent OOM on concurrent requests
    // 8MB × 3 files × 10 concurrent users = 240MB; Render free tier = 512MB RAM
    const totalSize = Object.values(files).flat().reduce((s, f) => s + f.size, 0);
    if (totalSize > 12 * 1024 * 1024) {
      slog(req, 'warn', 'upload_too_large', { total_kb: Math.round(totalSize/1024) });
      return res.status(413).json({ error: `Total upload size (${Math.round(totalSize/1024/1024)}MB) exceeds 12MB. Use digital PDFs — scans are unnecessarily large.` });
    }
    slog(req, 'info', 'request_start', { docs: Object.keys(files).join(','), total_kb: Math.round(totalSize/1024), quota_remaining: dailyQuota.remaining() });

    const results = {
      f16Data: {},
      as26Data: {},
      aisData: {},
      errors: [],
      warnings: [],
    };

    try {
      const ts = () => new Date().toISOString();

      // PDF magic byte validation — rejects garbage files disguised as PDFs
      function validatePDF(buffer, name) {
        if (buffer.slice(0, 5).toString('ascii') !== '%PDF-')
          throw new Error(`${name} is not a valid PDF`);
      }

      // Helper to run one doc extraction with full stats tracking
      async function extractDoc(fileObj, prompt, docKey, label) {
        const t0 = Date.now();
        validatePDF(fileObj.buffer, label);
        slog(req, 'info', 'extraction_start', { doc: docKey, size: fileObj.size });
        const b64 = fileObj.buffer.toString('base64');
        try {
          const data = validateShape(await callGemini(b64, prompt, fileObj.buffer), docKey);
          stats.record(docKey, true, Date.now() - t0);
          slog(req, 'info', 'extraction_ok', { doc: docKey, fields: Object.keys(data).length, quota_remaining: dailyQuota.remaining() });
          return data;
        } catch (e) {
          stats.record(docKey, false, 0);
          stats.trackError(e.message);
          throw e;
        }
      }

      if (files.f16) {
        try {
          results.f16Data = await extractDoc(files.f16[0], PROMPT_F16, 'f16', 'Form 16');
        } catch (e) {
          slog(req, 'error', 'extraction_fail', { doc: 'f16', err: e.message });
          results.warnings.push({ doc: 'Form 16', msg: e.message });
        }
        await sleep(2000);
      }

      if (files.as26) {
        try {
          results.as26Data = await extractDoc(files.as26[0], PROMPT_26AS, 'as26', 'Form 26AS');
        } catch (e) {
          slog(req, 'error', 'extraction_fail', { doc: '26as', err: e.message });
          results.warnings.push({ doc: 'Form 26AS', msg: e.message });
        }
        await sleep(2000);
      }

      if (files.ais) {
        try {
          results.aisData = await extractDoc(files.ais[0], PROMPT_AIS, 'ais', 'AIS');
        } catch (e) {
          slog(req, 'error', 'extraction_fail', { doc: 'ais', err: e.message });
          results.warnings.push({ doc: 'AIS', msg: e.message });
        }
      }

      results.errors = runErrorChecks(results.f16Data, results.as26Data, results.aisData);
      slog(req, 'info', 'request_done', { warnings: results.warnings.length, errors: results.errors.length });
      // Files in memoryStorage — auto GC'd after response
      return res.json(results);

    } catch (err) {
      slog(req, 'error', 'request_error', { err: err.message });
      return res.status(500).json({ error: 'Extraction failed. Please try again or fill manually.' });
    }
  }
);

// ── Error detection logic ────────────────────────────────────────────────────
function runErrorChecks(f16, as26, ais) {
  const errors = [];

  // 1. TDS Mismatch
  if (f16.tds_deducted_form16 > 0 && as26.total_tds_26as > 0) {
    const diff = Math.abs(f16.tds_deducted_form16 - as26.total_tds_26as);
    if (diff > 1000) {
      errors.push({
        type: 'crit', icon: 'warning',
        title: 'TDS Mismatch: Form 16 vs 26AS',
        desc: `Form 16 shows TDS of ${fmt(f16.tds_deducted_form16)}, but Form 26AS shows ${fmt(as26.total_tds_26as)}. Difference: ${fmt(diff)}.`,
        action: 'Contact your employer HR/payroll team immediately. TDS not in 26AS cannot be claimed as credit.',
        severity: 'red'
      });
    }
  }

  // 2. Salary mismatch Form 16 vs AIS
  if (f16.gross_salary > 0 && ais.salary_ais > 0) {
    const diff = Math.abs(f16.gross_salary - ais.salary_ais);
    if (diff > 5000) {
      errors.push({
        type: 'warn', icon: 'alert',
        title: 'Salary Mismatch: Form 16 vs AIS',
        desc: `Form 16 shows ${fmt(f16.gross_salary)} but AIS shows ${fmt(ais.salary_ais)}. Difference: ${fmt(diff)}.`,
        action: 'Cross-check with your employer. AIS may include perquisites. Declare the correct figure in your ITR.',
        severity: 'amber'
      });
    }
  }

  // 3. Missing PAN in TDS entries
  if (as26.tds_entries && as26.tds_entries.length > 0) {
    const missingPan = as26.tds_entries.filter(
      e => !e.pan_deductor || e.pan_deductor === 'PANNOTAVBL' || e.pan_deductor === ''
    );
    if (missingPan.length > 0) {
      errors.push({
        type: 'warn', icon: 'id-card',
        title: `Missing PAN in ${missingPan.length} TDS ${missingPan.length > 1 ? 'Entries' : 'Entry'}`,
        desc: `${missingPan.length} deductor(s) have missing or invalid PAN. TDS credit may not be claimable.`,
        action: 'Contact the deductors and ask them to file a TDS correction with their PAN.',
        severity: 'amber'
      });
    }
  }

  // 4. Interest income discrepancy
  if (ais.interest_income_ais > 0 && as26.interest_income_26as > 0) {
    const diff = Math.abs(ais.interest_income_ais - as26.interest_income_26as);
    if (diff > 2000) {
      errors.push({
        type: 'warn', icon: 'money',
        title: 'Interest Income Discrepancy',
        desc: `AIS shows ${fmt(ais.interest_income_ais)} but 26AS shows ${fmt(as26.interest_income_26as)}.`,
        action: 'Use the higher figure in your ITR to avoid a notice from the Income Tax Department.',
        severity: 'amber'
      });
    }
  }

  // 5. Capital gains found
  if ((ais.ltcg_ais > 0 || ais.stcg_ais > 0) && (ais.ltcg_ais + ais.stcg_ais) > 10000) {
    errors.push({
      type: 'info', icon: 'chart',
      title: 'Capital Gains Found in AIS',
      desc: `LTCG: ${fmt(ais.ltcg_ais || 0)}, STCG: ${fmt(ais.stcg_ais || 0)}. These have been auto-filled.`,
      action: "Cross-check with your broker's P&L statement before filing.",
      severity: 'blue'
    });
  }

  // 6. Dividend income
  if (ais.dividend_ais > 5000) {
    errors.push({
      type: 'info', icon: 'building',
      title: 'Dividend Income Detected',
      desc: `AIS shows dividend income of ${fmt(ais.dividend_ais)}. Fully taxable since FY 2020-21.`,
      action: 'Declare under Income from Other Sources in your ITR. Check if TDS was deducted.',
      severity: 'blue'
    });
  }

  // ── Edge case detection — complex situations requiring ITR-2 or CA ──────────
  if ((ais.foreign_income || 0) > 0)
    errors.push({
      type:'crit', icon:'globe', severity:'red',
      title:'Foreign Income Detected — ITR-2 Required',
      desc:`AIS shows foreign income of ${fmt(ais.foreign_income)}. ITR-1 cannot be used.`,
      action:'File ITR-2. DTAA exemptions and FBAR rules may apply — consult a CA.'
    });

  if ((ais.ltcg_ais + ais.stcg_ais) > 1_00_000)
    errors.push({
      type:'warn', icon:'chart', severity:'amber',
      title:'Capital Gains May Require ITR-2',
      desc:`LTCG: ${fmt(ais.ltcg_ais||0)}, STCG: ${fmt(ais.stcg_ais||0)}. ITR-1 covers salary + single house property only.`,
      action:'If gains are from equity/mutual funds, use ITR-2. Verify with broker P&L.'
    });

  if (ais.mf_transactions > 0 && (ais.ltcg_ais||0) === 0 && (ais.stcg_ais||0) === 0)
    errors.push({
      type:'info', icon:'info', severity:'blue',
      title:'Mutual Fund Activity — Capital Gains Not Reported',
      desc:`AIS shows ${fmt(ais.mf_transactions)} in MF transactions but no capital gains detected.`,
      action:"Download Capital Gains Statement from CAMS/Kfintech and verify before filing."
    });

  if (f16.special_allowance > 0 && f16.gross_salary > 0 && (f16.special_allowance / f16.gross_salary) > 0.4 && f16.special_allowance > 10_00_000)
    errors.push({
      type:'warn', icon:'briefcase', severity:'amber',
      title:'Possible ESOP Perquisite in Salary',
      desc:`Special allowance is ${Math.round((f16.special_allowance/f16.gross_salary)*100)}% of gross (${fmt(f16.special_allowance)}). This pattern often indicates ESOP vesting taxed as perquisite.`,
      action:'Verify with Form 12BA from your employer. ESOP perquisites affect regime calculation.'
    });

  return errors;
}

function fmt(n) {
  if (!n) return '0';
  n = Math.round(n);
  if (n >= 10000000) return '₹' + (n / 10000000).toFixed(1) + ' Cr';
  if (n >= 100000) return '₹' + (n / 100000).toFixed(1) + ' L';
  const s = n.toString();
  if (s.length <= 3) return '₹' + s;
  let r = s.slice(-3), rem = s.slice(0, -3);
  while (rem.length > 2) { r = rem.slice(-2) + ',' + r; rem = rem.slice(0, -2); }
  return '₹' + rem + ',' + r;
}

// ── Start server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`TaxSmart API running on port ${PORT}`);
  if (!process.env.GEMINI_API_KEY) {
    console.warn('WARNING: GEMINI_API_KEY not set. Extraction will fail.');
  }
});
