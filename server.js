const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ── CORS: allow your GitHub Pages frontend ──────────────────────────────────
const allowedOrigins = [
  'https://vedant4557-dev.github.io',
  'http://localhost:3000',
  'http://127.0.0.1:5500', // Live Server for local dev
];
app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (Postman, curl) or whitelisted origins
    if (!origin || allowedOrigins.some(o => origin.startsWith(o))) {
      cb(null, true);
    } else {
      cb(new Error('Not allowed by CORS'));
    }
  }
}));

app.use(express.json());

// ── File upload: memory storage (never writes to disk permanently) ──────────
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 }, // 15MB max per file
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Only PDF files are allowed'));
  }
});

// ── Rate limiting (simple in-memory, upgrade to Redis for scale) ───────────
const rateLimitMap = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = 60 * 60 * 1000; // 1 hour
  const maxRequests = 10; // 10 extractions per hour per IP

  const record = rateLimitMap.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + windowMs;
  }
  record.count++;
  rateLimitMap.set(ip, record);

  if (record.count > maxRequests) {
    return res.status(429).json({
      error: 'Too many requests. Please try again in an hour.',
      retryAfter: Math.ceil((record.resetAt - now) / 1000)
    });
  }
  next();
}

// ── Gemini API helper ───────────────────────────────────────────────────────
// Free tier: 1,500 requests/day, resets daily at midnight
async function callClaude(base64Pdf, prompt) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error('GEMINI_API_KEY not configured on server');

  // gemini-1.5-flash on v1beta is the correct endpoint for free tier
  // gemini-2.5-flash: current free tier model as of Feb 2026
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;
  console.log('Calling gemini-2.5-flash...');

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{
        parts: [
          { inline_data: { mime_type: 'application/pdf', data: base64Pdf } },
          { text: prompt }
        ]
      }],
      generationConfig: { temperature: 0, maxOutputTokens: 2000 }
    })
  });

  const data = await response.json();

  if (!response.ok) {
    const errMsg = data?.error?.message || JSON.stringify(data);
    console.error('Gemini error', response.status, errMsg.substring(0, 200));
    throw new Error('Gemini error: ' + errMsg);
  }

  const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  if (!text) {
    console.error('Empty Gemini response:', JSON.stringify(data).substring(0, 300));
    throw new Error('Empty response from Gemini');
  }

  const clean = text.replace(/```json/g, '').replace(/```/g, '').trim();
  return JSON.parse(clean);

}

// ── Prompts ─────────────────────────────────────────────────────────────────
const PROMPT_F16 = `You are an expert Indian tax data extractor. Extract all data from this Form 16 and return ONLY a valid JSON object with these exact keys (use 0 for missing numbers, empty string for missing text):
{
  "name": "",
  "pan": "",
  "employer_name": "",
  "gross_salary": 0,
  "basic_salary": 0,
  "hra_received": 0,
  "special_allowance": 0,
  "prof_tax": 0,
  "epf_employee": 0,
  "epf_employer": 0,
  "sec80c": 0,
  "nps": 0,
  "employer_nps": 0,
  "sec80d_self": 0,
  "home_loan_interest": 0,
  "sec80e": 0,
  "standard_deduction": 50000,
  "tds_deducted_form16": 0,
  "total_income_form16": 0,
  "taxable_income_form16": 0
}
Return ONLY the JSON object, absolutely no explanation or markdown.`;

const PROMPT_26AS = `You are an expert Indian tax data extractor. Extract all data from this Form 26AS and return ONLY a valid JSON object:
{
  "pan": "",
  "tds_entries": [{"deductor": "", "amount": 0, "tds": 0, "pan_deductor": ""}],
  "total_tds_26as": 0,
  "advance_tax": 0,
  "self_assessment_tax": 0,
  "salary_income_26as": 0,
  "interest_income_26as": 0
}
Return ONLY the JSON object, no explanation.`;

const PROMPT_AIS = `You are an expert Indian tax data extractor. Extract all financial data from this Annual Information Statement (AIS) and return ONLY a valid JSON object:
{
  "pan": "",
  "salary_ais": 0,
  "interest_income_ais": 0,
  "dividend_ais": 0,
  "rental_income_ais": 0,
  "ltcg_ais": 0,
  "stcg_ais": 0,
  "mf_transactions": 0,
  "foreign_income": 0,
  "tds_total_ais": 0
}
Return ONLY the JSON object, no explanation.`;

// ── Health check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'TaxSmart API', timestamp: new Date().toISOString() });
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

    const results = {
      f16Data: {},
      as26Data: {},
      aisData: {},
      errors: [],
      warnings: [],
    };

    try {
      const ts = () => new Date().toISOString();

      // Extract Form 16
      if (files.f16) {
        try {
          console.log(`[${ts()}] Starting Form 16 extraction, size: ${files.f16[0].size} bytes`);
          const b64 = files.f16[0].buffer.toString('base64');
          results.f16Data = await callClaude(b64, PROMPT_F16);
          console.log(`[${ts()}] Form 16 extracted OK:`, JSON.stringify(results.f16Data).substring(0, 100));
        } catch (e) {
          console.error(`[${ts()}] Form 16 FAILED:`, e.message);
          results.warnings.push({ doc: 'Form 16', msg: e.message });
        }
      }

      // Extract Form 26AS
      if (files.as26) {
        try {
          console.log(`[${ts()}] Starting 26AS extraction, size: ${files.as26[0].size} bytes`);
          const b64 = files.as26[0].buffer.toString('base64');
          results.as26Data = await callClaude(b64, PROMPT_26AS);
          console.log(`[${ts()}] 26AS extracted OK:`, JSON.stringify(results.as26Data).substring(0, 100));
        } catch (e) {
          console.error(`[${ts()}] 26AS FAILED:`, e.message);
          results.warnings.push({ doc: 'Form 26AS', msg: e.message });
        }
      }

      // Extract AIS
      if (files.ais) {
        try {
          console.log(`[${ts()}] Starting AIS extraction, size: ${files.ais[0].size} bytes`);
          const b64 = files.ais[0].buffer.toString('base64');
          results.aisData = await callClaude(b64, PROMPT_AIS);
          console.log(`[${ts()}] AIS extracted OK:`, JSON.stringify(results.aisData).substring(0, 100));
        } catch (e) {
          console.error(`[${ts()}] AIS FAILED:`, e.message);
          results.warnings.push({ doc: 'AIS', msg: e.message });
        }
      }

      // Cross-check for errors
      results.errors = runErrorChecks(results.f16Data, results.as26Data, results.aisData);

      // IMPORTANT: Files are in memory only (memoryStorage), never written to disk
      // They are automatically garbage-collected after this response
      return res.json(results);

    } catch (err) {
      console.error('Extraction error:', err);
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
