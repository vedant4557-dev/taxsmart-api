const express = require('express');
const multer = require('multer');
const cors = require('cors');
const helmet = require('helmet');
const { rateLimit: expressRateLimit } = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({ crossOriginResourcePolicy:{policy:'cross-origin'}, contentSecurityPolicy:false }));

const allowedOrigins = [
  'https://vedant4557-dev.github.io',
  'http://localhost:3000',
  'http://127.0.0.1:5500',
];
app.use(cors({
  origin:(origin,cb)=>{
    if(!origin||allowedOrigins.some(o=>origin.startsWith(o))) cb(null,true);
    else cb(new Error('Not allowed by CORS'));
  }
}));
app.use(express.json({limit:'1mb'}));

// ── File upload: strict validation ───────────────────────────────────────────
const MAX_MB = 12;
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits:{fileSize: MAX_MB*1024*1024},
  fileFilter:(req,file,cb)=>{
    const validMime = file.mimetype==='application/pdf';
    const validExt  = file.originalname.toLowerCase().endsWith('.pdf');
    if(validMime && validExt) cb(null,true);
    else cb(new Error('Only PDF files are allowed.'));
  }
});

// ── Rate limiting ─────────────────────────────────────────────────────────────
const rateLimit = expressRateLimit({
  windowMs:60*60*1000, max:10,
  standardHeaders:true, legacyHeaders:false,
  message:{error:'Too many requests. Please try again in an hour.'},
  keyGenerator:(req)=>req.ip||req.connection?.remoteAddress||'unknown',
});

// ── Strict schemas ────────────────────────────────────────────────────────────
const SCHEMA_F16 = {
  name:'string', pan:'string', employer_name:'string',
  gross_salary:'number', basic_salary:'number', hra_received:'number',
  special_allowance:'number', prof_tax:'number', epf_employee:'number',
  epf_employer:'number', sec80c:'number', nps:'number', employer_nps:'number',
  sec80d_self:'number', home_loan_interest:'number', sec80e:'number',
  standard_deduction:'number', tds_deducted_form16:'number',
  total_income_form16:'number', taxable_income_form16:'number',
};
const SCHEMA_26AS = {
  pan:'string', tds_entries:'array',
  total_tds_26as:'number', advance_tax:'number', self_assessment_tax:'number',
  salary_income_26as:'number', interest_income_26as:'number',
};
const SCHEMA_AIS = {
  pan:'string', salary_ais:'number', interest_income_ais:'number',
  dividend_ais:'number', rental_income_ais:'number', ltcg_ais:'number',
  stcg_ais:'number', mf_transactions:'number', foreign_income:'number',
  tds_total_ais:'number',
};

function buildEmpty(schema){
  const e={};
  for(const[k,t] of Object.entries(schema)) e[k]=t==='number'?0:t==='array'?[]:'';
  return e;
}

// ── Schema validator + sanity checks ─────────────────────────────────────────
function validateAndSanitize(data, schema, docName){
  if(!data||typeof data!=='object'||Array.isArray(data)){
    console.warn(`[Schema] ${docName}: non-object, returning empty`);
    return buildEmpty(schema);
  }
  const out={};
  const violations=[];
  for(const[key,type] of Object.entries(schema)){
    const val=data[key];
    if(type==='number'){
      if(val===null||val===undefined||val==='') out[key]=0;
      else if(typeof val==='number'&&isFinite(val)) out[key]=Math.min(Math.max(0,Math.round(val)),100000000);
      else if(typeof val==='string'){
        const parsed=parseFloat(val.replace(/[₹,\s]/g,''));
        out[key]=isFinite(parsed)?Math.min(Math.max(0,Math.round(parsed)),100000000):0;
        if(!isFinite(parsed)) violations.push(`${key}:"${val}"->0`);
      } else { out[key]=0; violations.push(`${key}:bad type`); }
    } else if(type==='string'){
      out[key]=typeof val==='string'?val.trim().substring(0,200):'';
    } else if(type==='array'){
      out[key]=Array.isArray(val)?val.slice(0,50):[];
    }
  }
  const extra=Object.keys(data).filter(k=>!schema[k]);
  if(extra.length) console.log(`[Schema] ${docName}: stripped extra keys: ${extra.slice(0,5)}`);
  if(violations.length) console.warn(`[Schema] ${docName}: violations:`,violations.slice(0,3));

  // Sanity caps
  if(out.tds_deducted_form16>0&&out.gross_salary>0&&out.tds_deducted_form16>out.gross_salary){
    console.warn(`[Sanity] ${docName}: TDS>gross, zeroing TDS`);
    out.tds_deducted_form16=0;
  }
  if(out.sec80c>150000){ out.sec80c=150000; }
  if(out.basic_salary>0&&out.gross_salary>0&&out.basic_salary>out.gross_salary){
    out.basic_salary=Math.round(out.gross_salary*0.4);
  }
  return out;
}

// ── Gemini caller ─────────────────────────────────────────────────────────────
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));

async function callGemini(base64Pdf, prompt){
  const apiKey=process.env.GEMINI_API_KEY;
  if(!apiKey) throw new Error('GEMINI_API_KEY not configured');
  const MODELS=['gemini-2.0-flash','gemini-2.5-flash'];
  let lastError=null;

  for(const modelName of MODELS){
    const url=`https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;
    console.log(`Trying ${modelName}...`);
    let response, data;
    try{
      response=await fetch(url,{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({
          contents:[{parts:[
            {inline_data:{mime_type:'application/pdf',data:base64Pdf}},
            {text:prompt}
          ]}],
          generationConfig:{
            temperature:0,
            maxOutputTokens:8192,
            responseMimeType:'application/json',
          }
        })
      });
      data=await response.json();
    } catch(fetchErr){
      console.error(`${modelName} fetch error:`,fetchErr.message);
      lastError=fetchErr; continue;
    }

    if(response.status===429){
      const retryMsg=data?.error?.message||'';
      const m=retryMsg.match(/(\d+\.?\d*)\s*s/i);
      const waitSec=m?Math.min(parseFloat(m[1])+1,15):5;
      console.log(`${modelName} quota, waiting ${waitSec}s`);
      await sleep(waitSec*1000);
      lastError=new Error(`${modelName}: quota`); continue;
    }
    if(!response.ok){
      const msg=data?.error?.message||JSON.stringify(data);
      console.error(`${modelName} error ${response.status}:`,msg.substring(0,200));
      lastError=new Error(`${modelName}: ${msg.substring(0,100)}`); continue;
    }

    const text=data.candidates?.[0]?.content?.parts?.[0]?.text||'';
    if(!text){ lastError=new Error(`${modelName}: empty`); continue; }

    let clean=text.replace(/```json/g,'').replace(/```/g,'').trim();
    const s=clean.indexOf('{'), e=clean.lastIndexOf('}');
    if(s===-1||e===-1){ lastError=new Error(`${modelName}: no JSON`); continue; }
    clean=clean.substring(s,e+1);

    try{ return JSON.parse(clean); }
    catch(err){ lastError=new Error(`${modelName}: parse failed`); continue; }
  }
  throw lastError||new Error('All models failed');
}

// ── Prompts: strict schema + scanned doc guidance ─────────────────────────────
const PROMPT_F16=`You are an expert Indian tax document parser for Form 16 (TDS certificate from employer).

CRITICAL RULES:
1. Return ONLY a valid JSON object. No markdown, no explanation, no extra text.
2. The document may be digital or scanned. Read all text and tables carefully.
3. Use 0 for any number you cannot find or are not confident about. NEVER guess.
4. All monetary values: plain integers only (no ₹, no commas, no "lakhs").
5. gross_salary = total salary income before deductions.
6. standard_deduction is 50000 for FY 2025-26 unless document states otherwise.
7. Do NOT add keys not listed below.

EXACT JSON TO RETURN:
{"name":"","pan":"","employer_name":"","gross_salary":0,"basic_salary":0,"hra_received":0,"special_allowance":0,"prof_tax":0,"epf_employee":0,"epf_employer":0,"sec80c":0,"nps":0,"employer_nps":0,"sec80d_self":0,"home_loan_interest":0,"sec80e":0,"standard_deduction":50000,"tds_deducted_form16":0,"total_income_form16":0,"taxable_income_form16":0}`;

const PROMPT_26AS=`You are an expert Indian tax document parser for Form 26AS (Annual Tax Statement from TRACES/IT Dept).

CRITICAL RULES:
1. Return ONLY a valid JSON object. No markdown, no explanation.
2. Sum ALL TDS entries in Part A for total_tds_26as.
3. Use 0 for missing numbers. NEVER guess.
4. All monetary values: plain integers only.
5. Do NOT add keys not listed below.

EXACT JSON TO RETURN:
{"pan":"","tds_entries":[{"deductor":"","amount":0,"tds":0,"pan_deductor":""}],"total_tds_26as":0,"advance_tax":0,"self_assessment_tax":0,"salary_income_26as":0,"interest_income_26as":0}`;

const PROMPT_AIS=`You are an expert Indian tax document parser for AIS (Annual Information Statement from IT Dept).

CRITICAL RULES:
1. Return ONLY a valid JSON object. No markdown, no explanation.
2. Read all sections: salary, interest, dividends, capital gains, etc.
3. Use 0 for missing values. NEVER guess.
4. All monetary values: plain integers only.
5. tds_total_ais = sum of all TDS across all entries in AIS.
6. Do NOT add keys not listed below.

EXACT JSON TO RETURN:
{"pan":"","salary_ais":0,"interest_income_ais":0,"dividend_ais":0,"rental_income_ais":0,"ltcg_ais":0,"stcg_ais":0,"mf_transactions":0,"foreign_income":0,"tds_total_ais":0}`;

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health',(req,res)=>{
  res.json({status:'ok',service:'TaxSmart API',version:'2.0.0',
    timestamp:new Date().toISOString(),
    gemini:process.env.GEMINI_API_KEY?'configured':'MISSING'});
});

// ── Extract endpoint ──────────────────────────────────────────────────────────
app.post('/extract',
  rateLimit,
  (req,res,next)=>{
    upload.fields([{name:'f16',maxCount:1},{name:'as26',maxCount:1},{name:'ais',maxCount:1}])(req,res,(err)=>{
      if(err instanceof multer.MulterError){
        if(err.code==='LIMIT_FILE_SIZE')
          return res.status(413).json({error:`File too large. Max ${MAX_MB}MB. Please compress your PDF.`});
        return res.status(400).json({error:`Upload error: ${err.message}`});
      } else if(err) return res.status(400).json({error:err.message});
      next();
    });
  },
  async(req,res)=>{
    if(!process.env.GEMINI_API_KEY)
      return res.status(500).json({error:'Server not configured. Contact support.'});

    const files=req.files||{};
    const body=req.body||{};
    const getB64=async(key)=>{
      if(files[key]?.[0]) return files[key][0].buffer.toString('base64');
      if(body[key])        return body[key];
      return null;
    };

    if(!files.f16&&!files.as26&&!files.ais&&!body.f16&&!body.as26&&!body.ais)
      return res.status(400).json({error:'Please upload at least one document.'});

    const results={f16Data:{},as26Data:{},aisData:{},errors:[],warnings:[],
      _meta:{extractedAt:new Date().toISOString(),version:'2.0'}};
    const ts=()=>new Date().toISOString();

    try{
      const b64F16=await getB64('f16');
      if(b64F16){
        try{
          console.log(`[${ts()}] Form 16 start`);
          const raw=await callGemini(b64F16,PROMPT_F16);
          results.f16Data=validateAndSanitize(raw,SCHEMA_F16,'Form 16');
          console.log(`[${ts()}] Form 16 OK gross:${results.f16Data.gross_salary} tds:${results.f16Data.tds_deducted_form16}`);
        }catch(e){
          console.error(`[${ts()}] Form 16 FAILED:`,e.message);
          results.warnings.push({doc:'Form 16',msg:e.message});
          results.f16Data=buildEmpty(SCHEMA_F16);
        }
        await sleep(3000);
      }

      const b64As26=await getB64('as26');
      if(b64As26){
        try{
          console.log(`[${ts()}] 26AS start`);
          const raw=await callGemini(b64As26,PROMPT_26AS);
          results.as26Data=validateAndSanitize(raw,SCHEMA_26AS,'26AS');
          console.log(`[${ts()}] 26AS OK tds:${results.as26Data.total_tds_26as}`);
        }catch(e){
          console.error(`[${ts()}] 26AS FAILED:`,e.message);
          results.warnings.push({doc:'Form 26AS',msg:e.message});
          results.as26Data=buildEmpty(SCHEMA_26AS);
        }
        await sleep(3000);
      }

      const b64Ais=await getB64('ais');
      if(b64Ais){
        try{
          console.log(`[${ts()}] AIS start`);
          const raw=await callGemini(b64Ais,PROMPT_AIS);
          results.aisData=validateAndSanitize(raw,SCHEMA_AIS,'AIS');
          console.log(`[${ts()}] AIS OK int:${results.aisData.interest_income_ais} ltcg:${results.aisData.ltcg_ais}`);
        }catch(e){
          console.error(`[${ts()}] AIS FAILED:`,e.message);
          results.warnings.push({doc:'AIS',msg:e.message});
          results.aisData=buildEmpty(SCHEMA_AIS);
        }
      }

      results.errors=runErrorChecks(results.f16Data,results.as26Data,results.aisData);
      return res.json(results);

    }catch(err){
      console.error('[FATAL]',err);
      return res.status(500).json({error:'Extraction failed. Please try again or fill manually.'});
    }
  }
);

// ── Error detection ───────────────────────────────────────────────────────────
function runErrorChecks(f16,as26,ais){
  const errors=[];

  if(f16.tds_deducted_form16>0&&as26.total_tds_26as>0){
    const diff=Math.abs(f16.tds_deducted_form16-as26.total_tds_26as);
    if(diff>1000) errors.push({type:'crit',icon:'warning',
      title:'TDS Mismatch: Form 16 vs 26AS',
      desc:`Form 16 shows TDS of ${fmt(f16.tds_deducted_form16)}, but Form 26AS shows ${fmt(as26.total_tds_26as)}. Difference: ${fmt(diff)}.`,
      action:'Contact your employer HR/payroll immediately. TDS not in 26AS cannot be claimed as credit and may trigger an IT notice.',
      severity:'red'});
  }

  if(f16.gross_salary>0&&ais.salary_ais>0){
    const diff=Math.abs(f16.gross_salary-ais.salary_ais);
    if(diff>5000) errors.push({type:'warn',icon:'alert',
      title:'Salary Mismatch: Form 16 vs AIS',
      desc:`Form 16 shows ${fmt(f16.gross_salary)} but AIS shows ${fmt(ais.salary_ais)}. Difference: ${fmt(diff)}.`,
      action:'Cross-check with employer. AIS may include perquisites. Declare correct figure in ITR.',
      severity:'amber'});
  }

  if(as26.tds_entries?.length>0){
    const missing=as26.tds_entries.filter(e=>!e.pan_deductor||e.pan_deductor==='PANNOTAVBL'||e.pan_deductor==='');
    if(missing.length>0) errors.push({type:'warn',icon:'id-card',
      title:`Missing PAN in ${missing.length} TDS ${missing.length>1?'Entries':'Entry'}`,
      desc:`${missing.length} deductor(s) have missing/invalid PAN. TDS credit may not be claimable.`,
      action:'Contact the deductors to file a TDS correction with valid PAN.',
      severity:'amber'});
  }

  if(ais.interest_income_ais>0&&as26.interest_income_26as>0){
    const diff=Math.abs(ais.interest_income_ais-as26.interest_income_26as);
    if(diff>2000) errors.push({type:'warn',icon:'money',
      title:'Interest Income Discrepancy: AIS vs 26AS',
      desc:`AIS shows ${fmt(ais.interest_income_ais)} but 26AS shows ${fmt(as26.interest_income_26as)}. Diff: ${fmt(diff)}.`,
      action:'Use the higher figure in ITR. AIS is typically more comprehensive.',
      severity:'amber'});
  }

  if((ais.ltcg_ais||0)+(ais.stcg_ais||0)>10000)
    errors.push({type:'info',icon:'chart',
      title:'Capital Gains Found in AIS',
      desc:`LTCG: ${fmt(ais.ltcg_ais||0)}, STCG: ${fmt(ais.stcg_ais||0)}. Auto-filled in your report.`,
      action:"Cross-check with broker P&L before filing. LTCG 12.5% above ₹1.25L, STCG 20%.",
      severity:'blue'});

  if((ais.dividend_ais||0)>5000)
    errors.push({type:'info',icon:'building',
      title:'Dividend Income Detected',
      desc:`AIS shows dividend income of ${fmt(ais.dividend_ais)}. Fully taxable at slab rates.`,
      action:'Declare under Income from Other Sources. Check if TDS @ 10% was deducted.',
      severity:'blue'});

  if((ais.foreign_income||0)>0)
    errors.push({type:'warn',icon:'globe',
      title:'Foreign Income Detected',
      desc:`AIS shows foreign income of ${fmt(ais.foreign_income)}. DTAA provisions may apply.`,
      action:'Foreign income requires Schedule FA in ITR. Consult a CA.',
      severity:'amber'});

  return errors;
}

function fmt(n){
  if(!n) return '₹0';
  n=Math.round(n);
  if(n>=10000000) return '₹'+(n/10000000).toFixed(1)+' Cr';
  if(n>=100000)   return '₹'+(n/100000).toFixed(1)+' L';
  const s=n.toString();
  if(s.length<=3) return '₹'+s;
  let r=s.slice(-3),rem=s.slice(0,-3);
  while(rem.length>2){r=rem.slice(-2)+','+r;rem=rem.slice(0,-2);}
  return '₹'+rem+','+r;
}

app.use((req,res)=>res.status(404).json({error:'Not found'}));
app.use((err,req,res,next)=>{ console.error(err); res.status(500).json({error:'Internal error'}); });

app.listen(PORT,()=>{
  console.log(`TaxSmart API v2.0 on port ${PORT}`);
  if(!process.env.GEMINI_API_KEY) console.warn('⚠️  GEMINI_API_KEY not set');
});
