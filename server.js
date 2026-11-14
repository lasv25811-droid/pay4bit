/**
 * YevroLato – Pay4bit backend (v3)
 * - 3 Firebase layihəsi: primary / basket / analytics
 * - Pay Çarx SİLİNDİ
 * - Email verify SİLİNDİ
 * - P2P (USDT+BTC) depozit + BTC çıxarış + Hədiyyə qutusu
 * - Region detection (Cloudflare cf-ipcountry)
 */
try { require('dns').setDefaultResultOrder('ipv4first'); } catch (_) {}
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const admin = require('firebase-admin');

const PUBLIC_KEY = process.env.PAY4BIT_PUBLIC_KEY || '';
const SECRET_KEY = process.env.PAY4BIT_SECRET_KEY || '';
if (!PUBLIC_KEY || !SECRET_KEY) {
  console.error('PAY4BIT_PUBLIC_KEY / PAY4BIT_SECRET_KEY təyin olunmayıb.');
  process.exit(1);
}

const PAY4BIT_URL = 'https://api.pay4bit.net/pay';
const CHARGE_CURRENCY = 'EUR';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const PAY_REQUIRE_SIGN = String(process.env.PAY4BIT_PAY_REQUIRE_SIGN || 'true').trim().toLowerCase() !== 'false';

const PAY_SYSTEM = {
  card:   process.env.PAY4BIT_CARD_PS   || '',
  google: process.env.PAY4BIT_GOOGLE_PS || '',
  apple:  process.env.PAY4BIT_APPLE_PS  || ''
};
const MIN_AZN = { card: 3, google: 20, apple: 20 };
const MIN_DEPOSIT_CARD_AZN = Number(process.env.PAY4BIT_MIN_DEPOSIT_CARD || 10);

const COMMISSION_PERCENT = {
  card:   Number(process.env.PAY4BIT_COMM_CARD   || 0),
  google: Number(process.env.PAY4BIT_COMM_GOOGLE || 18.14),
  apple:  Number(process.env.PAY4BIT_COMM_APPLE  || 18.14)
};
const COMMISSION_FIXED_EUR = {
  card:   Number(process.env.PAY4BIT_FIX_CARD   || 0),
  google: Number(process.env.PAY4BIT_FIX_GOOGLE || 2.52),
  apple:  Number(process.env.PAY4BIT_FIX_APPLE  || 2.52)
};
const MAX_AZN = 2000;
const MIN_CHARGE = 1;

/* ═══════════════════════════════════════════════════════════
   3 FIREBASE LAYİHƏSİ (oxuma/yazma yükü bölünür)
   ═══════════════════════════════════════════════════════════ */
function loadSA(envB64, envJson) {
  try {
    const raw = envB64 ? Buffer.from(envB64, 'base64').toString('utf8') : envJson;
    if (!raw || !String(raw).trim()) return null;
    const sa = JSON.parse(String(raw).trim());
    sa.private_key = String(sa.private_key || '').replace(/\\n/g, '\n');
    return sa;
  } catch (e) { console.error('SA parse xətası:', e.message); return null; }
}
const SA1 = loadSA(process.env.FIREBASE_SERVICE_ACCOUNT_B64, process.env.FIREBASE_SERVICE_ACCOUNT);
const SA2 = loadSA(process.env.FIREBASE_SERVICE_ACCOUNT_2_B64, process.env.FIREBASE_SERVICE_ACCOUNT_2);
const SA3 = loadSA(process.env.FIREBASE_SERVICE_ACCOUNT_3_B64, process.env.FIREBASE_SERVICE_ACCOUNT_3);

if (!SA1) { console.error('Primary Firebase SA yoxdur.'); process.exit(1); }

const app1 = admin.initializeApp({ credential: admin.credential.cert(SA1) }, 'p1');
const db  = app1.firestore();
try { db.settings({ ignoreUndefinedProperties: true }); } catch (_) {}
const FieldValue = admin.firestore.FieldValue;

let dbBasket = null;
if (SA2) {
  try {
    const app2 = admin.initializeApp({ credential: admin.credential.cert(SA2) }, 'p2');
    dbBasket = app2.firestore();
    try { dbBasket.settings({ ignoreUndefinedProperties: true }); } catch (_) {}
    console.log('[p2] basket Firebase qoşuldu:', SA2.project_id);
  } catch (e) { console.error('[p2]', e.message); }
} else { console.log('[p2] verilməyib — basket primary-də işləyəcək'); }

let dbAnalytics = null;
if (SA3) {
  try {
    const app3 = admin.initializeApp({ credential: admin.credential.cert(SA3) }, 'p3');
    dbAnalytics = app3.firestore();
    try { dbAnalytics.settings({ ignoreUndefinedProperties: true }); } catch (_) {}
    console.log('[p3] analytics Firebase qoşuldu:', SA3.project_id);
  } catch (e) { console.error('[p3]', e.message); }
} else { console.log('[p3] verilməyib — analytics primary-də işləyəcək'); }

const DB_BASKET = dbBasket || db;      // public/basket yazıları
const DB_ANALYTICS = dbAnalytics || db; // loq/analitika yazıları

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

function getClientIp(req) {
  const h = req.headers || {};
  const pick = v => String(Array.isArray(v) ? v[0] : (v || '')).split(',')[0].trim();
  const ip = pick(h['cf-connecting-ip']) || pick(h['true-client-ip']) || String(req.ip || '');
  return ip.replace(/^::ffff:/i, '');
}
app.use((req, res, next) => {
  req.realIp = getClientIp(req);
  // Cloudflare country header (pulsuz, dəqiq)
  req.countryCode = String(req.headers['cf-ipcountry'] || '').toUpperCase().slice(0, 2);
  next();
});

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

app.use(cors({ origin: true, methods: ['GET', 'POST', 'OPTIONS'], maxAge: 86400 }));

const GLOBAL_LIMIT = Math.max(60, Number(process.env.RATE_LIMIT_PER_MIN) || 600);
const globalHits = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of globalHits) if (now - v.t > 60000) globalHits.delete(k); }, 60000).unref();
app.use((req, res, next) => {
  if (req.method === 'OPTIONS' || req.path === '/pay4bit/callback' || req.path === '/betatransfer/callback' || req.path === '/health' || req.path === '/api/health') return next();
  const ip = String(req.realIp || req.ip || '');
  const now = Date.now();
  let e = globalHits.get(ip);
  if (!e || now - e.t > 60000) e = { t: now, n: 0 };
  e.n++; globalHits.set(ip, e);
  if (e.n > GLOBAL_LIMIT) return res.status(429).json({ success: false, error: 'Çox sorğu, bir az sonra yoxlayın' });
  next();
});
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: true, limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  if (req.path === '/pay4bit/callback' || req.path === '/betatransfer/callback') return next();
  const t0 = Date.now();
  req._stage = 'start';
  const t = setTimeout(() => {
    if (!res.headersSent) {
      console.error(`[timeout] ${req.method} ${req.path} mərhələ=${req._stage}`);
      res.status(503).json({ success: false, error: 'Server məşğuldur, bir az sonra yenidən cəhd edin' });
    }
  }, 30000);
  const done = () => { clearTimeout(t); const ms = Date.now() - t0; if (ms > 5000) console.warn(`[slow] ${req.method} ${req.path} ${ms}ms mərhələ=${req._stage}`); };
  res.on('finish', done); res.on('close', () => clearTimeout(t));
  next();
});

/* ═══════════════════════════════════════════════════════════
   REGION HELPER (region.js-dən import)
   ═══════════════════════════════════════════════════════════ */
const region = require('./region');

/* Valyuta məzənnəsi */
let rateCache = { aznPerEur: null, at: 0, source: null };
const RATE_TTL = 30 * 60 * 1000;
function bakuDateParts(offsetDays = 0) {
  const d = new Date(Date.now() - offsetDays * 86400000);
  const parts = new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Baku', day: '2-digit', month: '2-digit', year: 'numeric' })
    .formatToParts(d).reduce((a, p) => (a[p.type] = p.value, a), {});
  return `${parts.day}.${parts.month}.${parts.year}`;
}
async function fetchCbarEur() {
  for (let i = 0; i < 4; i++) {
    const r = await fetch(`https://www.cbar.az/currencies/${bakuDateParts(i)}.xml`, { signal: AbortSignal.timeout(6000) });
    if (!r.ok) continue;
    const xml = await r.text();
    const m = xml.match(/Code="EUR"[\s\S]*?<Nominal>([^<]+)<\/Nominal>[\s\S]*?<Value>([^<]+)<\/Value>/);
    if (m) { const v = parseFloat(m[2]) / parseFloat(String(m[1]).replace(/\D/g, '') || '1'); if (v > 0) return v; }
  }
  throw new Error('CBAR məzənnəsi tapılmadı');
}
async function fetchBackupEur() {
  const r = await fetch('https://open.er-api.com/v6/latest/EUR', { signal: AbortSignal.timeout(6000) });
  const j = await r.json();
  const v = j && j.rates && j.rates.AZN;
  if (!(v > 0)) throw new Error('Ehtiyat məzənnə alınmadı');
  return v;
}
async function getAznPerEur() {
  if (rateCache.aznPerEur && Date.now() - rateCache.at < RATE_TTL) return rateCache;
  try { rateCache = { aznPerEur: await fetchCbarEur(), at: Date.now(), source: 'CBAR' }; }
  catch (e1) {
    try { rateCache = { aznPerEur: await fetchBackupEur(), at: Date.now(), source: 'er-api' }; }
    catch (e2) {
      if (rateCache.aznPerEur) return rateCache;
      rateCache = { aznPerEur: Number(process.env.FALLBACK_AZN_PER_EUR || 1.98), at: Date.now() - RATE_TTL + 60000, source: 'fallback' };
    }
  }
  return rateCache;
}
let usdCache = { perEur: null, at: 0 };
async function getUsdPerEur() {
  if (usdCache.perEur && Date.now() - usdCache.at < RATE_TTL) return usdCache.perEur;
  try {
    const r = await fetch('https://open.er-api.com/v6/latest/EUR', { signal: AbortSignal.timeout(6000) });
    const j = await r.json();
    const v = j && j.rates && j.rates.USD;
    if (v > 0) { usdCache = { perEur: v, at: Date.now() }; return v; }
  } catch (_) {}
  return usdCache.perEur || 1.08;
}

function aznToEur(azn, aznPerEur, commissionPercent, fixedEur) {
  const target = azn / aznPerEur;
  const send = (target - (fixedEur || 0)) / (1 + (commissionPercent || 0) / 100);
  return (Math.round(send * 100) / 100).toFixed(2);
}
function payerTotal(sendEur, commissionPercent, fixedEur) {
  return (Number(sendEur) * (1 + (commissionPercent || 0) / 100) + (fixedEur || 0)).toFixed(2);
}

const sha256 = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const md5 = s => crypto.createHash('md5').update(s, 'utf8').digest('hex');
function safeEq(a, b) {
  a = Buffer.from(String(a || '')); b = Buffer.from(String(b || ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const eqHex = (a, b) => safeEq(String(a || '').toLowerCase(), String(b || '').toLowerCase());

function withTimeout(promise, ms) {
  return Promise.race([promise, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout ' + ms + 'ms')), ms))]);
}
async function authUser(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ success: false, error: 'Giriş tələb olunur' });
    req._stage = 'auth';
    try { req.user = await withTimeout(admin.auth().verifyIdToken(token), 15000); }
    catch (e) {
      if (/^timeout/.test(String(e && e.message))) return res.status(503).json({ success: false, error: 'Server məşğuldur' });
      throw e;
    }
    req._stage = 'handler';
    next();
  } catch (e) { res.status(401).json({ success: false, error: 'Etibarsız token' }); }
}

const uidHits = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of uidHits) if (now - v.t > 120000) uidHits.delete(k); }, 60000).unref();
function uidLimit(tag, max, windowMs) {
  return (req, res, next) => {
    const k = tag + ':' + (req.user && req.user.uid);
    const now = Date.now();
    let e = uidHits.get(k);
    if (!e || now - e.t > windowMs) e = { t: now, n: 0 };
    e.n++; uidHits.set(k, e);
    if (e.n > max) return res.status(429).json({ success: false, error: 'Çox sorğu' });
    next();
  };
}
const cbHits = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of cbHits) if (now - v.t > 60000) cbHits.delete(k); }, 60000).unref();
function callbackLimit(req, res, next) {
  const ip = String(req.realIp || req.ip || ''), now = Date.now();
  let e = cbHits.get(ip);
  if (!e || now - e.t > 60000) e = { t: now, n: 0 };
  e.n++; cbHits.set(ip, e);
  if (e.n > 300) return res.status(429).json({ result: { message: 'Too many requests' } });
  next();
}

/* ═══════════════════════════════════════════════════════════
   REGION ENDPOINT — Client dil və valyuta seçimi üçün
   ═══════════════════════════════════════════════════════════ */
app.get(['/region', '/api/region'], async (req, res) => {
  try {
    const info = region.resolveForRequest(req);
    const rates = {};
    try { const r = await getAznPerEur(); rates.aznPerEur = r.aznPerEur; } catch (_) {}
    try { rates.usdPerEur = await getUsdPerEur(); } catch (_) {}
    res.json({ success: true, ...info, rates });
  } catch (e) { res.status(500).json({ success: false, error: 'Server xətası' }); }
});

app.get(['/rate', '/api/rate'], async (req, res) => {
  try {
    const r = await getAznPerEur();
    res.json({ success: true, currency: CHARGE_CURRENCY, aznPerEur: r.aznPerEur, source: r.source });
  } catch (e) { res.status(503).json({ success: false, error: e.message }); }
});

/* ═══════════════════════════════════════════════════════════
   CREATE-PAYMENT (Pay4bit) — YALNIZ AZ istifadəçiləri üçün AZN,
   xaricdə EUR/USD. 2x bonus qalır.
   ═══════════════════════════════════════════════════════════ */
app.post(['/create-payment', '/api/create-payment'], authUser, uidLimit('pay', 10, 60000), async (req, res) => {
  try {
    const method = String(req.body.method || '');
    const purpose = req.body.purpose === 'deposit' ? 'deposit' : 'code';
    const platform = req.body.platform === 'chcplay' ? 'chcplay' : 'fastloto';
    if (!(method in MIN_AZN)) return res.status(400).json({ success: false, error: 'Yanlış ödəniş üsulu' });

    const curIn = String(req.body.currency || 'AZN').toUpperCase();
    const raw = String(req.body.amount ?? '').trim().replace(',', '.');
    if (!/^\d+(\.\d{1,2})?$/.test(raw)) return res.status(400).json({ success: false, error: 'Məbləğ yanlışdır' });
    let amountInCurrency = Number(raw);

    // Region: AZ və ya xarici
    const rg = region.resolveForRequest(req);
    // Xarici istifadəçi AZN istifadə edə bilməz, AZ istifadəçi EUR/USD istifadə edə bilməz (sadəlik üçün)
    const allowed = rg.currencyOptions; // AZ üçün ['AZN'], xarici üçün ['EUR','USD']
    if (!allowed.includes(curIn)) return res.status(400).json({ success: false, error: 'Bu valyuta icazəli deyil' });

    // Minimum yoxla
    const minAmt = purpose === 'deposit'
      ? (method === 'card' ? MIN_DEPOSIT_CARD_AZN : MIN_AZN[method]) // AZN-də
      : MIN_AZN[method];

    let azn;
    if (curIn === 'AZN') {
      if (amountInCurrency < minAmt) return res.status(400).json({ success: false, error: `Minimum ${minAmt} AZN` });
      if (amountInCurrency > MAX_AZN) return res.status(400).json({ success: false, error: `Maksimum ${MAX_AZN} AZN` });
      azn = amountInCurrency;
    } else {
      // EUR/USD → AZN
      const rates = await getAznPerEur().catch(() => ({ aznPerEur: 1.98 }));
      const usdPerEur = await getUsdPerEur().catch(() => 1.08);
      const eurAmount = curIn === 'EUR' ? amountInCurrency : amountInCurrency / usdPerEur;
      const minEur = minAmt / rates.aznPerEur;
      if (eurAmount < minEur) return res.status(400).json({ success: false, error: `Minimum ${minEur.toFixed(2)} ${curIn}` });
      azn = eurAmount * rates.aznPerEur;
      if (azn > MAX_AZN) return res.status(400).json({ success: false, error: 'Maksimum aşıldı' });
    }

    const { aznPerEur, source } = await getAznPerEur();
    const commission = COMMISSION_PERCENT[method] || 0;
    const fixedFee = COMMISSION_FIXED_EUR[method] || 0;
    const amount = aznToEur(azn, aznPerEur, commission, fixedFee);
    const payerTotalEur = payerTotal(amount, commission, fixedFee);
    console.log(`[create-payment] ${method} ${azn} AZN (${curIn}) | kurs ${aznPerEur} | ${amount} EUR`);
    if (Number(amount) < MIN_CHARGE) return res.status(400).json({ success: false, error: 'Məbləğ Pay4bit minimumundan (1 EUR) azdır' });

    const orderId = Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
    const account = orderId;
    const desc = purpose === 'deposit' ? `YevroLato depozit ${orderId}` : `YevroLato FASTLOTO kod ${orderId}`;
    const sign = sha256(desc + account + amount + SECRET_KEY);

    let uName = '', uUnique = '';
    try {
      const us = await db.collection('users').doc(req.user.uid).get();
      if (us.exists) { uName = us.data().displayName || ''; uUnique = us.data().uniqueId || ''; }
    } catch (_) {}

    await db.collection('payments').doc(orderId).set({
      uid: req.user.uid, userName: uName, userUniqueId: uUnique, method, status: 'pending',
      purpose, platform, commissionPercent: commission, commissionFixedEur: fixedFee,
      payerTotalEur, currencyIn: curIn,
      aznAmount: azn, chargeAmount: amount, chargeCurrency: CHARGE_CURRENCY,
      aznPerEur, rateSource: source, desc, createdAt: FieldValue.serverTimestamp()
    });

    const params = { public_key: PUBLIC_KEY, account, sum: amount, currency: CHARGE_CURRENCY, desc, sign };
    if (PAY_SYSTEM[method]) params.paySystem = PAY_SYSTEM[method];

    res.json({
      success: true, orderId, purpose,
      azn, charge: amount, currency: CHARGE_CURRENCY, aznPerEur, currencyIn: curIn,
      redirect_url: `${PAY4BIT_URL}?${new URLSearchParams(params).toString()}`
    });
  } catch (e) {
    console.error('[create-payment]', e);
    res.status(500).json({ success: false, error: 'Server xətası' });
  }
});

app.get(['/payment-status', '/api/payment-status'], authUser, async (req, res) => {
  try {
    const snap = await db.collection('payments').doc(String(req.query.order || '')).get();
    if (!snap.exists || snap.data().uid !== req.user.uid) return res.status(404).json({ success: false });
    const d = snap.data();
    res.json({
      success: true, status: d.status, azn: d.aznAmount, currencyIn: d.currencyIn || 'AZN',
      purpose: d.purpose || 'code', bonus: d.bonus || 0,
      codeStatus: d.codeStatus || null,
      code: d.codeStatus === 'delivered' ? d.code : null,
      codeRequestId: d.codeRequestId || null
    });
  } catch (e) {
    console.error('[payment-status]', e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

/* ═══════════════════════════════════════════════════════════
   KAMPANİYA (Pay4bit callback üçün)
   ═══════════════════════════════════════════════════════════ */
const CAMPAIGN_END = new Date(process.env.CAMPAIGN_END_ISO || '2026-12-31T20:00:00Z');
const CAMPAIGN_START = process.env.CAMPAIGN_START_ISO ? new Date(process.env.CAMPAIGN_START_ISO) : null;
const YE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function genYeKod() {
  const b = crypto.randomBytes(8);
  let c = '';
  for (let i = 0; i < 8; i++) c += YE_ALPHABET[b[i] % YE_ALPHABET.length];
  return 'YE-' + c.slice(0, 4) + '-' + c.slice(4);
}
function campaignActive() {
  const now = new Date();
  return now < CAMPAIGN_END && (!CAMPAIGN_START || now >= CAMPAIGN_START);
}

/* ═══════════════════════════════════════════════════════════
   PAY4BIT CALLBACK (depozit/kod üçün) — 2x bonus var
   ═══════════════════════════════════════════════════════════ */
async function pay4bitCallback(req, res) {
  const reply = (message, code = 200) => res.status(code).json({ result: { message } });
  try {
    const q = { ...(req.query || {}), ...(req.body || {}) };
    let p = q.params;
    if (typeof p === 'string') { try { p = JSON.parse(p); } catch (_) { p = null; } }
    if (!p || typeof p !== 'object') {
      p = {};
      for (const k of Object.keys(q)) { const m = k.match(/^params\[(.+)\]$/); if (m) p[m[1]] = q[k]; }
      if (!Object.keys(p).length) p = q;
    }
    const method = String(q.method || p.method || '').toLowerCase();
    const str = v => (v === undefined || v === null) ? '' : String(v);
    const account = str(p.account);
    const desc = str(p.desc);
    const uniq = arr => [...new Set(arr.filter(x => x !== ''))];

    let signedSum = null, signedAmt = null;
    if (p.sign && p.localpayId) {
      for (const sv of uniq([str(p.sum), str(p.amount), str(p.orderSum), str(p.payerSum)])) {
        if (eqHex(md5(str(p.localpayId) + account + sv + SECRET_KEY), p.sign)) { signedSum = sv; break; }
      }
    }
    if (p.check_sign) {
      for (const sv of uniq([str(p.amount), str(p.sum)])) {
        if (eqHex(sha256(desc + account + sv + SECRET_KEY), p.check_sign)) { signedAmt = sv; break; }
      }
    }
    const okSign = signedSum !== null, okCheck = signedAmt !== null;
    if (!okCheck && !okSign) return reply('Invalid signature', 400);

    const ref = db.collection('payments').doc(account);
    const snap = await ref.get();
    if (!snap.exists) return reply('Order not found', 404);
    const order = snap.data();

    if (method === 'pay' && PAY_REQUIRE_SIGN && !okSign) {
      await ref.update({ cbIssue: 'pay_needs_md5_sign', cbIssueAt: FieldValue.serverTimestamp() }).catch(() => {});
      return reply('Invalid signature', 400);
    }

    const signed = okSign ? signedSum : signedAmt;
    const expected = [order.chargeAmount, order.payerTotalEur].filter(x => x !== undefined && x !== null && x !== '').map(x => Number(x).toFixed(2));
    const curr = String(p.currency || '').toUpperCase();
    if (!expected.includes(Number(signed).toFixed(2)) || (curr && curr !== order.chargeCurrency)) {
      await ref.update({ cbIssue: 'amount_mismatch:' + signed + ' ' + curr, cbIssueAt: FieldValue.serverTimestamp() }).catch(() => {});
      return reply('Amount mismatch', 400);
    }

    if (method === 'check') return reply('Request successfully processed');
    if (method === 'error') {
      if (order.status === 'pending') await ref.update({ status: 'failed', failedAt: FieldValue.serverTimestamp() });
      return reply('Request successfully processed');
    }

    if (method === 'pay') {
      const round2 = n => Math.round(n * 100) / 100;
      await db.runTransaction(async tx => {
        const cur = await tx.get(ref);
        if (cur.data().status === 'paid') return;
        const purpose = order.purpose === 'deposit' ? 'deposit' : 'code';
        const userRef = db.collection('users').doc(order.uid);
        const userSnap = await tx.get(userRef);
        const u = userSnap.exists ? userSnap.data() : {};
        let poolDoc = null, poolCode = '';
        if (purpose === 'code') {
          const ps = await tx.get(db.collection('fastlotoCodes')
            .where('amount', '==', order.aznAmount).where('status', '==', 'available').limit(30));
          for (const dd of ps.docs) {
            const sd = await tx.get(db.collection('fastlotoSecrets').doc(dd.id));
            const c = String((sd.exists && sd.data().code) || dd.data().code || '').trim();
            if (c) { poolDoc = dd; poolCode = c; break; }
          }
        }

        let campaignNew = null;
        if (purpose === 'deposit' && campaignActive()) {
          for (let i = 0; i < 6 && !campaignNew; i++) {
            const cand = genYeKod();
            const cs = await tx.get(DB_BASKET.collection('campaignCodes').doc(cand));
            if (!cs.exists) campaignNew = cand;
          }
        }

        const platform = order.platform || 'fastloto';
        // Pay4bit depozitində: 2x bonus (ilk depozit "pending" idisə)
        const wheelPending = (u.firstDepositBonus === 'pending');
        const bonus = (purpose === 'deposit' || wheelPending) ? round2(order.aznAmount) : 0;
        const payUpdate = {
          status: 'paid', purpose, bonus, userName: u.displayName || order.userName || '',
          userUniqueId: u.uniqueId || order.userUniqueId || '',
          localpayId: String(p.localpayId || ''),
          paymentType: String(p.paymentType || ''), paidAt: FieldValue.serverTimestamp()
        };

        const userUpd = { points: FieldValue.increment(order.aznAmount) };
        let balanceAdd = 0;
        if (purpose === 'deposit') balanceAdd += order.aznAmount;
        if (bonus > 0) { balanceAdd += bonus; if (wheelPending) userUpd.firstDepositBonus = 'used'; }
        if (balanceAdd > 0) userUpd.balance = FieldValue.increment(round2(balanceAdd));
        if (purpose === 'deposit') userUpd.hasDeposited = true;
        if (purpose === 'deposit') userUpd.totalDepositedAZN = FieldValue.increment(round2(order.aznAmount));
        tx.update(userRef, userUpd);

        if (purpose === 'deposit') {
          tx.set(userRef.collection('history').doc('pay_' + account), {
            type: 'deposit', amount: order.aznAmount,
            description: 'Pay4bit depozit (' + order.method + ')', createdAt: FieldValue.serverTimestamp()
          });
        }
        if (campaignNew) {
          tx.set(DB_BASKET.collection('campaignCodes').doc(campaignNew), {
            code: campaignNew, uniqueId: u.uniqueId || order.userUniqueId || '',
            source: 'deposit', orderId: account, amount: order.aznAmount, createdAt: FieldValue.serverTimestamp()
          });
          payUpdate.campaignCode = campaignNew;
        }
        if (bonus > 0) {
          tx.set(userRef.collection('history').doc('bonus_' + account), {
            type: 'bonus', amount: bonus,
            description: wheelPending ? '2x bonus: ilk depozit' : 'Depozit bonusu: 2x balans', createdAt: FieldValue.serverTimestamp()
          });
        }

        if (purpose === 'code') {
          if (poolDoc) {
            const codeStr = poolCode;
            tx.update(poolDoc.ref, {
              status: 'used', usedByUid: order.uid,
              usedByUniqueId: u.uniqueId || '', usedAt: FieldValue.serverTimestamp()
            });
            tx.set(userRef.collection('codes').doc('pay_' + account), {
              code: codeStr, platform, amount: order.aznAmount, source: 'pool',
              status: 'active', createdAt: FieldValue.serverTimestamp()
            });
            tx.set(userRef.collection('history').doc('pay_' + account), {
              type: 'withdraw', amount: -order.aznAmount,
              description: platform.toUpperCase() + ' Kod Alışı (Pay4bit)', createdAt: FieldValue.serverTimestamp()
            });
            payUpdate.codeStatus = 'delivered';
            payUpdate.code = codeStr;
          } else {
            tx.set(db.collection('codeRequests').doc(account), {
              uid: order.uid, userName: u.displayName || '', userUniqueId: u.uniqueId || '',
              platform, amount: order.aznAmount, status: 'pending', code: '',
              paid: true, orderId: account, createdAt: FieldValue.serverTimestamp()
            });
            payUpdate.codeStatus = 'admin_pending';
            payUpdate.codeRequestId = account;
          }
        }
        tx.update(ref, payUpdate);
      });
      return reply('Request successfully processed');
    }
    return reply('Unknown method', 400);
  } catch (e) { console.error('[callback]', e); return reply('Server error', 500); }
}
app.get('/pay4bit/callback', callbackLimit, pay4bitCallback);
app.post('/pay4bit/callback', callbackLimit, pay4bitCallback);

/* ═══════════════════════════════════════════════════════════
   OTP (SMS) — simulyasiya bütün ölkələr üçün
   ═══════════════════════════════════════════════════════════ */
const OTP_API_KEY = String(process.env.OTP_API_KEY || '').trim().replace(/^["']+|["']+$/g, '');
const OTP_BASE = (process.env.OTP_BASE_URL || 'https://api.otpbay.com').trim().replace(/\/+$/, '').replace(/\/v1$/i, '') + '/v1';
const OTP_COOLDOWN_MS = 60 * 1000;
const OTP_MAX_SENDS_PER_HOUR = 5;
const OTP_MAX_ATTEMPTS = 5;
const SMS_SIMULATE = String(process.env.SMS_SIMULATE || 'true').trim().toLowerCase() !== 'false';
const SIM_CODE_TTL_MS = 10 * 60 * 1000;
const simHash = (uid, phone, code) => crypto.createHash('sha256').update(`${uid}|${phone}|${code}|yl-sms-sim`).digest('hex');
const OTP_IP_MAX_PER_HOUR = Math.max(20, Number(process.env.OTP_IP_MAX_PER_HOUR) || 60);
const otpIpHits = new Map();

function normPhone(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  const plus = s.startsWith('+');
  let d = s.replace(/\D/g, '');
  if (!d) return null;
  if (!plus && !d.startsWith('00') && d.length <= 12) {
    // heç bir ölkə kodu yoxdur → AZ default (köhnə davranış)
    if (d.length === 10 && d.startsWith('0')) d = '994' + d.slice(1);
    else if (d.length === 9) d = '994' + d;
  }
  if (d.startsWith('00')) d = d.slice(2);
  if (d.length < 10 || d.length > 15) return null;
  return '+' + d;
}

async function otpFinalize(uid, phone) {
  const ref = db.collection('users').doc(uid);
  let out = { phoneVerified: false };
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    const u = snap.exists ? snap.data() : {};
    tx.update(ref, { phone, phoneVerified: true, phoneVerifiedAt: FieldValue.serverTimestamp() });
    out.phoneVerified = true;
    out.alreadyVerified = u.phoneVerified === true;
  });
  await db.collection('otpSessions').doc(uid).delete().catch(() => {});
  return out;
}

async function otpSend(req, res, isResend) {
  try {
    const uid = req.user.uid;
    const ip = req.realIp || req.ip;
    const now = Date.now();
    const arr = (otpIpHits.get(ip) || []).filter(t => now - t < 3600000);
    if (arr.length >= OTP_IP_MAX_PER_HOUR) return res.status(429).json({ success: false, error: 'Çox cəhd' });
    arr.push(now); otpIpHits.set(ip, arr);

    const us = await db.collection('users').doc(uid).get();
    if (!us.exists) return res.status(404).json({ success: false, error: 'İstifadəçi tapılmadı' });
    const u = us.data();
    if (u.phoneVerified === true) return res.json({ success: true, alreadyVerified: true, phone: u.phone || '' });

    const phone = normPhone(u.phone);
    if (!phone) return res.status(400).json({ success: false, error: 'Əvvəlcə düzgün nömrə əlavə edin' });

    const sref = db.collection('otpSessions').doc(uid);
    const s = (await sref.get()).data() || {};
    const sends = (Array.isArray(s.sends) ? s.sends : []).filter(t => Number(t) && now - t < 3600000);
    if (sends.length) {
      const wait = OTP_COOLDOWN_MS - (now - sends[sends.length - 1]);
      if (wait > 0) return res.status(429).json({ success: false, error: `${Math.ceil(wait/1000)} saniyə sonra`, retryAfter: Math.ceil(wait/1000) });
    }
    if (sends.length >= OTP_MAX_SENDS_PER_HOUR) return res.status(429).json({ success: false, error: 'Saatlıq limit' });

    if (SMS_SIMULATE) {
      const out = await otpFinalize(uid, phone);
      return res.json({ success: true, simulated: true, verified: true, phone, ...out, cooldown: 0 });
    }
    return res.status(503).json({ success: false, error: 'SMS xidməti hazırda əlçatmazdır' });
  } catch (e) {
    console.error('[otp-send]', e);
    res.status(500).json({ success: false, error: 'Server xətası' });
  }
}
app.post(['/otp/send', '/api/otp/send'], authUser, (req, res) => otpSend(req, res, false));
app.post(['/otp/resend', '/api/otp/resend'], authUser, (req, res) => otpSend(req, res, true));

/* ═══════════════════════════════════════════════════════════
   BUY-CODE (balansdan)
   ═══════════════════════════════════════════════════════════ */
const round2g = n => Math.round((Number(n) || 0) * 100) / 100;

app.post(['/buy-code', '/api/buy-code'], authUser, uidLimit('buy', 12, 60000), async (req, res) => {
  try {
    const platform = req.body.platform === 'chcplay' ? 'chcplay' : 'fastloto';
    const raw = String(req.body.amount ?? '').trim().replace(',', '.');
    if (!/^\d+(\.\d{1,2})?$/.test(raw)) return res.status(400).json({ success: false, error: 'Məbləğ yanlışdır' });
    const amount = round2g(raw);
    if (!(amount > 0) || amount > MAX_AZN) return res.status(400).json({ success: false, error: 'Məbləğ yanlışdır' });
    const uid = req.user.uid;

    const out = await db.runTransaction(async tx => {
      const userRef = db.collection('users').doc(uid);
      const userSnap = await tx.get(userRef);
      if (!userSnap.exists) throw new Error('user_not_found');
      const u = userSnap.data();
      if (u.banned === true) throw new Error('banned');
      const bal = Number(u.balance) || 0;
      if (bal + 0.0001 < amount) throw new Error('balance');

      const ps = await tx.get(db.collection('fastlotoCodes')
        .where('amount', '==', amount).where('status', '==', 'available').limit(30));
      let poolDoc = null, codeStr = '';
      for (const dd of ps.docs) {
        const sd = await tx.get(db.collection('fastlotoSecrets').doc(dd.id));
        const c = String((sd.exists && sd.data().code) || dd.data().code || '').trim();
        if (c) { poolDoc = dd; codeStr = c; break; }
      }
      if (!poolDoc) return { noCode: true };

      const nb = round2g(bal - amount);
      tx.update(poolDoc.ref, {
        status: 'used', usedByUid: uid, usedByUniqueId: String(u.uniqueId || ''), usedAt: FieldValue.serverTimestamp()
      });
      tx.update(userRef, { balance: nb });
      tx.set(userRef.collection('codes').doc('pool_' + poolDoc.id), {
        code: codeStr, platform, amount, source: 'pool', status: 'active', createdAt: FieldValue.serverTimestamp()
      });
      tx.set(userRef.collection('history').doc('pool_' + poolDoc.id), {
        type: 'withdraw', amount: -amount,
        description: platform.toUpperCase() + ' Kod Alışı (Balans)', createdAt: FieldValue.serverTimestamp()
      });
      return { code: codeStr, balance: nb };
    });

    if (out.noCode) return res.json({ success: true, status: 'no_code' });
    return res.json({ success: true, status: 'delivered', code: out.code, balance: out.balance, amount, platform });
  } catch (e) {
    const m = e && e.message;
    if (m === 'balance') return res.status(409).json({ success: false, error: 'balance' });
    if (m === 'banned') return res.status(403).json({ success: false, error: 'banned' });
    if (m === 'user_not_found') return res.status(404).json({ success: false, error: 'user_not_found' });
    console.error('[buy-code]', e);
    return res.status(500).json({ success: false, error: 'server_error' });
  }
});

/* ═══════════════════════════════════════════════════════════
   ADMIN GUARD
   ═══════════════════════════════════════════════════════════ */
const SUPER_ADMIN_UID = process.env.SUPER_ADMIN_UID || 'dIxZVPfOLIPZW0xqtcTeg7JXRnN2';
async function requireFullAdmin(req, res, next) {
  try {
    const uid = req.user.uid;
    if (uid !== SUPER_ADMIN_UID) {
      const s = await db.collection('admins').doc(uid).get();
      const d = s.exists ? s.data() : null;
      if (!d || d.active !== true || d.role === 'support') return res.status(403).json({ success: false, error: 'İcazə yoxdur' });
    }
    next();
  } catch (e) { console.error('[admin-auth]', e); res.status(500).json({ success: false, error: 'server_error' }); }
}

app.post(['/admin/adjust-balance', '/api/admin/adjust-balance'], authUser, uidLimit('adm', 60, 60000), requireFullAdmin, async (req, res) => {
  try {
    const target = String(req.body.uid || '').trim();
    const amt = round2g(req.body.amount);
    const why = String(req.body.reason || 'Admin düzəlişi').slice(0, 200);
    if (!target || target.length > 128 || !amt || Math.abs(amt) > 100000) return res.status(400).json({ success: false, error: 'Məbləğ yanlışdır' });
    const ref = db.collection('users').doc(target);
    let nb = 0;
    await db.runTransaction(async tx => {
      const s = await tx.get(ref);
      if (!s.exists) throw new Error('user_not_found');
      nb = round2g((Number(s.data().balance) || 0) + amt);
      if (nb < 0) throw new Error('negative');
      tx.update(ref, { balance: nb });
      tx.set(ref.collection('history').doc(), {
        type: amt >= 0 ? 'deposit' : 'withdraw', amount: amt, description: why, createdAt: FieldValue.serverTimestamp()
      });
    });
    res.json({ success: true, balance: nb });
  } catch (e) {
    const m = e && e.message;
    if (m === 'user_not_found') return res.status(404).json({ success: false, error: 'İstifadəçi tapılmadı' });
    if (m === 'negative') return res.status(400).json({ success: false, error: 'Balans mənfi ola bilməz' });
    res.status(500).json({ success: false, error: 'server_error' });
  }
});

/* ═══════════════════════════════════════════════════════════
   YENİ ROUTE-LAR
   ═══════════════════════════════════════════════════════════ */
require('./p2p-route')(app, { admin, db, DB_ANALYTICS, authUser, uidLimit, callbackLimit, region, round2g, FieldValue, requireFullAdmin });
require('./gift-route')(app, { admin, db, authUser, uidLimit, region });
require('./betatransfer-route')(app, { admin, db, authUser, uidLimit, callbackLimit, genYeKod, campaignActive });
require('./password-reset-route')(app, { admin, db });
require('./payouts-route')(app, { db });

/* ═══════════════════════════════════════════════════════════
   HEALTH
   ═══════════════════════════════════════════════════════════ */
async function fsPing() {
  const t = Date.now();
  await withTimeout(db.collection('_health').doc('ping').get(), 25000);
  return Date.now() - t;
}
app.get(['/health/deep', '/api/health/deep'], async (req, res) => {
  try { res.json({ ok: true, firestoreMs: await fsPing(), p2: !!dbBasket, p3: !!dbAnalytics }); }
  catch (e) { res.status(503).json({ ok: false, error: String(e && e.message || e) }); }
});
app.get(['/health', '/api/health'], (req, res) => res.json({ ok: true }));
app.get('/', (req, res) => res.json({ ok: true }));

app.use((req, res) => res.status(404).json({ success: false, error: 'Tapılmadı' }));
app.use((err, req, res, next) => { console.error('[express]', err); res.status(500).json({ success: false, error: 'Server xətası' }); });
process.on('unhandledRejection', e => console.error('[unhandledRejection]', e));
process.on('uncaughtException', e => console.error('[uncaughtException]', e));

const PORT = process.env.PORT || 10000;
const server = app.listen(PORT, '0.0.0.0', () => console.log(`Server ${PORT} portunda işləyir`));
server.keepAliveTimeout = 120 * 1000;
server.headersTimeout = 125 * 1000;
fsPing().then(ms => console.log('[warmup] Firestore hazırdır,', ms, 'ms')).catch(e => console.warn('[warmup] Firestore:', e.message));

/* Basket sync — campaign kodları 2-ci layihəyə */
const BASKET_MAX = 300;
let basketBusy = false, basketLastErr = '';
async function syncCampaignBasket() {
  if (!dbBasket || basketBusy) return;
  basketBusy = true;
  try {
    const ref2 = dbBasket.collection('public').doc('campaignBasket');
    const snap2 = await withTimeout(ref2.get(), 30000);
    const prev = snap2.exists ? (snap2.data() || {}) : {};
    const lastMs = Number(prev.syncedMs) || 0;
    let q = db.collection('campaignCodes');
    q = lastMs
      ? q.where('createdAt', '>=', admin.firestore.Timestamp.fromMillis(Math.max(0, lastMs - 120000))).orderBy('createdAt', 'desc').limit(BASKET_MAX)
      : q.orderBy('createdAt', 'desc').limit(BASKET_MAX);
    const res = await withTimeout(q.get(), 30000);
    const map = new Map((Array.isArray(prev.items) ? prev.items : []).map(x => [x.code, x]));
    let changed = !snap2.exists, maxMs = lastMs;
    for (const d of res.docs) {
      const x = d.data() || {};
      if (!x.code) continue;
      const ms = x.createdAt && x.createdAt.toMillis ? x.createdAt.toMillis() : 0;
      const item = { code: String(x.code), uniqueId: String(x.uniqueId || ''), source: String(x.source || ''), s: Math.floor(ms / 1000) };
      const old = map.get(item.code);
      if (!old || old.uniqueId !== item.uniqueId || old.s !== item.s) changed = true;
      map.set(item.code, item);
      if (ms > maxMs) maxMs = ms;
    }
    basketLastErr = '';
    if (!changed) return;
    const items = [...map.values()].sort((a, b) => (b.s || 0) - (a.s || 0)).slice(0, BASKET_MAX);
    await withTimeout(ref2.set({ items, count: items.length, syncedMs: maxMs || Date.now(), updatedAt: FieldValue.serverTimestamp() }), 30000);
  } catch (e) {
    const m = String(e && e.message || e);
    if (m !== basketLastErr) console.warn('[basket] sinxron xətası:', m);
    basketLastErr = m;
  } finally { basketBusy = false; }
}
if (dbBasket) { setTimeout(syncCampaignBasket, 60000); setInterval(syncCampaignBasket, 15 * 60 * 1000); }