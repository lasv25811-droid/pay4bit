/**
 * YevroLato – Pay4bit backend
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
  console.error('PAY4BIT_PUBLIC_KEY / PAY4BIT_SECRET_KEY mühit dəyişənləri təyin olunmayıb.');
  process.exit(1);
}

const FIREBASE_SA = null;
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

let SA = null;
try {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_B64
    ? Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8')
    : process.env.FIREBASE_SERVICE_ACCOUNT;
  if (raw && raw.trim()) SA = JSON.parse(raw.trim());
} catch (e) {
  console.error('FIREBASE_SERVICE_ACCOUNT JSON kimi oxunmadı:', e.message);
}
if (!SA) SA = FIREBASE_SA;
if (!SA || !SA.private_key || !SA.client_email) {
  console.error('Firebase service account tapılmadı və ya natamamdır.');
  process.exit(1);
}
SA.private_key = String(SA.private_key).replace(/\\n/g, '\n');

admin.initializeApp({ credential: admin.credential.cert(SA) });
const db = admin.firestore();
try { db.settings({ ignoreUndefinedProperties: true }); } catch (_) {}
const FieldValue = admin.firestore.FieldValue;

// 2-ci Firebase layihəsi (yevrolato2)
let db2 = null;
try {
  const raw2 = process.env.FIREBASE_SERVICE_ACCOUNT_2_B64
    ? Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_2_B64, 'base64').toString('utf8')
    : process.env.FIREBASE_SERVICE_ACCOUNT_2;
  if (raw2 && raw2.trim()) {
    const SA2 = JSON.parse(raw2.trim());
    SA2.private_key = String(SA2.private_key || '').replace(/\\n/g, '\n');
    const app2 = admin.initializeApp({ credential: admin.credential.cert(SA2) }, 'p2');
    db2 = app2.firestore();
    try { db2.settings({ ignoreUndefinedProperties: true }); } catch (_) {}
    console.log('[p2] 2-ci Firebase layihəsi qoşuldu:', SA2.project_id);
  } else {
    console.log('[p2] FIREBASE_SERVICE_ACCOUNT_2 verilməyib.');
  }
} catch (e) { console.error('[p2] qoşulmadı:', e.message); db2 = null; }

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

function getClientIp(req) {
  const h = req.headers || {};
  const pick = v => String(Array.isArray(v) ? v[0] : (v || '')).split(',')[0].trim();
  const ip = pick(h['cf-connecting-ip']) || pick(h['true-client-ip']) || String(req.ip || '');
  return ip.replace(/^::ffff:/i, '');
}
app.use((req, res, next) => { req.realIp = getClientIp(req); next(); });

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
      console.error(`[timeout] 30 saniyədə cavab hazır olmadı: ${req.method} ${req.path} mərhələ=${req._stage}`);
      res.status(503).json({ success: false, error: 'Server məşğuldur, bir az sonra yenidən cəhd edin' });
    }
  }, 30000);
  const done = () => { clearTimeout(t); const ms = Date.now() - t0; if (ms > 5000) console.warn(`[slow] ${req.method} ${req.path} ${ms}ms mərhələ=${req._stage}`); };
  res.on('finish', done);
  res.on('close', () => clearTimeout(t));
  next();
});

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
    if (m) {
      const v = parseFloat(m[2]) / parseFloat(String(m[1]).replace(/\D/g, '') || '1');
      if (v > 0) return v;
    }
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
async function authUser(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ success: false, error: 'Giriş tələb olunur' });
    req._stage = 'auth';
    try { req.user = await withTimeout(admin.auth().verifyIdToken(token), 15000); }
    catch (e) {
      if (/^timeout/.test(String(e && e.message))) { return res.status(503).json({ success: false, error: 'Server məşğuldur, bir az sonra yenidən cəhd edin' }); }
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
    if (e.n > max) return res.status(429).json({ success: false, error: 'Çox sorğu, bir az sonra yoxlayın' });
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

app.get(['/rate', '/api/rate'], async (req, res) => {
  try {
    const r = await getAznPerEur();
    res.json({ success: true, currency: CHARGE_CURRENCY, aznPerEur: r.aznPerEur, source: r.source });
  } catch (e) { res.status(503).json({ success: false, error: e.message }); }
});

app.post(['/create-payment', '/api/create-payment'], authUser, uidLimit('pay', 10, 60000), async (req, res) => {
  try {
    const method = String(req.body.method || '');
    const purpose = req.body.purpose === 'deposit' ? 'deposit' : 'code';
    const platform = req.body.platform === 'chcplay' ? 'chcplay' : 'fastloto';
    if (!(method in MIN_AZN)) return res.status(400).json({ success: false, error: 'Yanlış ödəniş üsulu' });

    const raw = String(req.body.amount ?? '').trim().replace(',', '.');
    if (!/^\d+(\.\d{1,2})?$/.test(raw)) return res.status(400).json({ success: false, error: 'Məbləğ yanlışdır' });
    const azn = Number(raw);
    const minNeeded = (purpose === 'deposit' && method === 'card') ? MIN_DEPOSIT_CARD_AZN : MIN_AZN[method];
    if (azn < minNeeded) return res.status(400).json({ success: false, error: `Minimum ${minNeeded} AZN` });
    if (azn > MAX_AZN) return res.status(400).json({ success: false, error: `Maksimum ${MAX_AZN} AZN` });

    const { aznPerEur, source } = await getAznPerEur();
    const commission = COMMISSION_PERCENT[method] || 0;
    const fixedFee = COMMISSION_FIXED_EUR[method] || 0;
    const amount = aznToEur(azn, aznPerEur, commission, fixedFee);
    const payerTotalEur = payerTotal(amount, commission, fixedFee);
    console.log(`[create-payment] ${method} ${azn} AZN | kurs ${aznPerEur} | ${amount} EUR | səhifədə ≈ ${payerTotalEur} EUR`);
    if (Number(amount) < MIN_CHARGE) {
      return res.status(400).json({ success: false, error: 'Məbləğ Pay4bit minimumundan (1 EUR) azdır' });
    }

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
      payerTotalEur,
      aznAmount: azn, chargeAmount: amount, chargeCurrency: CHARGE_CURRENCY,
      aznPerEur, rateSource: source, desc, createdAt: FieldValue.serverTimestamp()
    });

    const params = { public_key: PUBLIC_KEY, account, sum: amount, currency: CHARGE_CURRENCY, desc, sign };
    if (PAY_SYSTEM[method]) params.paySystem = PAY_SYSTEM[method];

    res.json({
      success: true, orderId, purpose,
      azn, charge: amount, currency: CHARGE_CURRENCY, aznPerEur,
      redirect_url: `${PAY4BIT_URL}?${new URLSearchParams(params).toString()}`
    });
  } catch (e) {
    console.error('[create-payment]', e);
    res.status(500).json({ success: false, error: 'Server xətası, yenidən cəhd edin' });
  }
});

app.get(['/payment-status', '/api/payment-status'], authUser, async (req, res) => {
  try {
    const snap = await db.collection('payments').doc(String(req.query.order || '')).get();
    if (!snap.exists || snap.data().uid !== req.user.uid) return res.status(404).json({ success: false });
    const d = snap.data();
    res.json({
      success: true, status: d.status, azn: d.aznAmount,
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

    if (!okCheck && !okSign) { return reply('Invalid signature', 400); }

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
            const cs = await tx.get(db.collection('campaignCodes').doc(cand));
            if (!cs.exists) campaignNew = cand;
          }
        }

        const platform = order.platform || 'fastloto';
        const wheelPending = (u.firstDepositBonus === 'pending');
        const bonus = (purpose === 'deposit' || wheelPending) ? round2(order.aznAmount) : 0;
        const payUpdate = {
          status: 'paid', purpose, bonus, userName: u.displayName || order.userName || '',
          userUniqueId: u.uniqueId || order.userUniqueId || '',
          localpayId: String(p.localpayId || ''),
          paymentType: String(p.paymentType || ''), paidAt: FieldValue.serverTimestamp()
        };

        const userUpd = { points: FieldValue.increment(order.aznAmount) };
        if (purpose === 'deposit') userUpd.payWheelSpins = FieldValue.increment(1);
        let balanceAdd = 0;
        if (purpose === 'deposit') balanceAdd += order.aznAmount;
        if (bonus > 0) { balanceAdd += bonus; if (wheelPending) userUpd.firstDepositBonus = 'used'; }
        if (balanceAdd > 0) userUpd.balance = FieldValue.increment(round2(balanceAdd));
        if (purpose === 'deposit') userUpd.hasDeposited = true;
        tx.update(userRef, userUpd);

        if (purpose === 'deposit') {
          tx.set(userRef.collection('history').doc('pay_' + account), {
            type: 'deposit', amount: order.aznAmount,
            description: 'Pay4bit depozit (' + order.method + ')', createdAt: FieldValue.serverTimestamp()
          });
        }
        if (campaignNew) {
          tx.set(db.collection('campaignCodes').doc(campaignNew), {
            code: campaignNew, uniqueId: u.uniqueId || order.userUniqueId || '',
            source: 'deposit', orderId: account, amount: order.aznAmount, createdAt: FieldValue.serverTimestamp()
          });
          payUpdate.campaignCode = campaignNew;
        }
        if (bonus > 0) {
          tx.set(userRef.collection('history').doc('bonus_' + account), {
            type: 'bonus', amount: bonus,
            description: wheelPending ? 'PayÇarx bonus: ilk depozitin 2 qatı' : 'Depozit bonusu: 2 qat balans', createdAt: FieldValue.serverTimestamp()
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
  } catch (e) {
    console.error('[callback]', e);
    return reply('Server error', 500);
  }
}
app.get('/pay4bit/callback', callbackLimit, pay4bitCallback);
app.post('/pay4bit/callback', callbackLimit, pay4bitCallback);

const OTP_API_KEY = String(process.env.OTP_API_KEY || '').trim().replace(/^["']+|["']+$/g, '');
const OTP_BASE = (process.env.OTP_BASE_URL || 'https://api.otpbay.com').trim().replace(/\/+$/, '').replace(/\/v1$/i, '') + '/v1';
const OTP_LOCALE = process.env.OTP_LOCALE || '';
const OTP_COOLDOWN_MS = 60 * 1000;
const OTP_MAX_SENDS_PER_HOUR = 5;
const OTP_MAX_ATTEMPTS = 5;
const SMS_SIMULATE = String(process.env.SMS_SIMULATE || 'true').trim().toLowerCase() !== 'false';
const SIM_CODE_TTL_MS = 10 * 60 * 1000;
const simHash = (uid, phone, code) => crypto.createHash('sha256').update(`${uid}|${phone}|${code}|yl-sms-sim`).digest('hex');
const OTP_IP_MAX_PER_HOUR = Math.max(20, Number(process.env.OTP_IP_MAX_PER_HOUR) || 60);
const otpIpHits = new Map();

function normPhoneAz(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  const plus = s.startsWith('+');
  let d = s.replace(/\D/g, '');
  if (!d) return null;
  if (!plus) {
    if (d.startsWith('00')) d = d.slice(2);
    else if (d.startsWith('994')) { }
    else if (d.length === 10 && d.startsWith('0')) d = '994' + d.slice(1);
    else if (d.length === 9) d = '994' + d;
    else return null;
  }
  if (d.length < 10 || d.length > 15) return null;
  if (d.startsWith('994') && d.length !== 12) return null;
  return '+' + d;
}

async function otpApi(method, path, body) {
  try {
    const r = await fetch(OTP_BASE + path, {
      method,
      headers: { Authorization: 'Bearer ' + OTP_API_KEY, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(15000)
    });
    const data = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: { error: { type: 'network', message: String((e && e.message) || e) } } };
  }
}
function otpFail(res, r) {
  const map = {
    0:   [502, 'SMS xidməti ilə əlaqə qurulmadı, bir az sonra yenidən cəhd edin'],
    401: [502, 'SMS xidməti müvəqqəti əlçatmazdır'],
    402: [502, 'SMS xidməti müvəqqəti əlçatmazdır'],
    403: [502, 'SMS xidməti müvəqqəti əlçatmazdır'],
    404: [400, 'Kodun vaxtı bitib, yenidən göndərin'],
    409: [409, 'Bu nömrə üçün SMS kanalı aktiv deyil'],
    400: [400, 'Nömrə və ya kod düzgün deyil'],
    422: [400, 'Nömrə və ya kod düzgün deyil'],
    429: [429, 'Çox tez cəhd edildi, bir az gözləyin']
  };
  const m = map[r.status] || [502, 'SMS xidməti müvəqqəti əlçatmazdır'];
  return res.status(m[0]).json({ success: false, error: m[1] });
}
function otpIpAllowed(ip) {
  const now = Date.now();
  const arr = (otpIpHits.get(ip) || []).filter(t => now - t < 3600000);
  if (arr.length >= OTP_IP_MAX_PER_HOUR) { otpIpHits.set(ip, arr); return false; }
  arr.push(now); otpIpHits.set(ip, arr);
  return true;
}
const otpPick = (d, ...keys) => { for (const k of keys) if (d && d[k] !== undefined && d[k] !== null) return d[k]; return undefined; };

async function otpFinalize(uid, phone) {
  const ref = db.collection('users').doc(uid);
  let out = { bonus: 0, spinBonus: 0, spins: 0, points: 0 };
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    const u = snap.exists ? snap.data() : {};
    const upd = { phone, phoneVerified: true, phoneVerifiedAt: FieldValue.serverTimestamp() };
    let spins = Math.max(0, Math.floor(Number(u.payWheelSpins) || 0));
    if (u.phoneSpinGiven !== true) {
      spins += 1;
      upd.payWheelSpins = spins;
      upd.phoneSpinGiven = true;
      upd.welcomeSpinGiven = true;
      out.spinBonus = 1;
      tx.set(ref.collection('history').doc(), {
        type: 'bonus', amount: 0, description: 'Nömrə doğrulama: 1 PayÇarx', createdAt: FieldValue.serverTimestamp()
      });
    }
    out.spins = spins;
    out.points = Number(u.points) || 0;
    tx.update(ref, upd);
  });
  await db.collection('otpSessions').doc(uid).delete().catch(() => {});
  return out;
}

async function otpSend(req, res, isResend) {
  try {
    const uid = req.user.uid;
    if (!otpIpAllowed(req.realIp || req.ip)) return res.status(429).json({ success: false, error: 'Çox cəhd edildi, sonra yenidən yoxlayın' });

    const us = await db.collection('users').doc(uid).get();
    if (!us.exists) return res.status(404).json({ success: false, error: 'İstifadəçi tapılmadı' });
    const u = us.data();
    if (u.phoneVerified === true) return res.json({ success: true, alreadyVerified: true, phone: u.phone || '' });

    const phone = normPhoneAz(u.phone);
    if (!phone) return res.status(400).json({ success: false, error: 'Əvvəlcə düzgün nömrə əlavə edin' });

    try {
      const dup = await db.collection('users').where('phone', '==', phone).limit(10).get();
      if (dup.docs.some(d => d.id !== uid && d.data().phoneVerified === true)) {
        return res.status(409).json({ success: false, error: 'Bu nömrə başqa hesabda doğrulanıb' });
      }
    } catch (e) { console.warn('[otp] dublikat yoxlaması keçildi:', e && e.message); }

    const sref = db.collection('otpSessions').doc(uid);
    const s = (await sref.get()).data() || {};
    const now = Date.now();
    const sends = (Array.isArray(s.sends) ? s.sends : []).filter(t => Number(t) && now - t < 3600000);
    if (sends.length) {
      const wait = OTP_COOLDOWN_MS - (now - sends[sends.length - 1]);
      if (wait > 0) return res.status(429).json({ success: false, error: `${Math.ceil(wait / 1000)} saniyə sonra yenidən göndərin`, retryAfter: Math.ceil(wait / 1000) });
    }
    if (sends.length >= OTP_MAX_SENDS_PER_HOUR) return res.status(429).json({ success: false, error: 'Saatlıq limit dolub, sonra yenidən cəhd edin' });

    if (SMS_SIMULATE) {
      const out = await otpFinalize(uid, phone);
      return res.json({
        success: true, simulated: true, verified: true, phone, ...out,
        completion: 'code', actionUrl: null, channel: 'sms', maskedRecipient: '', cooldown: 0
      });
    }

    const r = await otpApi('POST', '/verifications', { to: phone });
    if (!r.ok) return otpFail(res, r);

    const d = r.data || {};
    const otpId = otpPick(d, 'sid', 'id', 'verification_sid', 'verificationSid', 'otp_id');
    if (!otpId) { return res.status(502).json({ success: false, error: 'SMS xidməti cavabı başa düşülmədi' }); }
    const completion = 'code';
    const actionUrl = null;

    await sref.set({
      otpId: String(otpId), phone, sends: [...sends, now], attempts: 0,
      channel: String(otpPick(d, 'channel') || 'sms'), completion, updatedAt: FieldValue.serverTimestamp()
    });
    res.json({
      success: true, completion, actionUrl,
      channel: String(otpPick(d, 'channel') || 'sms'),
      maskedRecipient: '',
      phone, cooldown: OTP_COOLDOWN_MS / 1000
    });
  } catch (e) {
    console.error('[otp-send]', e);
    res.status(500).json({ success: false, error: 'Server xətası, bir az sonra yenidən cəhd edin' });
  }
}

app.get(['/otp/diag', '/api/otp/diag'], async (req, res) => {
  if (!process.env.DIAG_TOKEN || !safeEq(req.headers['x-diag-token'], process.env.DIAG_TOKEN)) return res.status(404).json({ success: false });
  if (!otpIpAllowed(req.realIp || req.ip)) return res.status(429).json({ ok: false });
  const r = await otpApi('GET', '/verifications/VE00000000000000000000000000000000');
  if (!OTP_API_KEY) return res.json({ ok: false, keyStatus: 'MISSING', base: OTP_BASE });
  const keyStatus = r.status === 401 ? 'INVALID' : r.status === 0 ? 'UNREACHABLE' : 'VALID';
  res.json({
    ok: r.status !== 401 && r.status !== 0,
    keyStatus, httpStatus: r.status, base: OTP_BASE,
    keyFromEnv: !!process.env.OTP_API_KEY,
    simulate: SMS_SIMULATE,
    providerMessage: (r.data && r.data.error && r.data.error.message) || null
  });
});

app.post(['/otp/send', '/api/otp/send'], authUser, (req, res) => otpSend(req, res, false));
app.post(['/otp/resend', '/api/otp/resend'], authUser, (req, res) => otpSend(req, res, true));

app.post(['/otp/verify', '/api/otp/verify'], authUser, async (req, res) => {
  try {
    const uid = req.user.uid;
    const code = String(req.body.code || '').replace(/\D/g, '');
    if (code.length < 4 || code.length > 8) return res.status(400).json({ success: false, error: '6 rəqəmli kodu daxil edin' });

    const sref = db.collection('otpSessions').doc(uid);
    const [ss, us] = await Promise.all([sref.get(), db.collection('users').doc(uid).get()]);
    const s = ss.data();
    const u = us.exists ? us.data() : {};
    if (u.phoneVerified === true) return res.json({ success: true, phone: u.phone || '', bonus: 0, spinBonus: 0, spins: Math.max(0, Math.floor(Number(u.payWheelSpins) || 0)), points: Number(u.points) || 0 });
    if (!s || (!s.otpId && !s.simulated)) return res.status(400).json({ success: false, error: 'Əvvəlcə kod göndərin' });
    if ((s.attempts || 0) >= OTP_MAX_ATTEMPTS) return res.status(429).json({ success: false, error: 'Çox yanlış cəhd. Yeni kod göndərin' });
    if (normPhoneAz(u.phone) !== s.phone) return res.status(409).json({ success: false, error: 'Nömrə dəyişib, yenidən kod göndərin' });

    let matched = false;
    if (s.simulated) {
      if (Date.now() > Number(s.expiresAt || 0)) return res.status(400).json({ success: false, error: 'Kodun vaxtı bitib, yenidən göndərin' });
      const x = Buffer.from(simHash(uid, s.phone, code)), y = Buffer.from(String(s.codeHash || ''));
      matched = x.length === y.length && crypto.timingSafeEqual(x, y);
    } else {
      const r = await otpApi('POST', '/verifications/' + encodeURIComponent(s.otpId) + '/check', { code });
      if (!r.ok) return otpFail(res, r);
      matched = !!(r.data && (r.data.valid === true || r.data.approved === true || r.data.matched === true || r.data.status === 'approved'));
    }
    if (!matched) {
      await sref.update({ attempts: FieldValue.increment(1) }).catch(() => {});
      const left = Math.max(0, OTP_MAX_ATTEMPTS - (s.attempts || 0) - 1);
      return res.status(400).json({ success: false, error: left ? `Kod yanlışdır (${left} cəhd qaldı)` : 'Kod yanlışdır. Yeni kod göndərin' });
    }

    const dup = await db.collection('users').where('phone', '==', s.phone).limit(10).get();
    if (dup.docs.some(d => d.id !== uid && d.data().phoneVerified === true)) return res.status(409).json({ success: false, error: 'Bu nömrə başqa hesabda doğrulanıb' });

    const out = await otpFinalize(uid, s.phone);
    res.json({ success: true, phone: s.phone, ...out });
  } catch (e) {
    console.error('[otp-verify]', e);
    res.status(500).json({ success: false, error: 'Server xətası, yenidən cəhd edin' });
  }
});

app.get(['/otp/status', '/api/otp/status'], authUser, async (req, res) => {
  try {
    const uid = req.user.uid;
    const s = (await db.collection('otpSessions').doc(uid).get()).data();
    if (!s || !s.otpId) return res.json({ success: true, status: s && s.simulated ? 'pending' : 'none' });
    const r = await otpApi('GET', '/verifications/' + encodeURIComponent(s.otpId));
    if (!r.ok) return otpFail(res, r);
    const st = r.data && r.data.status;
    if (st === 'approved') {
      const us = await db.collection('users').doc(uid).get();
      if (normPhoneAz(us.data() && us.data().phone) !== s.phone) return res.status(409).json({ success: false, error: 'Nömrə dəyişib, yenidən kod göndərin' });
      const out = await otpFinalize(uid, s.phone);
      return res.json({ success: true, status: 'approved', phone: s.phone, ...out });
    }
    res.json({ success: true, status: st || 'pending' });
  } catch (e) {
    console.error('[otp-status]', e);
    res.status(502).json({ success: false, error: 'SMS xidməti müvəqqəti əlçatmazdır' });
  }
});

const round2g = n => Math.round((Number(n) || 0) * 100) / 100;

/* ═══════════════════════════════════════════════════════════════
   BUG FIX #1: /buy-code — kod çatdırılması
   - limit(10) → limit(30): orfan sənədlər sərhədi doldurmasın
   - RESOURCE_EXHAUSTED → 503 + quota_exceeded
   ═══════════════════════════════════════════════════════════════ */
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
      tx.update(userRef, { balance: nb, spendRef: 'p:' + poolDoc.id });
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
    const code = String((e && e.code) || '');
    if (code === '8' || /RESOURCE_EXHAUSTED|Quota exceeded/i.test(m || '')) {
      console.error('[buy-code] Firestore kvotası dolub');
      return res.status(503).json({ success: false, error: 'quota_exceeded', retryAfter: 3600 });
    }
    console.error('[buy-code]', e);
    return res.status(500).json({ success: false, error: 'server_error' });
  }
});

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
function adminErr(res, e, tag) {
  const m = e && e.message;
  if (m === 'user_not_found') return res.status(404).json({ success: false, error: 'İstifadəçi tapılmadı' });
  if (m === 'negative') return res.status(400).json({ success: false, error: 'Balans mənfi ola bilməz' });
  console.error(tag, e);
  return res.status(500).json({ success: false, error: 'server_error' });
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
  } catch (e) { adminErr(res, e, '[admin-adjust-balance]'); }
});
app.post(['/admin/give-spins', '/api/admin/give-spins'], authUser, uidLimit('adm', 60, 60000), requireFullAdmin, async (req, res) => {
  try {
    const target = String(req.body.uid || '').trim();
    const n = Math.floor(Number(req.body.count));
    if (!target || target.length > 128 || !(n >= 1 && n <= 100)) return res.status(400).json({ success: false, error: '1–100 arası yazın' });
    const ref = db.collection('users').doc(target);
    let spins = 0;
    await db.runTransaction(async tx => {
      const s = await tx.get(ref);
      if (!s.exists) throw new Error('user_not_found');
      spins = Math.max(0, Math.floor(Number(s.data().payWheelSpins) || 0)) + n;
      tx.update(ref, { payWheelSpins: spins });
    });
    res.json({ success: true, spins });
  } catch (e) { adminErr(res, e, '[admin-give-spins]'); }
});

require('./betatransfer-route')(app, { admin, db, authUser, uidLimit, callbackLimit, genYeKod, campaignActive });
require('./spin-route')(app, { admin, db });
require('./email-verify-route')(app, { admin, db });
require('./password-reset-route')(app, { admin, db });
require('./payouts-route')(app, { db });

function withTimeout(promise, ms) {
  return Promise.race([promise, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout ' + ms + 'ms')), ms))]);
}
async function fsPing() {
  const t = Date.now();
  await withTimeout(db.collection('_health').doc('ping').get(), 25000);
  return Date.now() - t;
}
app.get(['/health/deep', '/api/health/deep'], async (req, res) => {
  try { res.json({ ok: true, firestoreMs: await fsPing(), p2: !!db2 }); }
  catch (e) { res.status(503).json({ ok: false, error: String(e && e.message || e) }); }
});

app.get(['/health', '/api/health'], (req, res) => res.json({ ok: true }));
app.get('/', (req, res) => res.json({ ok: true }));

app.use((req, res) => res.status(404).json({ success: false, error: 'Tapılmadı' }));
app.use((err, req, res, next) => { console.error('[express]', err); res.status(500).json({ success: false, error: 'Server xətası' }); });
process.on('unhandledRejection', e => console.error('[unhandledRejection]', e));
process.on('uncaughtException', e => console.error('[uncaughtException]', e));

/* ═══════════════════════════════════════════════════════════════
   BUG FIX #2: Basket sync — 5 dəq → 15 dəq, 1000 → 300
   ═══════════════════════════════════════════════════════════════ */
const BASKET_MAX = 300;
let basketBusy = false, basketLastErr = '';
async function syncCampaignBasket() {
  if (!db2 || basketBusy) return;
  basketBusy = true;
  try {
    const ref2 = db2.collection('public').doc('campaignBasket');
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
if (db2) { setTimeout(syncCampaignBasket, 60000); setInterval(syncCampaignBasket, 15 * 60 * 1000); }

const PORT = process.env.PORT || 10000;
const server = app.listen(PORT, '0.0.0.0', () => console.log(`Server ${PORT} portunda işləyir`));
server.keepAliveTimeout = 120 * 1000;
server.headersTimeout = 125 * 1000;

fsPing().then(ms => console.log('[warmup] Firestore hazırdır,', ms, 'ms')).catch(e => console.warn('[warmup] Firestore:', e.message));

let fsFails = 0;
setInterval(() => {
  fsPing().then(ms => { if (fsFails) console.log('[keepwarm] Firestore bərpa olundu,', ms, 'ms'); fsFails = 0; })
    .catch(e => {
      const msg = String(e && e.message || e);
      if (/RESOURCE_EXHAUSTED|Quota/i.test(msg)) {
        console.error('[QUOTA] Firestore gündəlik limiti dolub.');
        return;
      }
      fsFails++;
      if (fsFails >= 3) { console.error('[watchdog] Firestore 3 dəfə cavab vermədi'); setTimeout(() => process.exit(1), 500); }
    });
}, 15 * 60 * 1000);

/* BUG FIX #3: Self-ping SİLİNDİ (Render TOS-a ziddir) */