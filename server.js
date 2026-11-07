/**
 * YevroLato – Pay4bit backend (FASTLOTO KOD AL)
 * Axın:
 *  1) Frontend  -> POST /create-payment  (Firebase ID token + AZN kod məbləği + üsul)
 *  2) Server    -> aktiv məzənnə (CBAR) ilə AZN -> EUR çevirir, Pay4bit komissiyasını məbləğin İÇİNDƏ saxlayır
 *                  (müştəri komissiya daxil ÜMUMİ olaraq yazdığı AZN-in avro qarşılığını ödəyir), imzalı Pay4bit linki qaytarır
 *  3) İstifadəçi Pay4bit-də ödəyir (kart / Google Pay / Apple Pay)
 *  4) Pay4bit   -> /pay4bit/callback (CHECK -> PAY) ; server imzanı + məbləği yoxlayır,
 *                  purpose='deposit' -> sayt balansı AVTOMATİK artırılır (+ xal, + PayÇarx fırlatması, ilk depozit 2x bonusu)
 *                  purpose='code'    -> admin panelindəki kod hovuzundan (fastlotoCodes) həmin məbləğdə kod verilir
 *                                       (hovuzda yoxdursa adminə kod tələbi yaradılır). Balans artırılmır.
 *                  Uğurlu ödənişlər 'payments' kolleksiyasında qalır -> admin paneldə 'Pay4bit Depozitlər' bölməsi.
 * Secret key YALNIZ bu serverdə qalır, brauzerə heç vaxt getmir.
 */
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const admin = require('firebase-admin');

// ---------- Konfiqurasiya ----------
// Açarlar YALNIZ mühit dəyişənlərindən oxunur (kodda saxlanmır).
const PUBLIC_KEY = process.env.PAY4BIT_PUBLIC_KEY || '';
const SECRET_KEY = process.env.PAY4BIT_SECRET_KEY || '';
if (!PUBLIC_KEY || !SECRET_KEY) {
  console.error('PAY4BIT_PUBLIC_KEY / PAY4BIT_SECRET_KEY mühit dəyişənləri təyin olunmayıb.');
  process.exit(1);
}

// Firebase service account (null qalsa mühit dəyişənindən oxunur)
const FIREBASE_SA = null;
// =======================================
const PAY4BIT_URL = 'https://api.pay4bit.net/pay';
const CHARGE_CURRENCY = 'EUR';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

const PAY_SYSTEM = {
  card:   process.env.PAY4BIT_CARD_PS   || '',
  google: process.env.PAY4BIT_GOOGLE_PS || '',
  apple:  process.env.PAY4BIT_APPLE_PS  || ''
};
// Minimum məbləğlər (AZN)
const MIN_AZN = { card: 3, google: 20, apple: 20 };

/**
 * Pay4bit ödəniş səhifəsində müştərinin ödəyəcəyi ümumi məbləğ:
 *     ümumi = göndərilən * (1 + faiz/100) + sabit
 * Ölçmə (Google Pay): göndərilən 7.32 € -> 11.17 €, göndərilən 14.65 € -> 19.83 €
 *     => faiz ≈ 18.14 %, sabit ≈ 2.52 €
 * Server tərsini hesablayır: göndərilən = (hədəf - sabit) / (1 + faiz/100)
 * Beləliklə səhifədə həmişə yazılan AZN-in avro qarşılığı görünür.
 * Kart üçün komissiya ölçülməyib -> 0 (ölçəndən sonra Render env ilə yaz).
 */
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
const MIN_CHARGE = 1; // Pay4bit minimumu 1 EUR

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
  console.error('Firebase service account tapılmadı və ya natamamdır (private_key / client_email yoxdur).');
  process.exit(1);
}
SA.private_key = String(SA.private_key).replace(/\\n/g, '\n');
console.log('Firebase service account yükləndi.');

admin.initializeApp({ credential: admin.credential.cert(SA) });
const db = admin.firestore();
try { db.settings({ ignoreUndefinedProperties: true }); } catch (_) {}
const FieldValue = admin.firestore.FieldValue;

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

// ---- Təhlükəsizlik başlıqları ----
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// ---- Ümumi sorğu limiti (IP başına dəqiqədə 240; callback və health istisna) ----
const globalHits = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of globalHits) if (now - v.t > 60000) globalHits.delete(k); }, 60000).unref();
app.use((req, res, next) => {
  if (req.path === '/pay4bit/callback' || req.path === '/health' || req.path === '/api/health') return next();
  const ip = String(req.ip || '');
  const now = Date.now();
  let e = globalHits.get(ip);
  if (!e || now - e.t > 60000) e = { t: now, n: 0 };
  e.n++; globalHits.set(ip, e);
  if (e.n > 240) return res.status(429).json({ success: false, error: 'Çox sorğu, bir az sonra yoxlayın' });
  next();
});
app.use(cors({
  origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: true, limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Aktiv məzənnə (AZN -> EUR) ----------
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
      // Hər iki mənbə işləməsə də ödəniş dayanmasın: ehtiyat sabit kurs
      rateCache = { aznPerEur: Number(process.env.FALLBACK_AZN_PER_EUR || 1.98), at: Date.now() - RATE_TTL + 60000, source: 'fallback' };
      console.warn('[rate] CBAR və ehtiyat mənbə işləmədi, sabit kurs:', rateCache.aznPerEur);
    }
  }
  return rateCache;
}

// azn = müştərinin ödəməli olduğu ümumi məbləğ (AZN). Hədəf avro = azn / kurs.
// Pay4bit göndərilənin üstünə faiz + sabit əlavə etdiyi üçün göndərilən məbləğ tərsinə hesablanır.
// Ən yaxın sentə yuvarlaqlanır ki, səhifədə görünən məbləğ hədəfə maksimum yaxın olsun.
function aznToEur(azn, aznPerEur, commissionPercent, fixedEur) {
  const target = azn / aznPerEur;
  const send = (target - (fixedEur || 0)) / (1 + (commissionPercent || 0) / 100);
  return (Math.round(send * 100) / 100).toFixed(2);
}
function payerTotal(sendEur, commissionPercent, fixedEur) {
  return (Number(sendEur) * (1 + (commissionPercent || 0) / 100) + (fixedEur || 0)).toFixed(2);
}

// ---------- Köməkçilər ----------
const sha256 = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const md5 = s => crypto.createHash('md5').update(s, 'utf8').digest('hex');
function safeEq(a, b) {
  a = Buffer.from(String(a || '')); b = Buffer.from(String(b || ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function authUser(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ success: false, error: 'Giriş tələb olunur' });
    req.user = await admin.auth().verifyIdToken(token);
    next();
  } catch (e) { res.status(401).json({ success: false, error: 'Etibarsız token' }); }
}

// ---------- Məzənnə (frontend önbaxışı üçün) ----------
app.get(['/rate', '/api/rate'], async (req, res) => {
  try {
    const r = await getAznPerEur();
    res.json({ success: true, currency: CHARGE_CURRENCY, aznPerEur: r.aznPerEur, source: r.source });
  } catch (e) { res.status(503).json({ success: false, error: e.message }); }
});

// ---------- Ödəniş yarat ----------
app.post(['/create-payment', '/api/create-payment'], authUser, async (req, res) => {
  try {
    const method = String(req.body.method || '');
    const purpose = req.body.purpose === 'deposit' ? 'deposit' : 'code';
    const platform = req.body.platform === 'chcplay' ? 'chcplay' : 'fastloto';
    if (!(method in MIN_AZN)) return res.status(400).json({ success: false, error: 'Yanlış ödəniş üsulu' });

    const raw = String(req.body.amount ?? '').trim().replace(',', '.');
    if (!/^\d+(\.\d{1,2})?$/.test(raw)) return res.status(400).json({ success: false, error: 'Məbləğ yanlışdır' });
    const azn = Number(raw);
    if (azn < MIN_AZN[method]) return res.status(400).json({ success: false, error: `Minimum ${MIN_AZN[method]} AZN` });
    if (azn > MAX_AZN) return res.status(400).json({ success: false, error: `Maksimum ${MAX_AZN} AZN` });

    const { aznPerEur, source } = await getAznPerEur();
    const commission = COMMISSION_PERCENT[method] || 0;
    const fixedFee = COMMISSION_FIXED_EUR[method] || 0;
    const amount = aznToEur(azn, aznPerEur, commission, fixedFee);
    const payerTotalEur = payerTotal(amount, commission, fixedFee);
    console.log(`[create-payment] ${method} ${azn} AZN | kurs ${aznPerEur} | komissiya ${commission}%+${fixedFee} EUR | Pay4bit-ə gedən ${amount} EUR | səhifədə görünəcək ≈ ${payerTotalEur} EUR (hədəf ${(azn / aznPerEur).toFixed(2)} EUR)`);
    if (Number(amount) < MIN_CHARGE) {
      return res.status(400).json({ success: false, error: 'Məbləğ Pay4bit minimumundan (1 EUR) azdır' });
    }

    const orderId = Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
    const account = orderId;
    const desc = purpose === 'deposit' ? `YevroLato depozit ${orderId}` : `YevroLato FASTLOTO kod ${orderId}`;
    const sign = sha256(desc + account + amount + SECRET_KEY);   // check_sign

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

// ---------- Ödəniş statusu (istifadəçi geri qayıdanda) ----------
app.get(['/payment-status', '/api/payment-status'], authUser, async (req, res) => {
  const snap = await db.collection('payments').doc(String(req.query.order || '')).get();
  if (!snap.exists || snap.data().uid !== req.user.uid) return res.status(404).json({ success: false });
  const d = snap.data();
  res.json({
    success: true, status: d.status, azn: d.aznAmount,
    purpose: d.purpose || 'code', bonus: d.bonus || 0,
    codeStatus: d.codeStatus || null,            // 'delivered' | 'admin_pending'
    code: d.codeStatus === 'delivered' ? d.code : null,
    codeRequestId: d.codeRequestId || null
  });
});

// ---------- 2027 Yeni İl Kampaniyası (YeKod) ----------
// Hər uğurlu Pay4bit DEPOZİTİNDƏ avtomatik YeKod verilir (çıxarışda isə admin təsdiq edəndə — admin.html).
// Kod nə qədər çox olarsa, qazanma şansı o qədər çox olur.
// campaignCodes/{kod} -> açıq səbət (yalnız ID + kod + mənbə; ad/uid YOXDUR)
const CAMPAIGN_END = new Date(process.env.CAMPAIGN_END_ISO || '2026-12-31T20:00:00Z'); // 1 yanvar 2027 00:00 (Bakı)
const CAMPAIGN_START = process.env.CAMPAIGN_START_ISO ? new Date(process.env.CAMPAIGN_START_ISO) : null;
const YE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 0/O, 1/I qarışmasın
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

// ---------- Pay4bit callback (CHECK / PAY / ERROR) ----------
async function pay4bitCallback(req, res) {
  const reply = (message, code = 200) => res.status(code).json({ result: { message } });
  try {
    const q = { ...req.query, ...req.body };
    const method = String(q.method || '').toLowerCase();
    const p = q.params || {};
    const account = String(p.account || '');
    const amount = String(p.amount || '');
    const desc = String(p.desc || '');

    const okCheck = p.check_sign && safeEq(sha256(desc + account + amount + SECRET_KEY), p.check_sign);
    const okSign = p.sign && p.localpayId && safeEq(md5(String(p.localpayId) + account + String(p.sum) + SECRET_KEY), p.sign);
    if (!okCheck && !okSign) { console.warn('[callback] imza səhvdir', account); return reply('Invalid signature', 400); }

    const ref = db.collection('payments').doc(account);
    const snap = await ref.get();
    if (!snap.exists) return reply('Order not found', 404);
    const order = snap.data();

    // İmzalanmış məbləği yoxla (check_sign -> amount, sign -> sum). Valyuta yalnız göndərilibsə yoxlanılır.
    const signedAmount = okCheck ? amount : String(p.sum || '');
    const curr = String(p.currency || '').toUpperCase();
    if (Number(signedAmount).toFixed(2) !== order.chargeAmount || (curr && curr !== order.chargeCurrency)) {
      console.warn('[callback] məbləğ uyğunsuzluğu', account, signedAmount, p.currency);
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
        // ---- bütün oxumalar əvvəl ----
        const cur = await tx.get(ref);
        if (cur.data().status === 'paid') return;              // təkrar PAY -> ikinci dəfə balans/kod vermə
        const purpose = order.purpose === 'deposit' ? 'deposit' : 'code';
        const userRef = db.collection('users').doc(order.uid);
        const userSnap = await tx.get(userRef);
        const u = userSnap.exists ? userSnap.data() : {};
        let poolSnap = null, secretSnap = null;
        if (purpose === 'code') {
          poolSnap = await tx.get(db.collection('fastlotoCodes')
            .where('amount', '==', order.aznAmount).where('status', '==', 'available').limit(1));
          // Kodun özü fastlotoSecrets/{id}-də saxlanır (admin paneli belə yazır)
          if (!poolSnap.empty) secretSnap = await tx.get(db.collection('fastlotoSecrets').doc(poolSnap.docs[0].id));
        }

        // ---- 2027 kampaniya: bu istifadəçinin kodu varmı? yoxdursa boş kod seç ----
        let campaignNew = null;
        if (purpose === 'deposit' && campaignActive()) {
          for (let i = 0; i < 6 && !campaignNew; i++) {
            const cand = genYeKod();
            const cs = await tx.get(db.collection('campaignCodes').doc(cand));
            if (!cs.exists) campaignNew = cand;
          }
        }

        // ---- yazmalar ----
        const platform = order.platform || 'fastloto';
        const bonus = (u.firstDepositBonus === 'pending') ? round2(order.aznAmount) : 0;   // PayÇarx: ilk depozit 2x
        const payUpdate = {
          status: 'paid', purpose, bonus, userName: u.displayName || order.userName || '',
          userUniqueId: u.uniqueId || order.userUniqueId || '',
          localpayId: String(p.localpayId || ''),
          paymentType: String(p.paymentType || ''), paidAt: FieldValue.serverTimestamp()
        };

        const userUpd = {
          points: FieldValue.increment(order.aznAmount)        // 1 AZN = 1 xal
        };
        // PayÇarx: hər uğurlu DEPOZİT 1 fırlatma açır (kod alışı fırlatma vermir)
        if (purpose === 'deposit') userUpd.payWheelSpins = FieldValue.increment(1);
        let balanceAdd = 0;
        if (purpose === 'deposit') balanceAdd += order.aznAmount;
        if (bonus > 0) { balanceAdd += bonus; userUpd.firstDepositBonus = 'used'; }
        if (balanceAdd > 0) userUpd.balance = FieldValue.increment(round2(balanceAdd));
        if (purpose === 'deposit') userUpd.hasDeposited = true;   // PayÇarx: depozit edənlər köhnə qaydada fırlayır
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
            description: 'PayÇarx bonus: ilk depozitin 2 qatı', createdAt: FieldValue.serverTimestamp()
          });
        }

        if (purpose === 'code') {
          if (poolSnap && !poolSnap.empty) {
            const poolDoc = poolSnap.docs[0];
            const codeStr = String((secretSnap && secretSnap.exists && secretSnap.data().code) || poolDoc.data().code || '');
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
      console.log('[callback] PAY uğurlu', account, order.purpose, order.aznAmount, 'AZN');
      return reply('Request successfully processed');
    }
    return reply('Unknown method', 400);
  } catch (e) {
    console.error('[callback]', e);
    return reply('Server error', 500);
  }
}
app.get('/pay4bit/callback', pay4bitCallback);
app.post('/pay4bit/callback', pay4bitCallback);

// ---------- OTP (OTPBAY) — nömrə təsdiqi ----------
// Açar Render-də OTP_API_KEY mühit dəyişəni ilə də verilə bilər (varsa o üstünlük təşkil edir).
const OTP_API_KEY = String(process.env.OTP_API_KEY || '').trim().replace(/^["']+|["']+$/g, '');
// OTP_BASE_URL: https://api.otpbay.com (sonunda /v1 yazılıb-yazılmaması vacib deyil)
const OTP_BASE = (process.env.OTP_BASE_URL || 'https://api.otpbay.com').trim().replace(/\/+$/, '').replace(/\/v1$/i, '') + '/v1';
const OTP_LOCALE = process.env.OTP_LOCALE || '';          // məs: 'az' (boşdursa göndərilmir)
const OTP_COOLDOWN_MS = 60 * 1000;                         // təkrar göndərmə arası
const OTP_MAX_SENDS_PER_HOUR = 5;                          // bir istifadəçi üçün saatda
const OTP_MAX_ATTEMPTS = 5;                                // bir kod üçün yanlış cəhd limiti
// SMS API hələ qoşulmayıb: SMS_SIMULATE=true (və ya OTP_API_KEY boşdursa) kod serverdə təsadüfi yaradılır,
// real SMS göndərilmir. Real API hazır olanda Render-də SMS_SIMULATE=false yazın və OTP_API_KEY əlavə edin.
const SMS_SIMULATE = process.env.SMS_SIMULATE !== undefined && process.env.SMS_SIMULATE !== ''
  ? String(process.env.SMS_SIMULATE).toLowerCase() === 'true'
  : !OTP_API_KEY;
const SIM_CODE_TTL_MS = 10 * 60 * 1000;
const simHash = (uid, phone, code) => crypto.createHash('sha256').update(`${uid}|${phone}|${code}|yl-sms-sim`).digest('hex');
const otpIpHits = new Map();                               // ip -> [vaxtlar] (SMS pumping qorunması)

function normPhoneAz(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  const plus = s.startsWith('+');
  let d = s.replace(/\D/g, '');
  if (!d) return null;
  if (!plus) {
    if (d.startsWith('00')) d = d.slice(2);
    else if (d.startsWith('994')) { /* artıq ölkə kodu ilə */ }
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
  const d = r.data || {};
  const e = (d.error && typeof d.error === 'object') ? d.error : {};
  const detail = [e.type || e.code, e.message || (typeof d.error === 'string' ? d.error : '') || d.message].filter(Boolean).join(': ').slice(0, 200);
  console.warn('[otp] xəta', r.status, detail);
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
const cleanIp = ip => String(ip || '').replace(/^::ffff:/i, '');
function otpIpAllowed(ip) {
  const now = Date.now();
  const arr = (otpIpHits.get(ip) || []).filter(t => now - t < 3600000);
  if (arr.length >= 20) { otpIpHits.set(ip, arr); return false; }
  arr.push(now); otpIpHits.set(ip, arr);
  return true;
}
const otpPick = (d, ...keys) => { for (const k of keys) if (d && d[k] !== undefined && d[k] !== null) return d[k]; return undefined; };

// Doğrulama uğurlu olanda: phoneVerified=true + (ilk dəfə) 1 PayÇarx
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
      upd.welcomeSpinGiven = true;   // qeydiyyat hədiyyəsi ilə ikiqat PayÇarx verilməsin
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
    if (!otpIpAllowed(req.ip)) return res.status(429).json({ success: false, error: 'Çox cəhd edildi, sonra yenidən yoxlayın' });

    const us = await db.collection('users').doc(uid).get();
    if (!us.exists) return res.status(404).json({ success: false, error: 'İstifadəçi tapılmadı' });
    const u = us.data();
    if (u.phoneVerified === true) return res.json({ success: true, alreadyVerified: true, phone: u.phone || '' });

    const phone = normPhoneAz(u.phone);
    if (!phone) return res.status(400).json({ success: false, error: 'Əvvəlcə düzgün nömrə əlavə edin' });

    // Tək sahə üzrə sorğu (kompozit indeks tələb etmir) + yaddaşda süzgəc.
    // Sorğu uğursuz olsa belə SMS göndərilməsi dayanmasın.
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
      const code = String(crypto.randomInt(100000, 1000000));
      await sref.set({
        simulated: true, codeHash: simHash(uid, phone, code), expiresAt: now + SIM_CODE_TTL_MS,
        phone, sends: [...sends, now], attempts: 0, channel: 'sms', completion: 'code',
        updatedAt: FieldValue.serverTimestamp()
      });
      return res.json({
        success: true, simulated: true, code, completion: 'code', actionUrl: null,
        channel: 'sms', maskedRecipient: '', phone, cooldown: OTP_COOLDOWN_MS / 1000
      });
    }

    // OTPBAY: POST /v1/verifications {to}. (Təkrar göndərmə də yeni doğrulama yaradır.)
    const r = await otpApi('POST', '/verifications', { to: phone });
    if (!r.ok) return otpFail(res, r);

    const d = r.data || {};
    const otpId = otpPick(d, 'sid', 'id', 'verification_sid', 'verificationSid', 'otp_id');
    if (!otpId) { console.error('[otp] cavabda sid yoxdur', d); return res.status(502).json({ success: false, error: 'SMS xidməti cavabı başa düşülmədi' }); }
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

// Diaqnostika: açar işləyirmi? (brauzerdə aç: /api/otp/diag) — SMS göndərmir
app.get(['/otp/diag', '/api/otp/diag'], async (req, res) => {
  if (!process.env.DIAG_TOKEN || !safeEq(req.headers['x-diag-token'], process.env.DIAG_TOKEN)) return res.status(404).json({ success: false });
  if (!otpIpAllowed(req.ip)) return res.status(429).json({ ok: false });
  const r = await otpApi('GET', '/verifications/VE00000000000000000000000000000000');
  if (!OTP_API_KEY) return res.json({ ok: false, keyStatus: 'MISSING (Render-də OTP_API_KEY yoxdur)', base: OTP_BASE });
  const keyStatus = r.status === 401 ? 'INVALID (açar yanlışdır / tətbiq söndürülüb / şirkət dayandırılıb)'
    : r.status === 0 ? 'UNREACHABLE (api.otp.com-a qoşulmaq olmadı)'
    : 'VALID (açar qəbul olundu)';
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
    const s = (await sref.get()).data();
    if (!s || (!s.otpId && !s.simulated)) return res.status(400).json({ success: false, error: 'Əvvəlcə kod göndərin' });
    if ((s.attempts || 0) >= OTP_MAX_ATTEMPTS) return res.status(429).json({ success: false, error: 'Çox yanlış cəhd. Yeni kod göndərin' });

    const us = await db.collection('users').doc(uid).get();
    const u = us.exists ? us.data() : {};
    if (u.phoneVerified === true) return res.json({ success: true, phone: u.phone || '', bonus: 0, spinBonus: 0, points: Number(u.points) || 0 });
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
    console.log('[otp] doğrulandı', uid, s.phone);
    res.json({ success: true, phone: s.phone, ...out });
  } catch (e) {
    console.error('[otp-verify]', e);
    res.status(500).json({ success: false, error: 'Server xətası, yenidən cəhd edin' });
  }
});

// WhatsApp "inbound" rejimi üçün: status yoxlanır, təsdiqlənibsə eyni qaydada tamamlanır
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

// PayÇarx (fırlatma) marşrutları: /spin-state, /spin
require('./spin-route')(app, { admin, db });

// E-poçt doğrulama (Brevo ilə kod göndərir, uğurda 1 PayÇarx): /email-verify/send, /confirm
require('./email-verify-route')(app, { admin, db });

// Şifrə yeniləmə (e-mail kodu): /password-reset/lookup, /send, /confirm
require('./password-reset-route')(app, { admin, db });

app.get(['/health', '/api/health'], (req, res) => res.json({ ok: true }));
app.get('/', (req, res) => res.json({ ok: true }));

app.use((req, res) => res.status(404).json({ success: false, error: 'Tapılmadı' }));
app.use((err, req, res, next) => { console.error('[express]', err); res.status(500).json({ success: false, error: 'Server xətası' }); });
process.on('unhandledRejection', e => console.error('[unhandledRejection]', e));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server ${PORT} portunda işləyir`));

// Render pulsuz planda yatmasın deyə hər 10 dəqiqədən bir özünü çağırır
const SELF_URL = process.env.RENDER_EXTERNAL_URL || process.env.SELF_URL || '';
if (SELF_URL) setInterval(() => { fetch(SELF_URL + '/health', { signal: AbortSignal.timeout(15000) }).catch(() => {}); }, 10 * 60 * 1000);
