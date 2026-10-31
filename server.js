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
// Test üçün açarlar birbaşa kodda yazılıb (mühit dəyişəni varsa, o üstünlük təşkil edir).
const PUBLIC_KEY = process.env.PAY4BIT_PUBLIC_KEY || '36cf4-712';
const SECRET_KEY = process.env.PAY4BIT_SECRET_KEY || 'd868aee241455e82f6d3a99cb3283d73';

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
app.use(cors({
  origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
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
        let poolSnap = null;
        if (purpose === 'code') {
          poolSnap = await tx.get(db.collection('fastlotoCodes')
            .where('amount', '==', order.aznAmount).where('status', '==', 'available').limit(1));
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
          points: FieldValue.increment(order.aznAmount),       // 1 AZN = 1 xal
          payWheelSpins: FieldValue.increment(1)
        };
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
        if (bonus > 0) {
          tx.set(userRef.collection('history').doc('bonus_' + account), {
            type: 'bonus', amount: bonus,
            description: 'PayÇarx bonus: ilk depozitin 2 qatı', createdAt: FieldValue.serverTimestamp()
          });
        }

        if (purpose === 'code') {
          if (poolSnap && !poolSnap.empty) {
            const poolDoc = poolSnap.docs[0];
            const codeStr = poolDoc.data().code;
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

// PayÇarx (fırlatma) marşrutları: /spin-state, /spin
require('./spin-route')(app, { admin, db });

app.get(['/health', '/api/health'], (req, res) => res.json({ ok: true }));
app.get('/', (req, res) => res.json({ ok: true, service: 'pay4bit-server' }));

app.use((req, res) => res.status(404).json({ success: false, error: 'Tapılmadı' }));
app.use((err, req, res, next) => { console.error('[express]', err); res.status(500).json({ success: false, error: 'Server xətası' }); });
process.on('unhandledRejection', e => console.error('[unhandledRejection]', e));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server ${PORT} portunda işləyir`));

// Render pulsuz planda yatmasın deyə hər 10 dəqiqədən bir özünü çağırır
const SELF_URL = process.env.RENDER_EXTERNAL_URL || process.env.SELF_URL || 'https://pay4bit.onrender.com';
setInterval(() => { fetch(SELF_URL + '/health', { signal: AbortSignal.timeout(15000) }).catch(() => {}); }, 10 * 60 * 1000);
