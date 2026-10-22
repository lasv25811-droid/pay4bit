/**
 * YevroLato – Pay4bit backend (FASTLOTO KOD AL)
 * Axın:
 *  1) Frontend  -> POST /create-payment  (Firebase ID token + AZN kod məbləği + üsul)
 *  2) Server    -> aktiv məzənnə (CBAR) ilə AZN -> EUR çevirir, Pay4bit komissiyasını məbləğin İÇİNDƏ saxlayır
 *                  (müştəri komissiya daxil ÜMUMİ olaraq yazdığı məbləği ödəyir), imzalı Pay4bit linki qaytarır
 *  3) İstifadəçi Pay4bit-də ödəyir (kart / Google Pay / Apple Pay)
 *  4) Pay4bit   -> /pay4bit/callback (CHECK -> PAY) ; server imzanı + məbləği yoxlayır,
 *                  hovuzdan həmin məbləğdə kodu müştəriyə verir (yoxdursa adminə kod tələbi yaradır).
 *                  Sayt balansı artırılmır.
 * Secret key YALNIZ bu serverdə qalır, brauzerə heç vaxt getmir.
 */
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const admin = require('firebase-admin');

// ---------- Konfiqurasiya (Environment dəyişənləri) ----------
// ====== AYARLAR (birbaşa burada) ======
const PUBLIC_KEY = process.env.PAY4BIT_PUBLIC_KEY || '36cf4-712';
const SECRET_KEY = process.env.PAY4BIT_SECRET_KEY || 'd868aee241455e82f6d3a99cb3283d73';

// Firebase Console -> Project settings -> Service accounts -> Generate new private key
// Endirilən .json faylının BÜTÜN məzmununu null yerinə yapışdır: const FIREBASE_SA = { "type": "service_account", ... };
const FIREBASE_SA = null;
// =======================================
const PAY4BIT_URL = 'https://api.pay4bit.net/pay';
const CHARGE_CURRENCY = 'EUR';                       // Pay4bit default valyutası
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

// Pay4bit paySystem dəyərləri (boşdursa Pay4bit öz seçim səhifəsini göstərir – ən təhlükəsiz variant)
const PAY_SYSTEM = {
  card:   process.env.PAY4BIT_CARD_PS   || '',
  google: process.env.PAY4BIT_GOOGLE_PS || '',
  apple:  process.env.PAY4BIT_APPLE_PS  || ''
};
// Minimum məbləğlər (AZN): kart 3, Google Pay 20, Apple Pay 20
const MIN_AZN = { card: 3, google: 20, apple: 20 };

// Pay4bit-in MÜŞTƏRİDƏN tutduğu komissiya faizi (üsul üzrə). Pay4bit kabinetindəki real faizi bura yaz!
// Məsələn kart 5% tutursa -> card: 5. Server müştərinin ÜMUMİ ödənişi (məbləğ + komissiya)
// yazdığı məbləğə (məs. 20 AZN) bərabər olsun deyə Pay4bit-ə göndərilən məbləği avtomatik azaldır.
const COMMISSION_PERCENT = {
  card:   Number(process.env.PAY4BIT_COMM_CARD   || 0),
  google: Number(process.env.PAY4BIT_COMM_GOOGLE || 0),
  apple:  Number(process.env.PAY4BIT_COMM_APPLE  || 0)
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
console.log('Firebase service account yükləndi:', SA.project_id, SA.client_email);

admin.initializeApp({ credential: admin.credential.cert(SA) });
const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

const app = express();
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
      if (rateCache.aznPerEur) return rateCache;       // köhnə keş (son çarə)
      throw new Error('Məzənnə əldə edilə bilmədi');
    }
  }
  return rateCache;
}
// azn = müştərinin ödəyəcəyi ÜMUMİ məbləğ (komissiya daxil). Pay4bit komissiyanı üstünə əlavə etdiyi üçün
// göndərilən məbləğ = ümumi / (1 + komissiya%). Aşağı yuvarlaqlanır ki, müştəri heç vaxt artıq ödəməsin.
function aznToEur(azn, aznPerEur, commissionPercent) {
  const eurTotal = azn / aznPerEur;
  const eurSend = eurTotal / (1 + (commissionPercent || 0) / 100);
  return (Math.floor(eurSend * 100 + 1e-9) / 100).toFixed(2);
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
app.get('/rate', async (req, res) => {
  try {
    const r = await getAznPerEur();
    res.json({ success: true, currency: CHARGE_CURRENCY, aznPerEur: r.aznPerEur, source: r.source });
  } catch (e) { res.status(503).json({ success: false, error: e.message }); }
});

// ---------- Ödəniş yarat ----------
app.post('/create-payment', authUser, async (req, res) => {
  try {
    const method = String(req.body.method || '');
    if (!(method in MIN_AZN)) return res.status(400).json({ success: false, error: 'Yanlış ödəniş üsulu' });

    const raw = String(req.body.amount ?? '').trim().replace(',', '.');
    if (!/^\d+(\.\d{1,2})?$/.test(raw)) return res.status(400).json({ success: false, error: 'Məbləğ yanlışdır' });
    const azn = Number(raw);
    if (azn < MIN_AZN[method]) return res.status(400).json({ success: false, error: `Minimum ${MIN_AZN[method]} AZN` });
    if (azn > MAX_AZN) return res.status(400).json({ success: false, error: `Maksimum ${MAX_AZN} AZN` });

    const { aznPerEur, source } = await getAznPerEur();
    const commission = COMMISSION_PERCENT[method] || 0;
    const amount = aznToEur(azn, aznPerEur, commission);
    if (Number(amount) < MIN_CHARGE) {
      return res.status(400).json({ success: false, error: 'Məbləğ Pay4bit minimumundan (1 EUR) azdır' });
    }

    const orderId = Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
    const account = orderId;
    const desc = `YevroLato FASTLOTO kod ${orderId}`;
    const sign = sha256(desc + account + amount + SECRET_KEY);   // check_sign

    await db.collection('payments').doc(orderId).set({
      uid: req.user.uid, method, status: 'pending',
      purpose: 'code', platform: 'fastloto', commissionPercent: commission,
      aznAmount: azn, chargeAmount: amount, chargeCurrency: CHARGE_CURRENCY,
      aznPerEur, rateSource: source, desc, createdAt: FieldValue.serverTimestamp()
    });

    const params = { public_key: PUBLIC_KEY, account, sum: amount, currency: CHARGE_CURRENCY, desc, sign };
    if (PAY_SYSTEM[method]) params.paySystem = PAY_SYSTEM[method];

    res.json({
      success: true, orderId,
      azn, charge: amount, currency: CHARGE_CURRENCY, aznPerEur,
      redirect_url: `${PAY4BIT_URL}?${new URLSearchParams(params).toString()}`
    });
  } catch (e) {
    console.error('[create-payment]', e);
    res.status(500).json({ success: false, error: 'Server xətası' });
  }
});

// ---------- Ödəniş statusu (istifadəçi geri qayıdanda) ----------
app.get('/payment-status', authUser, async (req, res) => {
  const snap = await db.collection('payments').doc(String(req.query.order || '')).get();
  if (!snap.exists || snap.data().uid !== req.user.uid) return res.status(404).json({ success: false });
  const d = snap.data();
  res.json({
    success: true, status: d.status, azn: d.aznAmount,
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

    // İmza yoxlaması (ikisindən biri düzgün olmalıdır; hər ikisi secret key tələb edir)
    const okCheck = p.check_sign && safeEq(sha256(desc + account + amount + SECRET_KEY), p.check_sign);
    const okSign = p.sign && p.localpayId && safeEq(md5(String(p.localpayId) + account + String(p.sum) + SECRET_KEY), p.sign);
    if (!okCheck && !okSign) { console.warn('[callback] imza səhvdir', account); return reply('Invalid signature', 400); }

    const ref = db.collection('payments').doc(account);
    const snap = await ref.get();
    if (!snap.exists) return reply('Order not found', 404);
    const order = snap.data();

    if (Number(amount).toFixed(2) !== order.chargeAmount || String(p.currency).toUpperCase() !== order.chargeCurrency) {
      console.warn('[callback] məbləğ uyğunsuzluğu', account, amount, p.currency);
      return reply('Amount mismatch', 400);
    }

    if (method === 'check') return reply('Request successfully processed');

    if (method === 'error') {
      if (order.status === 'pending') await ref.update({ status: 'failed', failedAt: FieldValue.serverTimestamp() });
      return reply('Request successfully processed');
    }

    if (method === 'pay') {
      await db.runTransaction(async tx => {
        // ---- bütün oxumalar əvvəl ----
        const cur = await tx.get(ref);
        if (cur.data().status === 'paid') return;              // təkrar PAY -> kodu ikinci dəfə vermə
        const userRef = db.collection('users').doc(order.uid);
        const userSnap = await tx.get(userRef);
        const u = userSnap.exists ? userSnap.data() : {};
        const poolQ = db.collection('fastlotoCodes')
          .where('amount', '==', order.aznAmount).where('status', '==', 'available').limit(1);
        const poolSnap = await tx.get(poolQ);

        // ---- yazmalar ----
        const platform = order.platform || 'fastloto';
        const payUpdate = {
          status: 'paid', localpayId: String(p.localpayId || ''),
          paymentType: String(p.paymentType || ''), paidAt: FieldValue.serverTimestamp()
        };
        // balans artırılmır; yalnız xal və çarx hüququ (əvvəlki kimi)
        tx.update(userRef, {
          points: FieldValue.increment(order.aznAmount),       // 1 AZN = 1 xal
          payWheelSpins: FieldValue.increment(1)
        });

        if (!poolSnap.empty) {
          // Hovuzda kod var -> avtomatik təhvil
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
          // Hovuzda yoxdur -> adminə (ödənilmiş) kod tələbi
          tx.set(db.collection('codeRequests').doc(account), {
            uid: order.uid, userName: u.displayName || '', userUniqueId: u.uniqueId || '',
            platform, amount: order.aznAmount, status: 'pending', code: '',
            paid: true, orderId: account, createdAt: FieldValue.serverTimestamp()
          });
          payUpdate.codeStatus = 'admin_pending';
          payUpdate.codeRequestId = account;
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
app.get('/pay4bit/callback', pay4bitCallback);
app.post('/pay4bit/callback', pay4bitCallback);

app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server ${PORT} portunda işləyir`));
