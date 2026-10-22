/**
 * YevroLato – Pay4bit backend
 * Axın:
 *  1) Frontend  -> POST /create-payment  (Firebase ID token + AZN məbləğ + üsul)
 *  2) Server    -> aktiv məzənnə (CBAR) ilə AZN -> EUR çevirir, sifariş yaradır, imzalı Pay4bit linki qaytarır
 *  3) İstifadəçi Pay4bit-də ödəyir (kart / Google Pay / Apple Pay)
 *  4) Pay4bit   -> /pay4bit/callback (CHECK -> PAY) ; server imzanı + məbləği yoxlayıb balansı artırır
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
const FX_MARGIN_PERCENT = Number(process.env.FX_MARGIN_PERCENT || 0); // istəsən +% əlavə et
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

// Pay4bit paySystem dəyərləri (boşdursa Pay4bit öz seçim səhifəsini göstərir – ən təhlükəsiz variant)
const PAY_SYSTEM = {
  card:   process.env.PAY4BIT_CARD_PS   || '',
  google: process.env.PAY4BIT_GOOGLE_PS || '',
  apple:  process.env.PAY4BIT_APPLE_PS  || ''
};
const MIN_AZN = { card: 3, google: 3, apple: 3 };
const MAX_AZN = 2000;
const MIN_CHARGE = 1; // Pay4bit minimumu 1 EUR

const SA = process.env.FIREBASE_SERVICE_ACCOUNT ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT) : FIREBASE_SA;
if (!SA) {
  console.error('Firebase service account əlavə olunmayıb! server.js-də FIREBASE_SA sətrinə JSON yapışdır.');
  process.exit(1);
}

// ---------- Firebase Admin ----------
// FIREBASE_SERVICE_ACCOUNT = service account JSON-un tam mətni
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
function aznToEur(azn, aznPerEur) {
  const eur = (azn / aznPerEur) * (1 + FX_MARGIN_PERCENT / 100);
  return (Math.ceil(eur * 100) / 100).toFixed(2); // yuxarı yuvarlaqla, 2 rəqəm
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
    const amount = aznToEur(azn, aznPerEur);
    if (Number(amount) < MIN_CHARGE) {
      return res.status(400).json({ success: false, error: 'Məbləğ Pay4bit minimumundan (1 EUR) azdır' });
    }

    const orderId = Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
    const account = orderId;
    const desc = `YevroLato depozit ${orderId}`;
    const sign = sha256(desc + account + amount + SECRET_KEY);   // check_sign

    await db.collection('payments').doc(orderId).set({
      uid: req.user.uid, method, status: 'pending',
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
  res.json({ success: true, status: d.status, azn: d.aznAmount });
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
        const cur = await tx.get(ref);
        if (cur.data().status === 'paid') return;              // təkrar PAY -> yenidən əlavə etmə
        const userRef = db.collection('users').doc(order.uid);
        tx.update(userRef, {
          balance: FieldValue.increment(order.aznAmount),
          points: FieldValue.increment(order.aznAmount),       // 1 AZN = 1 xal
          payWheelSpins: FieldValue.increment(1)
        });
        tx.set(userRef.collection('history').doc(), {
          type: 'deposit', amount: order.aznAmount,
          description: `Pay4bit (${order.method}) depozit`, createdAt: FieldValue.serverTimestamp()
        });
        tx.update(ref, {
          status: 'paid', localpayId: String(p.localpayId || ''),
          paymentType: String(p.paymentType || ''), paidAt: FieldValue.serverTimestamp()
        });
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
