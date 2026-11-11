'use strict';
/**
 * BetaTransfer (betatransfer.io) — DEPOZİT (kart-to-kart, Azərbaycan)
 *
 *   POST /betatransfer/create     (Firebase token tələb olunur)  -> { success, orderId, url }
 *   GET  /betatransfer/status     (Firebase token tələb olunur)  -> { success, status, azn }
 *   POST /betatransfer/callback   (BetaTransfer server-to-server, form-urlencoded) -> HTTP 200
 *
 * Render mühit dəyişənləri (kodda açar SAXLANMIR):
 *   BETATRANSFER_PUBLIC_KEY   (məcburi)  public key  -> ?token=
 *   BETATRANSFER_SECRET_KEY   (məcburi)  secret key  -> imza
 *   BETATRANSFER_PAYMENT_SYSTEM          Azərbaycan kart-to-kart üçün paymentSystem kodu
 *                                        (GET /api/payment-system və ya BetaTransfer menecerindən)
 *   BETATRANSFER_CURRENCY                default AZN
 *   BETATRANSFER_MIN / BETATRANSFER_MAX  default 5 / 2000 (AZN)
 *   BETATRANSFER_SIGN_FIELDS             yaratma imzasının sahə sırası (vergüllə), default aşağıdadır.
 *                                        Sənəddə sıra yazılmayıb -> 403/invalid signature olsa BU dəyişənlə düzəldilir.
 *   BETATRANSFER_CALLBACK_BASE           məs. https://pay4bit.onrender.com (default RENDER_EXTERNAL_URL)
 *   SITE_URL                             istifadəçinin qayıdacağı sayt (default ALLOWED_ORIGINS[0])
 */
const crypto = require('crypto');

const API_BASE = 'https://merchant.betatransfer.io';
const md5 = s => crypto.createHash('md5').update(String(s), 'utf8').digest('hex');
const round2 = n => Math.round(n * 100) / 100;
function safeEq(a, b) {
  a = Buffer.from(String(a || '').toLowerCase()); b = Buffer.from(String(b || '').toLowerCase());
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const SUCCESS = new Set(['success']);
const PARTIAL = new Set(['partial_payment']);
const FAILED = new Set(['cancel', 'not_paid', 'not_paid_timeout', 'error', 'blocked', 'not_paid_unavailable_country']);
// new / pending / verification / checkPayment -> gözləmə (heç nə dəyişmir)

module.exports = function registerBetaTransferRoutes(app, deps) {
  const { admin, db, authUser, uidLimit, callbackLimit, genYeKod, campaignActive } = deps;
  const FieldValue = admin.firestore.FieldValue;

  const PUBLIC_KEY = String(process.env.BETATRANSFER_PUBLIC_KEY || '').trim();
  const SECRET_KEY = String(process.env.BETATRANSFER_SECRET_KEY || '').trim();
  if (!PUBLIC_KEY || !SECRET_KEY) {
    console.warn('[betatransfer] BETATRANSFER_PUBLIC_KEY / BETATRANSFER_SECRET_KEY təyin olunmayıb — BetaTransfer deaktivdir.');
    const off = (req, res) => res.status(503).json({ success: false, error: 'Bu ödəniş üsulu hazırda aktiv deyil' });
    app.post('/betatransfer/create', off);
    app.get('/betatransfer/status', off);
    // BetaTransfer-ə həmişə 200 qaytarırıq ki, sonsuz təkrar göndərməsin; açar yoxdursa heç nə kreditləmirik
    app.post('/betatransfer/callback', (req, res) => res.status(200).send('OK'));
    return;
  }

  const PAYMENT_SYSTEM = String(process.env.BETATRANSFER_PAYMENT_SYSTEM || '').trim();
  const CURRENCY = String(process.env.BETATRANSFER_CURRENCY || 'AZN').trim().toUpperCase();
  const MIN_AZN = Number(process.env.BETATRANSFER_MIN || 5);
  const MAX_AZN = Number(process.env.BETATRANSFER_MAX || 2000);
  const SIGN_FIELDS = String(process.env.BETATRANSFER_SIGN_FIELDS ||
    'amount,currency,orderId,paymentSystem,urlResult,urlSuccess,urlFail,payerId')
    .split(',').map(s => s.trim()).filter(Boolean);
  const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const SITE_URL = (process.env.SITE_URL || ALLOWED_ORIGINS[0] || '').replace(/\/+$/, '');
  const CALLBACK_BASE = (process.env.BETATRANSFER_CALLBACK_BASE || process.env.RENDER_EXTERNAL_URL || '').replace(/\/+$/, '');
  if (!CALLBACK_BASE) console.warn('[betatransfer] BETATRANSFER_CALLBACK_BASE / RENDER_EXTERNAL_URL boşdur — urlResult tam olmayacaq!');
  if (!PAYMENT_SYSTEM) console.warn('[betatransfer] BETATRANSFER_PAYMENT_SYSTEM boşdur — kart-to-kart üçün kod yazın.');

  const sign = (fields) => md5(SIGN_FIELDS.map(k => (fields[k] === undefined || fields[k] === null) ? '' : String(fields[k])).join('') + SECRET_KEY);

  // ---------- Ödəniş yarat ----------
  app.post('/betatransfer/create', authUser, uidLimit('btcreate', 8, 60000), async (req, res) => {
    try {
      if (!PAYMENT_SYSTEM) return res.status(503).json({ success: false, error: 'Bu ödəniş üsulu hazırda aktiv deyil' });
      const raw = String((req.body && req.body.amount) ?? '').trim().replace(',', '.');
      if (!/^\d+(\.\d{1,2})?$/.test(raw)) return res.status(400).json({ success: false, error: 'Məbləğ yanlışdır' });
      const azn = Number(raw);
      if (azn < MIN_AZN) return res.status(400).json({ success: false, error: `Minimum ${MIN_AZN} AZN` });
      if (azn > MAX_AZN) return res.status(400).json({ success: false, error: `Maksimum ${MAX_AZN} AZN` });
      const amount = azn.toFixed(2);

      // orderId: yalnız latın hərf/rəqəm, ≤ 40 simvol
      const orderId = 'bt' + Date.now().toString(36) + crypto.randomBytes(5).toString('hex');

      let uName = '', uUnique = '';
      try {
        const us = await db.collection('users').doc(req.user.uid).get();
        if (us.exists) { uName = us.data().displayName || ''; uUnique = us.data().uniqueId || ''; }
      } catch (_) {}

      // qayıdış ünvanı: yalnız icazəli origin (open-redirect olmasın)
      let base = SITE_URL;
      const origin = String(req.headers.origin || '').replace(/\/+$/, '');
      if (origin && ALLOWED_ORIGINS.includes(origin)) base = origin;
      const urlSuccess = base ? `${base}/profile.html?bt=${orderId}&r=ok` : '';
      const urlFail = base ? `${base}/profile.html?bt=${orderId}&r=fail` : '';
      const urlResult = `${CALLBACK_BASE}/betatransfer/callback`;

      await db.collection('payments').doc(orderId).set({
        uid: req.user.uid, userName: uName, userUniqueId: uUnique,
        provider: 'betatransfer', method: 'bt_card2card', status: 'pending', purpose: 'deposit', platform: 'fastloto',
        aznAmount: azn, chargeAmount: amount, chargeCurrency: CURRENCY,
        desc: 'YevroLato depozit ' + orderId, createdAt: FieldValue.serverTimestamp()
      });

      const f = {
        amount, currency: CURRENCY, orderId, paymentSystem: PAYMENT_SYSTEM,
        urlResult, urlSuccess, urlFail, payerId: String(req.user.uid).slice(0, 64),
        fullCallback: 1
      };
      const form = new URLSearchParams();
      for (const [k, v] of Object.entries(f)) if (v !== '' && v !== undefined) form.set(k, String(v));
      form.set('user_comment', ('deposit ' + (uUnique || req.user.uid)).slice(0, 100));
      const ip = String(req.realIp || req.ip || '');
      if (ip) form.set('ip', ip);
      form.set('sign', sign(f));

      let data = null, httpStatus = 0;
      try {
        const r = await fetch(`${API_BASE}/api/payment?token=${encodeURIComponent(PUBLIC_KEY)}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
          body: form.toString(),
          signal: AbortSignal.timeout(20000)
        });
        httpStatus = r.status;
        const txt = await r.text();
        try { data = JSON.parse(txt); } catch (_) { data = { raw: txt.slice(0, 300) }; }
      } catch (e) {
        console.error('[betatransfer/create] şəbəkə xətası', e.message);
      }

      if (!data || !data.url) {
        console.error('[betatransfer/create] uğursuz', httpStatus, JSON.stringify(data || {}).slice(0, 500));
        await db.collection('payments').doc(orderId).update({ status: 'failed', failReason: 'create_failed_' + httpStatus, failedAt: FieldValue.serverTimestamp() }).catch(() => {});
        return res.status(502).json({ success: false, error: 'Ödəniş səhifəsi yaradıla bilmədi, bir az sonra yenidən cəhd edin' });
      }
      await db.collection('payments').doc(orderId).update({ btId: String(data.id || ''), btHash: String(data.hash || '') }).catch(() => {});
      res.json({ success: true, orderId, azn, url: data.url });
    } catch (e) {
      console.error('[betatransfer/create]', e);
      res.status(500).json({ success: false, error: 'Server xətası, yenidən cəhd edin' });
    }
  });

  // ---------- Status (istifadəçi geri qayıdanda) ----------
  app.get('/betatransfer/status', authUser, async (req, res) => {
    try {
      const snap = await db.collection('payments').doc(String(req.query.order || '')).get();
      if (!snap.exists || snap.data().uid !== req.user.uid || snap.data().provider !== 'betatransfer') return res.status(404).json({ success: false });
      const d = snap.data();
      res.json({ success: true, status: d.status, azn: d.creditedAzn != null ? d.creditedAzn : d.aznAmount, bonus: d.bonus || 0 });
    } catch (e) { res.status(500).json({ success: false }); }
  });

  // ---------- Callback ----------
  async function callback(req, res) {
    const ok = () => res.status(200).send('OK');
    try {
      const b = req.body || {};
      const orderId = String(b.orderId || '');
      const amountRaw = String(b.amount === undefined ? '' : b.amount);
      if (!/^[A-Za-z0-9-]{1,40}$/.test(orderId) || !b.sign) return res.status(400).send('Bad request');

      // 1) İmza: md5(amount + orderId + secret)
      if (!safeEq(md5(amountRaw + orderId + SECRET_KEY), b.sign)) {
        console.warn('[betatransfer/callback] imza səhvdir', orderId);
        return res.status(400).send('Invalid signature');
      }

      const ref = db.collection('payments').doc(orderId);
      const snap = await ref.get();
      if (!snap.exists || snap.data().provider !== 'betatransfer') { console.warn('[betatransfer/callback] sifariş tapılmadı', orderId); return ok(); }
      const order = snap.data();

      const status = String(b.status || '').trim();
      const type = String(b.type || 'deposit').toLowerCase();
      if (type !== 'deposit') return ok();

      // 2) Valyuta + məbləğ uyğunluğu
      const curr = String(b.currency || '').toUpperCase();
      if (curr && curr !== order.chargeCurrency) { console.warn('[betatransfer/callback] valyuta uyğunsuzluğu', orderId, curr); return ok(); }

      if (FAILED.has(status)) {
        if (order.status === 'pending') await ref.update({ status: 'failed', btStatus: status, failedAt: FieldValue.serverTimestamp() });
        return ok();
      }
      const isSuccess = SUCCESS.has(status), isPartial = PARTIAL.has(status);
      if (!isSuccess && !isPartial) {           // new/pending/verification/checkPayment
        if (status) await ref.update({ btStatus: status }).catch(() => {});
        return ok();
      }

      // 3) Kreditlənəcək məbləğ
      let credit;
      if (isSuccess) {
        const orderAmt = b.orderAmount !== undefined && b.orderAmount !== '' ? Number(b.orderAmount) : Number(order.chargeAmount);
        if (!Number.isFinite(orderAmt) || orderAmt.toFixed(2) !== Number(order.chargeAmount).toFixed(2)) {
          console.warn('[betatransfer/callback] məbləğ uyğunsuzluğu', orderId, b.orderAmount, order.chargeAmount);
          return ok();
        }
        const paid = b.paidAmount !== undefined && b.paidAmount !== '' ? Number(b.paidAmount) : orderAmt;
        // müştəri sifariş məbləğindən az ödəyibsə (status success olsa belə) yalnız ödənilən qədər kreditlə
        credit = round2(Math.min(order.aznAmount, Number.isFinite(paid) && paid > 0 ? paid : order.aznAmount));
      } else {
        const paid = Number(b.paidAmount);
        if (!Number.isFinite(paid) || paid <= 0) { console.warn('[betatransfer/callback] partial: paidAmount yoxdur', orderId); return ok(); }
        credit = round2(Math.min(order.aznAmount, paid));
      }
      if (!(credit > 0)) return ok();

      // 4) İdempotent kreditləmə (təkrar callback -> ikinci dəfə balans verilmir)
      let done = false;
      await db.runTransaction(async tx => {
        const cur = await tx.get(ref);
        if (!cur.exists || cur.data().status === 'paid') return;
        const userRef = db.collection('users').doc(order.uid);
        const userSnap = await tx.get(userRef);
        if (!userSnap.exists) throw new Error('user_not_found');
        const u = userSnap.data();

        let campaignNew = null;
        if (typeof campaignActive === 'function' && typeof genYeKod === 'function' && campaignActive()) {
          for (let i = 0; i < 6 && !campaignNew; i++) {
            const cand = genYeKod();
            const cs = await tx.get(db.collection('campaignCodes').doc(cand));
            if (!cs.exists) campaignNew = cand;
          }
        }

        const bonus = (u.firstDepositBonus === 'pending') ? credit : 0;   // PayÇarx: ilk depozit 2x
        const userUpd = {
          points: FieldValue.increment(credit),
          payWheelSpins: FieldValue.increment(1),
          hasDeposited: true,
          balance: FieldValue.increment(round2(credit + bonus))
        };
        if (bonus > 0) userUpd.firstDepositBonus = 'used';
        tx.update(userRef, userUpd);

        tx.set(userRef.collection('history').doc('pay_' + orderId), {
          type: 'deposit', amount: credit,
          description: 'BetaTransfer depozit (kart-to-kart)', createdAt: FieldValue.serverTimestamp()
        });
        if (bonus > 0) {
          tx.set(userRef.collection('history').doc('bonus_' + orderId), {
            type: 'bonus', amount: bonus,
            description: 'PayÇarx bonus: ilk depozitin 2 qatı', createdAt: FieldValue.serverTimestamp()
          });
        }
        const payUpd = {
          status: 'paid', btStatus: status, bonus, creditedAzn: credit,
          userName: u.displayName || order.userName || '', userUniqueId: u.uniqueId || order.userUniqueId || '',
          btPaymentId: String(b.id || ''), btPaymentSystem: String(b.paymentSystem || ''),
          btPaidAmount: String(b.paidAmount || ''), btNetAmount: amountRaw, paidAt: FieldValue.serverTimestamp()
        };
        if (campaignNew) {
          tx.set(db.collection('campaignCodes').doc(campaignNew), {
            code: campaignNew, uniqueId: u.uniqueId || order.userUniqueId || '',
            source: 'deposit', orderId, amount: credit, createdAt: FieldValue.serverTimestamp()
          });
          payUpd.campaignCode = campaignNew;
        }
        tx.update(ref, payUpd);
        done = true;
      });
      if (done) console.log('[betatransfer/callback] PAY uğurlu', orderId, credit, 'AZN', status);
      return ok();
    } catch (e) {
      console.error('[betatransfer/callback]', e);
      return res.status(500).send('Server error');   // 5xx -> BetaTransfer təkrar göndərər
    }
  }
  app.post('/betatransfer/callback', callbackLimit, callback);
};
