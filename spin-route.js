/**
 * PayÇarx — SERVER TƏRƏFİ (Render-dəki pay4bit serverinə əlavə et).
 *
 * Niyə lazımdır: çarxın bütün məntiqi əvvəl brauzerdə idi (fırlatma sayı, pulsuz fırlatma
 * vaxtı, təsadüfi nəticə). İstifadəçi həm cihaz saatını dəyişərək, həm də DevTools ilə
 * `payWheelSpins` sahəsini birbaşa yazaraq sonsuz fırlada bilirdi. İndi hər şeyi YALNIZ
 * server həll edir: server saatı, server təsadüfiliyi, atomik Firestore transaction.
 *
 * Qoşulması (server faylında, cors() və auth hazırlığından sonra, listen()-dən əvvəl):
 *
 *   const registerSpinRoutes = require('./spin-route');
 *   registerSpinRoutes(app, { admin, db });   // admin = firebase-admin, db = admin.firestore()
 *
 * Yeni endpoint-lər (hər ikisi `Authorization: Bearer <Firebase ID token>` tələb edir):
 *   POST /spin-state  (və /api/spin-state)  -> pulsuz fırlatmanı yoxlayır/verir, vəziyyəti qaytarır
 *   POST /spin        (və /api/spin)        -> 1 fırlatma xərcləyir, nəticəni qaytarır
 */
'use strict';

const crypto = require('crypto');

const FREE_SPIN_MS = 24 * 60 * 60 * 1000;

/* DİQQƏT: sıra və say paycarx.html-dəki SEGMENTS ilə EYNİ olmalıdır (client yalnız indeksi alır
   və bucaqlara görə fırladır). Çəkiləri (w) YALNIZ buradan dəyiş. */
const SEGMENTS = [
  { type: 'money',  value: 1,   label: '1 AZN',                w: 20, nw: 10 },
  { type: 'spin',   value: 2,   label: 'PayÇarx 2 dəfə',       w: 1,  nw: 0  },
  { type: 'money',  value: 2,   label: '2 AZN',                w: 20, nw: 10 },
  { type: 'x2',     value: 2,   label: 'İlk depozitin 2 qatı', w: 7,  nw: 3  },
  { type: 'money',  value: 3,   label: '3 AZN',                w: 10, nw: 35 },
  { type: 'lose',   value: 0,   label: 'Bu dəfə olmadı',       w: 20, nw: 10 },
  { type: 'money',  value: 5,   label: '5 AZN',                w: 1,  nw: 0  },
  { type: 'points', value: 100, label: '100 level xalı',       w: 6,  nw: 2  },
  { type: 'money',  value: 4,   label: '4 AZN',                w: 5,  nw: 0  },
  { type: 'points', value: 50,  label: '50 level xalı',        w: 9,  nw: 30 },
  { type: 'money',  value: 10,  label: '10 AZN',               w: 1,  nw: 0  }
];
/* w  = depozit edmiş istifadəçilər üçün (köhnə qayda)
   nw = hələ depozit etməyənlər üçün: 3 AZN və 50 xal şansı daha çox, böyük mükafatlar bağlıdır */
const TOTAL_W = SEGMENTS.reduce((a, s) => a + s.w, 0);
const TOTAL_NW = SEGMENTS.reduce((a, s) => a + s.nw, 0);

const r2 = (n) => Math.round((Number(n) || 0) * 100) / 100;

/* Kriptoqrafik təsadüfilik (Math.random əvəzinə) */
function pickSegment(deposited = true, rand = crypto.randomInt) {
  const key = deposited ? 'w' : 'nw';
  const total = deposited ? TOTAL_W : TOTAL_NW;
  let r = rand(0, total);
  for (let i = 0; i < SEGMENTS.length; i++) {
    r -= SEGMENTS[i][key];
    if (r < 0) return i;
  }
  return SEGMENTS.length - 1;
}

/* Son fırlatma/qeydiyyat vaxtı. Gələcəyə yazılmış vaxt (köhnə saat hiyləsi) "indi"yə endirilir:
   belə hesab 24 saat gözləməli olur. */
function lastRefMs(d, now) {
  let last = Number(d.lastSpinAtMs) || 0;
  if (!last && d.createdAt && typeof d.createdAt.toMillis === 'function') last = d.createdAt.toMillis();
  if (last > now) last = now;
  return last;
}

/* Pulsuz fırlatma: fırlatma 0-dırsa və son fırlatmadan 24 saat keçibsə 1 fırlatma verilir. SAF funksiya. */
function resolveSpins(d, now) {
  let spins = Math.max(0, Math.floor(Number(d.payWheelSpins) || 0));
  let last = lastRefMs(d, now);
  const upd = {};
  if (spins === 0 && now - last >= FREE_SPIN_MS) {
    spins = 1;
    last = now;
    upd.payWheelSpins = 1;
    upd.lastSpinAtMs = now;
  }
  return { spins, last, upd };
}

/* Nəticənin tətbiqi. SAF funksiya (test üçün ayrılıb). */
function applyPrize(d, spinsBefore, idx, now) {
  const prize = SEGMENTS[idx];
  const upd = {
    payWheelSpins: spinsBefore - 1 + (prize.type === 'spin' ? prize.value : 0),
    lastSpinAtMs: now
  };
  let alreadyX2 = false;
  if (prize.type === 'money') {
    upd.balance = r2((Number(d.balance) || 0) + prize.value);
    upd.points = r2((Number(d.points) || 0) + prize.value);
  } else if (prize.type === 'points') {
    upd.points = r2((Number(d.points) || 0) + prize.value);
  } else if (prize.type === 'x2') {
    if (d.firstDepositBonus === 'pending') alreadyX2 = true;
    else upd.firstDepositBonus = 'pending';
  }
  return { upd, alreadyX2, prize };
}

function publicState(d, upd, spins, last, now) {
  const merged = { ...d, ...upd };
  return {
    spins,
    nextFreeAtMs: spins > 0 ? 0 : last + FREE_SPIN_MS,
    serverNow: now,
    balance: r2(merged.balance),
    points: r2(merged.points),
    currency: merged.currency || 'AZN'
  };
}

function registerSpinRoutes(app, { admin, db }) {
  const FieldValue = admin.firestore.FieldValue;

  async function uidFromReq(req) {
    const m = String(req.headers.authorization || '').match(/^Bearer (.+)$/);
    if (!m) return null;
    try { return (await admin.auth().verifyIdToken(m[1])).uid; } catch (_) { return null; }
  }

  function fail(res, status, code) { return res.status(status).json({ success: false, error: code }); }

  function mapError(res, e) {
    const m = e && e.message;
    if (m === 'user_not_found') return fail(res, 404, 'user_not_found');
    if (m === 'banned')         return fail(res, 403, 'banned');
    if (m === 'no_spins')       return fail(res, 409, 'no_spins');
    console.error('[spin] error:', e);
    return fail(res, 500, 'server_error');
  }

  /* İstifadəçi depozit edibmi? (bayraq və ya uğurlu depozit ödənişi) */
  async function userHasDeposited(ref, uid) {
    try {
      const u = await ref.get();
      if (u.exists && u.data().hasDeposited === true) return true;
      const q = await db.collection('payments')
        .where('uid', '==', uid).where('purpose', '==', 'deposit').where('status', '==', 'paid').limit(1).get();
      if (!q.empty) { try { await ref.update({ hasDeposited: true }); } catch (_) {} return true; }
    } catch (e) { console.warn('[spin] deposit check:', e.message); }
    return false;
  }

  /* Vəziyyət + pulsuz fırlatma yoxlaması */
  async function stateHandler(req, res) {
    const uid = await uidFromReq(req);
    if (!uid) return fail(res, 401, 'unauthorized');
    try {
      const ref = db.collection('users').doc(uid);
      const out = await db.runTransaction(async (tx) => {
        const snap = await tx.get(ref);
        if (!snap.exists) throw new Error('user_not_found');
        const d = snap.data();
        if (d.banned === true) throw new Error('banned');
        const now = Date.now();
        const { spins, last, upd } = resolveSpins(d, now);
        if (Object.keys(upd).length) tx.update(ref, upd);
        return publicState(d, upd, spins, last, now);
      });
      return res.json({ success: true, ...out });
    } catch (e) { return mapError(res, e); }
  }

  /* Fırlatma */
  async function spinHandler(req, res) {
    const uid = await uidFromReq(req);
    if (!uid) return fail(res, 401, 'unauthorized');
    try {
      const ref = db.collection('users').doc(uid);
      const dep = await userHasDeposited(ref, uid);
      const out = await db.runTransaction(async (tx) => {
        const snap = await tx.get(ref);
        if (!snap.exists) throw new Error('user_not_found');
        const d = snap.data();
        if (d.banned === true) throw new Error('banned');

        const now = Date.now();
        const free = resolveSpins(d, now);
        if (free.spins < 1) throw new Error('no_spins');

        const idx = pickSegment(dep);
        const { upd, alreadyX2, prize } = applyPrize(d, free.spins, idx, now);
        tx.update(ref, upd);
        tx.set(ref.collection('history').doc(), {
          type: 'bonus',
          amount: prize.type === 'money' ? prize.value : 0,
          description: 'PayÇarx: ' + prize.label,
          createdAt: FieldValue.serverTimestamp()
        });

        const spinsAfter = upd.payWheelSpins;
        return {
          segmentIndex: idx,
          prize: { type: prize.type, value: prize.value, label: prize.label },
          alreadyX2,
          ...publicState(d, upd, spinsAfter, now, now)
        };
      });
      return res.json({ success: true, ...out });
    } catch (e) { return mapError(res, e); }
  }

  app.post(['/spin-state', '/api/spin-state'], stateHandler);
  app.post(['/spin', '/api/spin'], spinHandler);
}

module.exports = registerSpinRoutes;
/* test üçün */
module.exports._internals = { SEGMENTS, TOTAL_W, TOTAL_NW, FREE_SPIN_MS, pickSegment, resolveSpins, applyPrize, lastRefMs };
