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
 * QAYDALAR (yeni):
 *   1) Qeydiyyatdan keçən HƏR KƏSƏ 1 dəfəlik PayÇarx hədiyyəsi (qeydiyyatdan 24 saat sonra, bir dəfə).
 *   2) Hər 24 saatdan bir pulsuz fırlatma LƏĞV edilib. İstisna: profil səviyyəsi MATRIX (>= 5000 xal)
 *      olanlara hər 24 saatdan bir pulsuz fırlatma verilir.
 *   3) Hər uğurlu DEPOZİT 1 fırlatma açır (server.js callback-də).
 *   4) Qazanc faizi endirilib (aşağıdakı çəkilər).
 *
 * Yeni endpoint-lər (hər ikisi `Authorization: Bearer <Firebase ID token>` tələb edir):
 *   POST /spin-state  (və /api/spin-state)  -> pulsuz fırlatmanı yoxlayır/verir, vəziyyəti qaytarır
 *   POST /spin        (və /api/spin)        -> 1 fırlatma xərcləyir, nəticəni qaytarır
 */
'use strict';

const crypto = require('crypto');

const FREE_SPIN_MS = 24 * 60 * 60 * 1000;
const MATRIX_POINTS = 5000;   // admin.html RANKS: Matrix = 5000 xal

/* DİQQƏT: sıra və say paycarx.html-dəki SEGMENTS ilə EYNİ olmalıdır (client yalnız indeksi alır
   və bucaqlara görə fırladır). Çəkiləri (w) YALNIZ buradan dəyiş. */
const SEGMENTS = [
  { type: 'money',  value: 1,   label: '1 AZN',                w: 18, nw: 10 },
  { type: 'spin',   value: 2,   label: 'PayÇarx 2 dəfə',       w: 1,  nw: 0  },
  { type: 'money',  value: 2,   label: '2 AZN',                w: 16, nw: 8  },
  { type: 'x2',     value: 2,   label: 'İlk depozitin 2 qatı', w: 5,  nw: 3  },
  { type: 'money',  value: 3,   label: '3 AZN',                w: 7,  nw: 25 },
  { type: 'lose',   value: 0,   label: 'Bu dəfə olmadı',       w: 32, nw: 20 },
  { type: 'money',  value: 5,   label: '5 AZN',                w: 1,  nw: 0  },
  { type: 'points', value: 100, label: '100 level xalı',       w: 6,  nw: 2  },
  { type: 'money',  value: 4,   label: '4 AZN',                w: 3,  nw: 0  },
  { type: 'points', value: 50,  label: '50 level xalı',        w: 10, nw: 32 },
  { type: 'money',  value: 10,  label: '10 AZN',               w: 1,  nw: 0  }
];
/* w  = depozit edmiş istifadəçilər üçün (çəkilər cəmi 100; orta pul qazancı ~0.98 AZN, əvvəl ~1.25)
   nw = hələ depozit etməyənlər üçün (cəmi 100; orta ~1.01 AZN, əvvəl ~1.35): böyük mükafatlar bağlıdır */
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

/* Qeydiyyat vaxtı (ms). */
function createdMs(d, now) {
  let c = 0;
  if (d.createdAt && typeof d.createdAt.toMillis === 'function') c = d.createdAt.toMillis();
  if (c > now) c = now;
  return c;
}

/* Hesab MATRIX səviyyəsindədirmi? (səviyyə `points` sahəsinə görə hesablanır) */
function isMatrix(d) { return (Number(d.points) || 0) >= MATRIX_POINTS; }

/* Qeydiyyat hədiyyəsi artıq istifadə olunubmu?
   Köhnə hesablar (artıq bir dəfə pulsuz fırladanlar, lastSpinAtMs > 0) da "istifadə olunub" sayılır. */
function welcomeDone(d) { return d.welcomeSpinGiven === true || (Number(d.lastSpinAtMs) || 0) > 0; }

/* PayÇarx hüququ (SAF funksiya):
   - qeydiyyat hədiyyəsi: hər hesaba 1 dəfə, qeydiyyatdan 24 saat sonra;
   - MATRIX: hər 24 saatdan bir 1 pulsuz fırlatma (yalnız fırlatma qalmayanda);
   - digər hamı üçün gündəlik pulsuz fırlatma YOXDUR — yalnız depozit fırlatma açır. */
function resolveSpins(d, now) {
  let spins = Math.max(0, Math.floor(Number(d.payWheelSpins) || 0));
  const upd = {};
  const matrix = isMatrix(d);
  let nextFreeAtMs = 0;
  let mode = 'deposit';          // 'welcome' | 'matrix' | 'deposit'

  if (spins === 0) {
    if (!welcomeDone(d)) {
      const at = createdMs(d, now) + FREE_SPIN_MS;
      if (now >= at) { spins = 1; upd.payWheelSpins = 1; upd.welcomeSpinGiven = true; }
      else { nextFreeAtMs = at; mode = 'welcome'; }
    } else if (matrix) {
      let last = Number(d.lastDailySpinAtMs) || 0;
      if (last > now) last = now;            // saat hiyləsi: gələcək vaxt "indi"yə endirilir
      const at = last + FREE_SPIN_MS;
      if (!last || now >= at) { spins = 1; upd.payWheelSpins = 1; upd.lastDailySpinAtMs = now; }
      else { nextFreeAtMs = at; mode = 'matrix'; }
    }
  }
  return { spins, upd, nextFreeAtMs, mode, matrix };
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

function publicState(d, upd, spins, info, now) {
  const merged = { ...d, ...upd };
  return {
    spins,
    nextFreeAtMs: spins > 0 ? 0 : (info.nextFreeAtMs || 0),
    freeMode: spins > 0 ? 'ready' : info.mode,      // welcome | matrix | deposit | ready
    isMatrix: isMatrix(merged),
    matrixPoints: MATRIX_POINTS,
    points: r2(merged.points),
    serverNow: now,
    balance: r2(merged.balance),
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
        const info = resolveSpins(d, now);
        if (Object.keys(info.upd).length) tx.update(ref, info.upd);
        return publicState(d, info.upd, info.spins, info, now);
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
        Object.assign(upd, free.upd);          // welcomeSpinGiven / lastDailySpinAtMs eyni əməliyyatda yazılır
        upd.payWheelSpins = free.spins - 1 + (prize.type === 'spin' ? prize.value : 0);
        tx.update(ref, upd);
        tx.set(ref.collection('history').doc(), {
          type: 'bonus',
          amount: prize.type === 'money' ? prize.value : 0,
          description: 'PayÇarx: ' + prize.label,
          createdAt: FieldValue.serverTimestamp()
        });

        const spinsAfter = upd.payWheelSpins;
        const after = resolveSpins({ ...d, ...upd }, now);
        return {
          segmentIndex: idx,
          prize: { type: prize.type, value: prize.value, label: prize.label },
          alreadyX2,
          ...publicState(d, upd, spinsAfter, after, now)
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
module.exports._internals = { SEGMENTS, TOTAL_W, TOTAL_NW, FREE_SPIN_MS, MATRIX_POINTS, pickSegment, resolveSpins, applyPrize, isMatrix, welcomeDone };
