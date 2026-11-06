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
 *   1) Qeydiyyat hədiyyəsi (1 dəfəlik PayÇarx) YALNIZ aşağıdakı şərtlərin HAMISI ödənəndə verilir:
 *        a) hesabın telefon nömrəsi SMS ilə doğrulanıb (phoneVerified === true);
 *        b) hədiyyə alan IP ünvan yenidir (eyni IP-dən əvvəl hədiyyə alınmayıb);
 *        c) hədiyyə alan cihaz yenidir (eyni cihazdan əvvəl hədiyyə alınmayıb);
 *        d) qeydiyyatdan WELCOME_DELAY_MS keçib (standart 24 saat; env ilə dəyişir, 0 = dərhal).
 *      Claim qeydləri `welcomeClaims` kolleksiyasında saxlanır (yalnız server yazır/oxuyur).
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

/* Qeydiyyat hədiyyəsi qorunması (SMS + yeni IP + yeni cihaz) */
const WELCOME_DELAY_MS = process.env.WELCOME_DELAY_MS !== undefined && process.env.WELCOME_DELAY_MS !== ''
  ? Math.max(0, Number(process.env.WELCOME_DELAY_MS) || 0) : FREE_SPIN_MS;
const WELCOME_MAX_PER_IP = Math.max(1, Number(process.env.WELCOME_MAX_PER_IP) || 1);       // 1 IP -> neçə hesab hədiyyə ala bilər
const WELCOME_MAX_PER_DEVICE = Math.max(1, Number(process.env.WELCOME_MAX_PER_DEVICE) || 1); // 1 cihaz -> neçə hesab
const CLAIM_SALT = process.env.WELCOME_CLAIM_SALT || 'yevrolato-welcome-v1';
const DEVICE_ID_RE = /^[A-Za-z0-9_-]{16,64}$/;

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
   - qeydiyyat hədiyyəsi: hər hesaba 1 dəfə; SMS doğrulaması + yeni IP + yeni cihaz + gözləmə müddəti tələb olunur;
   - MATRIX: hər 24 saatdan bir 1 pulsuz fırlatma (yalnız fırlatma qalmayanda);
   - digər hamı üçün gündəlik pulsuz fırlatma YOXDUR — yalnız depozit fırlatma açır.
   gate: IP/cihaz yoxlamasının nəticəsi (welcomeGate). null verilibsə və hədiyyə vaxtı çatıbsa,
         `welcomeDue: true` qaytarılır — çağıran yoxlamanı edib funksiyanı gate ilə yenidən çağırmalıdır.
   mode: 'welcome_sms' (nömrə doğrulanmayıb) | 'welcome' (gözləmə) | 'welcome_blocked' (IP/cihaz artıq istifadə olunub)
         | 'welcome_device' (cihaz identifikatoru yoxdur) | 'matrix' | 'deposit' */
function resolveSpins(d, now, gate) {
  let spins = Math.max(0, Math.floor(Number(d.payWheelSpins) || 0));
  const upd = {};
  const matrix = isMatrix(d);
  let nextFreeAtMs = 0;
  let mode = 'deposit';
  let welcomeDue = false;
  let welcomeGranted = false;

  if (spins === 0) {
    if (!welcomeDone(d)) {
      if (d.phoneVerified !== true) {
        mode = 'welcome_sms';                    // əvvəl SMS ilə nömrəni doğrula
      } else {
        const at = createdMs(d, now) + WELCOME_DELAY_MS;
        if (now < at) { nextFreeAtMs = at; mode = 'welcome'; }
        else if (!gate) { welcomeDue = true; mode = 'welcome_check'; }
        else if (gate.ok) {
          spins = 1; upd.payWheelSpins = 1; upd.welcomeSpinGiven = true; welcomeGranted = true;
        } else { mode = gate.reason || 'welcome_blocked'; }
      }
    } else if (matrix) {
      let last = Number(d.lastDailySpinAtMs) || 0;
      if (last > now) last = now;            // saat hiyləsi: gələcək vaxt "indi"yə endirilir
      const at = last + FREE_SPIN_MS;
      if (!last || now >= at) { spins = 1; upd.payWheelSpins = 1; upd.lastDailySpinAtMs = now; }
      else { nextFreeAtMs = at; mode = 'matrix'; }
    }
  }
  return { spins, upd, nextFreeAtMs, mode, matrix, welcomeDue, welcomeGranted };
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
    phoneVerified: merged.phoneVerified === true,
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

  const hashKey = (v) => crypto.createHash('sha256').update(CLAIM_SALT + '|' + String(v)).digest('hex');
  const cleanIp = (ip) => String(ip || '').replace(/^::ffff:/i, '').trim();
  const getDeviceId = (req) => String((req.body && req.body.deviceId) || '').trim();

  /* Qeydiyyat hədiyyəsi üçün IP + cihaz yoxlaması. Transaction daxilində OXUMA (yazma sonra, handler-də). */
  async function welcomeGate(tx, uid, ip, deviceId) {
    if (!DEVICE_ID_RE.test(deviceId || '')) return { ok: false, reason: 'welcome_device' };
    if (!ip) return { ok: false, reason: 'welcome_blocked' };
    const ipRef = db.collection('welcomeClaims').doc('ip_' + hashKey(ip));
    const devRef = db.collection('welcomeClaims').doc('dev_' + hashKey(deviceId));
    const [ipSnap, devSnap] = await Promise.all([tx.get(ipRef), tx.get(devRef)]);
    const ipUids = ipSnap.exists && Array.isArray(ipSnap.data().uids) ? ipSnap.data().uids : [];
    const devUids = devSnap.exists && Array.isArray(devSnap.data().uids) ? devSnap.data().uids : [];
    const ipOk = ipUids.includes(uid) || ipUids.length < WELCOME_MAX_PER_IP;
    const devOk = devUids.includes(uid) || devUids.length < WELCOME_MAX_PER_DEVICE;
    if (!ipOk || !devOk) return { ok: false, reason: 'welcome_blocked' };
    return { ok: true, ipRef, devRef, ipUids, devUids };
  }
  function writeWelcomeClaims(tx, gate, uid) {
    const add = (arr) => (arr.includes(uid) ? arr : arr.concat(uid));
    tx.set(gate.ipRef, { kind: 'ip', uids: add(gate.ipUids), updatedAt: FieldValue.serverTimestamp() }, { merge: true });
    tx.set(gate.devRef, { kind: 'device', uids: add(gate.devUids), updatedAt: FieldValue.serverTimestamp() }, { merge: true });
  }
  /* resolveSpins + (lazım olsa) IP/cihaz yoxlaması */
  async function resolveWithGate(tx, d, uid, now, req) {
    let info = resolveSpins(d, now, null);
    let gate = null;
    if (info.welcomeDue) {
      gate = await welcomeGate(tx, uid, cleanIp(req.ip), getDeviceId(req));
      info = resolveSpins(d, now, gate);
    }
    return { info, gate };
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
        const { info, gate } = await resolveWithGate(tx, d, uid, now, req);   // oxumalar yazmalardan əvvəl
        if (Object.keys(info.upd).length) tx.update(ref, info.upd);
        if (info.welcomeGranted && gate && gate.ok) writeWelcomeClaims(tx, gate, uid);
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
        const { info: free, gate } = await resolveWithGate(tx, d, uid, now, req);
        if (free.spins < 1) throw new Error('no_spins');

        const idx = pickSegment(dep);
        const { upd, alreadyX2, prize } = applyPrize(d, free.spins, idx, now);
        Object.assign(upd, free.upd);          // welcomeSpinGiven / lastDailySpinAtMs eyni əməliyyatda yazılır
        upd.payWheelSpins = free.spins - 1 + (prize.type === 'spin' ? prize.value : 0);
        tx.update(ref, upd);
        if (free.welcomeGranted && gate && gate.ok) writeWelcomeClaims(tx, gate, uid);
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
module.exports._internals = { SEGMENTS, TOTAL_W, TOTAL_NW, FREE_SPIN_MS, WELCOME_DELAY_MS, WELCOME_MAX_PER_IP, WELCOME_MAX_PER_DEVICE, MATRIX_POINTS, pickSegment, resolveSpins, applyPrize, isMatrix, welcomeDone };
