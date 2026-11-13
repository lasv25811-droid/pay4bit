'use strict';
/**
 * E-poçt doğrulama — FIREBASE-in öz məktubu ilə (Brevo / Gmail / Functions LAZIM DEYİL, pulsuz Spark plan).
 *
 * Axın:
 *  1) /email-verify/send    -> server həmin e-poçt üçün müvəqqəti Firebase Auth istifadəçisi yaradır
 *                              (nick@yevroloto.app giriş hesablarına toxunmur) və Firebase-in rəsmi
 *                              "e-poçtu təsdiqlə" məktubunu göndərir (Identity Toolkit sendOobCode).
 *  2) İstifadəçi məktubdakı linkə toxunur (Firebase e-poçtu doğrulanmış edir).
 *  3) /email-verify/confirm -> server Firebase Auth-da e-poçtun doğrulandığını YOXLAYIR
 *                              (brauzerə inanmır) və users sənədində emailVerified=true + 1 PayÇarx verir.
 */
const crypto = require('crypto');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const AUTO_MAIL_RE = /@(phone\.)?yevroloto\.app$/i;
const RESEND_MS = 60 * 1000;
const MAX_SENDS_PER_HOUR = 5;
const IP_MAX_PER_HOUR = 40;
const MARK = 'yl-email-verify';
// Firebase web API açarı (profile.html-dəki ilə eynidir, gizli deyil). İstəsəniz Render-də FIREBASE_WEB_API_KEY ilə dəyişin.
const WEB_API_KEY = process.env.FIREBASE_WEB_API_KEY || 'AIzaSyD2LGEWIqHdt1q9HOHuMw7HdKEpI8Vzx-c';
const REFERER = process.env.FIREBASE_AUTH_REFERER || 'https://yevrolatotest.firebaseapp.com/';

class HttpErr extends Error {
  constructor(status, message, extra) { super(message); this.status = status; this.extra = extra || {}; }
}
const maskEmail = e => {
  const [local, domain] = e.split('@');
  return local[0] + '*'.repeat(Math.max(local.length - 1, 3)) + '@' + domain;
};

async function idt(path, body) {
  const r = await fetch('https://identitytoolkit.googleapis.com/v1/' + path + '?key=' + encodeURIComponent(WEB_API_KEY), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Firebase-Locale': 'az', Referer: REFERER },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000)
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = (data && data.error && data.error.message) || ('HTTP ' + r.status);
    const e = new Error('identitytoolkit ' + path + ': ' + msg);
    e.fbCode = String(msg);
    throw e;
  }
  return data;
}

module.exports = function registerEmailVerifyRoutes(app, { admin, db }) {
  const ipHits = new Map();
  const ipAllowed = ip => {
    const now = Date.now();
    const arr = (ipHits.get(ip) || []).filter(t => now - t < 3600000);
    if (arr.length >= IP_MAX_PER_HOUR) { ipHits.set(ip, arr); return false; }
    arr.push(now); ipHits.set(ip, arr);
    return true;
  };

  async function authUid(req) {
    const m = String(req.headers.authorization || '').match(/^Bearer (.+)$/);
    if (!m) throw new HttpErr(401, 'Təhlükəsizlik üçün yenidən daxil olun');
    try { return (await admin.auth().verifyIdToken(m[1])).uid; }
    catch (_) { throw new HttpErr(401, 'Təhlükəsizlik üçün yenidən daxil olun'); }
  }

  async function loadUser(uid) {
    const snap = await db.collection('users').doc(uid).get();
    if (!snap.exists) throw new HttpErr(404, 'Hesab tapılmadı');
    const d = snap.data();
    if (d.banned === true) throw new HttpErr(403, 'Hesab bloklanıb');
    const email = String(d.email || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email) || AUTO_MAIL_RE.test(email)) throw new HttpErr(400, 'Əvvəlcə düzgün e-poçt əlavə edin');
    return { data: d, email };
  }

  async function takenByOther(uid, email) {
    const q = await db.collection('users').where('emailVerifiedFor', '==', email).limit(5).get();
    return q.docs.some(d => d.id !== uid && d.data().emailVerified === true);
  }

  const wrap = fn => async (req, res) => {
    try {
      if (!ipAllowed(req.realIp || req.ip)) throw new HttpErr(429, 'Çox cəhd edildi, sonra yenidən yoxlayın');
      const uid = await authUid(req);
      res.json({ success: true, ...(await fn(uid, req.body || {})) });
    } catch (e) {
      if (e instanceof HttpErr) return res.status(e.status).json({ success: false, error: e.message, ...e.extra });
      console.error('[email-verify]', e && e.message ? e.message : e);
      res.status(500).json({ success: false, error: 'Server xətası, bir az sonra yenidən yoxlayın' });
    }
  };

  /* ---------- 1) Firebase məktubunu göndər ---------- */
  app.post(['/email-verify/send', '/api/email-verify/send'], wrap(async (uid) => {
    const { data, email } = await loadUser(uid);
    if (data.emailVerified === true && String(data.emailVerifiedFor || '') === email) return { alreadyVerified: true };
    if (await takenByOther(uid, email)) throw new HttpErr(409, 'Bu e-poçt başqa hesabda doğrulanıb');

    const ref = db.collection('emailVerifications').doc(uid);
    const now = Date.now();
    const d = (await ref.get()).data() || {};
    if (d.sentAt && now - d.sentAt < RESEND_MS) {
      const wait = Math.ceil((RESEND_MS - (now - d.sentAt)) / 1000);
      throw new HttpErr(429, `${wait} saniyə sonra yenidən göndərin`, { retryAfter: wait });
    }
    let hourStart = d.hourStart || now, hourCount = d.hourCount || 0;
    if (now - hourStart > 3600000) { hourStart = now; hourCount = 0; }
    if (hourCount >= MAX_SENDS_PER_HOUR) throw new HttpErr(429, 'Çox cəhd edildi. 1 saat sonra yoxlayın', { retryAfter: 3600 });

    // Müvəqqəti doğrulama hesabı: varsa sıfırlanır, yoxdursa yaradılır (delete+create əvəzinə 1 sorğu)
    let tmp = null;
    try { tmp = await admin.auth().getUserByEmail(email); }
    catch (e) { if (!(e && e.code === 'auth/user-not-found')) throw e; }
    const pw = crypto.randomBytes(24).toString('base64url');
    if (tmp) {
      if (tmp.displayName !== MARK) throw new HttpErr(409, 'Bu e-poçt ilə doğrulama mümkün deyil. Başqa e-poçt yazın');
      await admin.auth().updateUser(tmp.uid, { emailVerified: false, password: pw });
    } else {
      await admin.auth().createUser({ email, password: pw, displayName: MARK, emailVerified: false });
    }

    // Render-də BREVO_API_KEY + MAIL_FROM varsa link Brevo ilə göndərilir (spam-a düşmür). Yoxdursa Firebase məktubu.
    let sent = false;
    const bKey = String(process.env.BREVO_API_KEY || '').trim(), bFrom = String(process.env.MAIL_FROM || '').trim();
    if (bKey && bFrom) {
      try {
        const link = await admin.auth().generateEmailVerificationLink(email);
        const r = await fetch('https://api.brevo.com/v3/smtp/email', {
          method: 'POST',
          headers: { 'api-key': bKey, 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({
            sender: { name: process.env.MAIL_FROM_NAME || 'YevroLato', email: bFrom },
            to: [{ email }],
            subject: 'YevroLato — e-poçtu təsdiq edin',
            textContent: `E-poçtunuzu təsdiq etmək üçün linkə toxunun:\n${link}\n\nSonra YevroLato-ya qayıdıb "Təsdiq etdim" düyməsinə basın.`,
            htmlContent: `<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px;border-radius:14px;background:#06261b;color:#e8f6ee"><h2 style="margin:0 0 12px;color:#e6c87a">YevroLato</h2><p>E-poçtunuzu təsdiq etmək üçün düyməyə toxunun:</p><p style="margin:18px 0"><a href="${link}" style="background:#e6c87a;color:#06261b;padding:12px 22px;border-radius:10px;text-decoration:none;font-weight:700">E-poçtu təsdiq et</a></p><p style="color:#8fb3a3;font-size:13px">Sonra YevroLato-ya qayıdıb "Təsdiq etdim" düyməsinə basın.</p></div>`
          }),
          signal: AbortSignal.timeout(10000)
        });
        if (!r.ok) throw new Error('Brevo ' + r.status);
        sent = true;
      } catch (e) { console.error('[email-verify] Brevo alınmadı, Firebase məktubuna keçilir:', e && e.message); }
    }
    if (!sent) {
      try {
        const si = await idt('accounts:signInWithPassword', { email, password: pw, returnSecureToken: true });
        await idt('accounts:sendOobCode', { requestType: 'VERIFY_EMAIL', idToken: si.idToken });
      } catch (e) {
        console.error('[email-verify] Firebase məktub xətası:', e && e.message);
        const code = (e && e.fbCode) || '';
        if (/TOO_MANY_ATTEMPTS/i.test(code)) throw new HttpErr(429, 'Çox cəhd edildi, bir az sonra yenidən yoxlayın');
        if (/INVALID_EMAIL/i.test(code)) throw new HttpErr(400, 'E-poçt ünvanı düzgün deyil');
        throw new HttpErr(502, 'E-poçt göndərilmədi, bir az sonra yenidən yoxlayın');
      }
    }

    await ref.set({ email, sentAt: now, hourStart, hourCount: hourCount + 1 });
    return { masked: maskEmail(email), cooldown: RESEND_MS / 1000 };
  }));

  /* ---------- 2) Firebase-də doğrulandımı? -> doğrula + 1 PayÇarx ---------- */
  app.post(['/email-verify/confirm', '/api/email-verify/confirm'], wrap(async (uid) => {
    const { data: cu, email } = await loadUser(uid);
    // Artıq doğrulanıbsa (iki dəfə toxunma / təkrar sorğu) xəta yox, uğur qaytar
    if (cu.emailVerified === true && String(cu.emailVerifiedFor || '') === email) {
      return { spinBonus: 0, spins: Math.max(0, Math.floor(Number(cu.payWheelSpins) || 0)) };
    }
    const ref = db.collection('emailVerifications').doc(uid);
    const snap = await ref.get();
    if (!snap.exists || snap.data().email !== email) throw new HttpErr(400, 'Əvvəlcə doğrulama məktubu göndərin');

    let fu;
    try { fu = await admin.auth().getUserByEmail(email); }
    catch (_) { throw new HttpErr(400, 'Əvvəlcə doğrulama məktubu göndərin'); }
    if (fu.displayName !== MARK) throw new HttpErr(409, 'Bu e-poçt ilə doğrulama mümkün deyil');
    if (fu.emailVerified !== true) throw new HttpErr(400, 'E-poçt hələ təsdiqlənməyib. Məktubdakı linkə toxunun, sonra yenidən yoxlayın');

    if (await takenByOther(uid, email)) throw new HttpErr(409, 'Bu e-poçt başqa hesabda doğrulanıb');

    const uref = db.collection('users').doc(uid);
    const result = await db.runTransaction(async tx => {
      const u = (await tx.get(uref)).data() || {};
      if (String(u.email || '').trim().toLowerCase() !== email) throw new HttpErr(400, 'E-poçt dəyişib. Yenidən məktub göndərin');
      const upd = {
        emailVerified: true,
        emailVerifiedFor: email,
        emailVerifiedAt: admin.firestore.FieldValue.serverTimestamp()
      };
      let spinBonus = 0, spins = Math.max(0, Math.floor(Number(u.payWheelSpins) || 0));
      if (u.emailSpinGiven !== true) {            // 1 PayÇarx, yalnız bir dəfə
        spinBonus = 1; spins += 1;
        upd.payWheelSpins = spins;
        upd.emailSpinGiven = true;
        tx.set(uref.collection('history').doc(), {
          type: 'bonus', amount: 0, description: 'E-poçt doğrulama: 1 PayÇarx',
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
      }
      tx.update(uref, upd);
      return { spinBonus, spins };
    });
    await ref.delete().catch(() => {});
    return result;
  }));
};
